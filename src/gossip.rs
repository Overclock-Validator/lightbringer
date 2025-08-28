use std::net::{SocketAddr, ToSocketAddrs};
use std::num::{NonZero, NonZeroUsize};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use solana_gossip::cluster_info::{ClusterInfo, Node, NodeConfig};
use solana_gossip::contact_info::{ContactInfo};
use solana_gossip::gossip_service::GossipService;
use solana_net_utils::get_public_ip_addr;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use solana_streamer::socket::SocketAddrSpace;

pub struct GossipManager {
    exit: Arc<AtomicBool>,
    gossip_service: Option<GossipService>,
    cluster_info: Option<Arc<ClusterInfo>>,
}

impl GossipManager {
    pub fn new() -> Self {
        GossipManager {
            exit: Arc::new(AtomicBool::new(false)),
            gossip_service: None,
            cluster_info: None,
        }
    }

    pub fn initialize(&mut self, entrypoint: &str) -> Result<(), Box<dyn std::error::Error>> {
        let keypair = Arc::new(Keypair::new());
        let exit = Arc::clone(&self.exit);

        let entrypoint_addrs: Vec<_> = entrypoint.to_socket_addrs().unwrap().collect();
        let cluster_entrypoints = entrypoint_addrs
            .iter()
            .map(ContactInfo::new_gossip_entry_point)
            .collect::<Vec<_>>();

        let gossip_entry = entrypoint_addrs.first().ok_or("Failed to resolve entrypoint")?;

        let my_ip = get_public_ip_addr(gossip_entry).map_err(|e| format!("Failed to get public IP: {}", e))?;
        let gossip_addr = SocketAddr::new(my_ip, 65509);
        let node_config = NodeConfig {
            gossip_addr,
            port_range: (65510, 65530),
            bind_ip_addr: my_ip,
            public_tpu_addr: None,
            public_tpu_forwards_addr: None,
            num_tvu_receive_sockets: NonZeroUsize::new(1).unwrap(),
            num_tvu_retransmit_sockets: NonZeroUsize::new(1).unwrap(),
            num_quic_endpoints: NonZeroUsize::new(1).unwrap(),
        };

        let ep_shred_version = solana_net_utils::get_cluster_shred_version(&gossip_entry)?;

        let mut node = Node::new_with_external_ip(&keypair.pubkey(), node_config);
        node.info.set_shred_version(ep_shred_version);

        let mut cluster_info = ClusterInfo::new(
            node.info.clone(),
            keypair.clone(),
            SocketAddrSpace::Global,
        );
        cluster_info.set_contact_debug_interval(10_000);
        cluster_info.set_entrypoints(cluster_entrypoints);

        let cluster_info = Arc::new(cluster_info);
        let gossip_service = GossipService::new(
            &cluster_info,
            None,
            node.sockets.gossip,
            None,
            false,
            None,
            exit.clone(),
        );

        self.gossip_service = Some(gossip_service);
        self.cluster_info = Some(cluster_info);

        Ok(())
    }

    pub fn lookup_my_info(&self) -> ContactInfo {
        let cluster_info = Arc::clone(self.cluster_info.as_ref().unwrap());
        cluster_info.my_contact_info()
    }

    pub fn lookup_info(&self, pubkey: &Pubkey) -> Option<ContactInfo> {
        let cluster_info = Arc::clone(self.cluster_info.as_ref().unwrap());
        cluster_info.lookup_contact_info(pubkey, |x| x.clone())
    }

    pub fn get_cluster_info(&self) -> Option<Arc<ClusterInfo>> {
        self.cluster_info.clone()
    }

    pub fn get_all_peers(&self) -> Vec<(ContactInfo, u64)> {
        let cluster_info = Arc::clone(self.cluster_info.as_ref().unwrap());
        cluster_info.all_peers()
    }

    pub fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.exit.store(true, Ordering::Relaxed);

        if let Some(gossip_service) = self.gossip_service.take() {
            gossip_service.join().map_err(|_| "Failed to join gossip service")?;
        }

        Ok(())
    }
}

impl Drop for GossipManager {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}