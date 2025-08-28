use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::anyhow;
use solana_gossip::{
    cluster_info::{ClusterInfo, Node, NodeConfig},
    contact_info::ContactInfo,
    gossip_service::GossipService,
};
use solana_net_utils::get_public_ip_addr;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use solana_streamer::socket::SocketAddrSpace;

pub struct GossipManager {
    exit: Arc<AtomicBool>,
    gossip_service: GossipService,
    cluster_info: Arc<ClusterInfo>,
    pub version: u16,
}

impl GossipManager {
    pub fn new(gossip_entry: SocketAddr) -> anyhow::Result<Self> {
        let keypair = Arc::new(Keypair::new());

        let cluster_entrypoints = vec![ContactInfo::new_gossip_entry_point(&gossip_entry)];

        let my_ip = get_public_ip_addr(&gossip_entry)
            .map_err(|e| anyhow!("Failed to get public IP: {}", e))?;
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

        let ep_shred_version = solana_net_utils::get_cluster_shred_version(&gossip_entry)
            .map_err(|e| anyhow!("Failed to fetch shred version from entrypoint {e}"))?;

        let mut node = Node::new_with_external_ip(&keypair.pubkey(), node_config);
        node.info.set_shred_version(ep_shred_version);
        let mut cluster_info =
            ClusterInfo::new(node.info.clone(), keypair.clone(), SocketAddrSpace::Global);
        cluster_info.set_contact_debug_interval(10_000);
        cluster_info.set_entrypoints(cluster_entrypoints);

        let exit = Arc::new(AtomicBool::new(false));
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

        Ok(GossipManager {
            exit,
            gossip_service,
            cluster_info,
            version: ep_shred_version,
        })
    }

    pub fn lookup_my_info(&self) -> ContactInfo {
        self.cluster_info.my_contact_info()
    }

    pub fn lookup_info(&self, pubkey: &Pubkey) -> Option<ContactInfo> {
        self.cluster_info.lookup_contact_info(pubkey, |x| x.clone())
    }

    pub fn get_cluster_info(&self) -> Arc<ClusterInfo> {
        self.cluster_info.clone()
    }

    pub fn get_all_peers(&self) -> Vec<(ContactInfo, u64)> {
        self.cluster_info.all_peers()
    }

    pub fn stop(self) -> anyhow::Result<()> {
        self.exit.store(true, Ordering::Relaxed);

        self.gossip_service
            .join()
            .map_err(|_| anyhow!("Failed to join gossip service"))?;

        Ok(())
    }
}
