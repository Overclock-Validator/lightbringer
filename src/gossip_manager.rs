use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::anyhow;
use solana_gossip::{
    cluster_info::{ClusterInfo, NodeConfig},
    contact_info::ContactInfo,
    gossip_service::GossipService,
    node::Node,
};
use solana_net_utils::socket_addr_space::SocketAddrSpace;
use solana_net_utils::{get_public_ip_addr_with_binding, multihomed_sockets::BindIpAddrs};
use solana_sdk::{signature::Keypair, signer::Signer};

use crate::config::GossipConfig;

pub struct GossipManager {
    exit: Arc<AtomicBool>,
    gossip_service: GossipService,
    cluster_info: Arc<ClusterInfo>,
    pub version: u16,
}

pub struct Sockets {
    pub repair_socket: std::net::UdpSocket,
    pub serve_repair_socket: std::net::UdpSocket,
}

impl GossipManager {
    pub fn new(
        gossip_entry: SocketAddr,
        keypair: Arc<Keypair>,
        gossip_config: GossipConfig,
    ) -> anyhow::Result<(Self, Sockets)> {
        let cluster_entrypoints = vec![ContactInfo::new_gossip_entry_point(&gossip_entry)];

        let bind_ip_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let my_ip = get_public_ip_addr_with_binding(&gossip_entry, bind_ip_addr)
            .map_err(|e| anyhow!("Failed to get public IP: {}", e))?;
        let node_config = NodeConfig {
            gossip_port: gossip_config.gossip_port,
            port_range: gossip_config.port_range(),
            advertised_ip: my_ip,
            public_tpu_addr: None,
            public_tpu_forwards_addr: None,
            public_tvu_addr: None,
            num_tvu_receive_sockets: NonZeroUsize::new(1).unwrap(),
            num_tvu_retransmit_sockets: NonZeroUsize::new(1).unwrap(),
            num_quic_endpoints: NonZeroUsize::new(1).unwrap(),
            bind_ip_addrs: BindIpAddrs::new(vec![my_ip]).unwrap(),
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

        Ok((
            GossipManager {
                exit,
                gossip_service,
                cluster_info,
                version: ep_shred_version,
            },
            Sockets {
                repair_socket: node.sockets.repair,
                serve_repair_socket: node.sockets.serve_repair,
            },
        ))
    }

    pub fn lookup_my_info(&self) -> ContactInfo {
        self.cluster_info.my_contact_info()
    }

    pub fn get_cluster_info(&self) -> Arc<ClusterInfo> {
        self.cluster_info.clone()
    }

    pub fn stop(self) -> anyhow::Result<()> {
        self.exit.store(true, Ordering::Relaxed);

        self.gossip_service
            .join()
            .map_err(|_| anyhow!("Failed to join gossip service"))?;

        Ok(())
    }
}
