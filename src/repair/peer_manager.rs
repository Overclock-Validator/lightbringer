use std::{collections::HashMap, net::{IpAddr, SocketAddr}, pin::pin, sync::Arc, time::{Duration, SystemTime}};

use futures::{select_biased, FutureExt};
use glommio::spawn_local;
use solana_gossip::{cluster_info::ClusterInfo, contact_info::Protocol};

use crate::thread_manager::CancelRx;

const REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const STALE_THRESHOLD: Duration = Duration::from_secs(300);

struct RepairPeerInfo {
    socket_addr: SocketAddr,
    last_seen: SystemTime,
}

pub async fn start_repair_peer_manager(exit: CancelRx, cluster_info: Arc<ClusterInfo>) {
    let mut repair_peers = HashMap::<IpAddr, RepairPeerInfo>::new();

    let task = spawn_local(async move {
        loop {
            let now = SystemTime::now();
            let peers = cluster_info.all_peers();

            repair_peers.retain(|_, info| {
                if let Ok(duration) = now.duration_since(info.last_seen) {
                    duration < STALE_THRESHOLD
                } else {
                    true
                }
            });

            for (peer, _) in peers {
                let Some(peer_repair_addr) = peer.serve_repair(Protocol::UDP) else {
                    continue;
                };
                let ip = peer_repair_addr.ip();
                repair_peers.insert(ip, RepairPeerInfo {
                    socket_addr: peer_repair_addr,
                    last_seen: now,
                });
            }

            log::info!("Refreshed repair peers. Current count: {}", repair_peers.len());

            glommio::timer::sleep(REFRESH_INTERVAL).await;
        
            #[cfg(feature = "debug")]
            {
                for (ip, info) in repair_peers.iter() {
                    let duration = SystemTime::now().duration_since(info.last_seen).unwrap_or(Duration::from_secs(0));
                    log::debug!("Repair Peer, IP: {}, Address: {:?}, Last seen: {} seconds ago", ip, info.socket_addr, duration.as_secs());
                } 
            }
        }
    });

    exit.await;
    task.cancel().await;
}