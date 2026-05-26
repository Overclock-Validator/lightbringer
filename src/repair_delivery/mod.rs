use std::{collections::HashMap, net::SocketAddr, rc::Rc, sync::Arc};

use bincode::Options;
use glommio::{net::UdpSocket, spawn_local};
use solana_core::repair::serve_repair::{REPAIR_RESPONSE_SERIALIZED_PING_BYTES, RepairResponse};
use solana_gossip::{cluster_info::ClusterInfo, ping_pong::Pong};
use solana_ledger::shred::{Nonce, SIZE_OF_NONCE, ShredType};
use solana_packet::PACKET_DATA_SIZE;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signable, Signature},
};

use crate::{
    metrics::{MetricsSender, points::ServeRepairMeasurement},
    store::shred::ShredStore,
    thread_manager::CancelRx,
    turbine_manager::recv_shred,
    types::PacketView,
};

const MAX_REQUESTS_PER_SECOND: u32 = 100;
const RATE_LIMIT_WINDOW_SECS: u64 = 1;
const STATS_REPORT_INTERVAL_SECS: u64 = 10;

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct RepairRequestHeader {
    signature: Signature,
    sender: Pubkey,
    recipient: Pubkey,
    timestamp: u64,
    nonce: Nonce,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
enum RepairProtocol {
    LegacyWindowIndex,
    LegacyHighestWindowIndex,
    LegacyOrphan,
    LegacyWindowIndexWithNonce,
    LegacyHighestWindowIndexWithNonce,
    LegacyOrphanWithNonce,
    LegacyAncestorHashes,
    Pong(solana_gossip::ping_pong::Pong),
    WindowIndex {
        header: RepairRequestHeader,
        slot: u64,
        shred_index: u64,
    },
    HighestWindowIndex {
        header: RepairRequestHeader,
        slot: u64,
        shred_index: u64,
    },
    Orphan {
        header: RepairRequestHeader,
        slot: u64,
    },
    AncestorHashes {
        header: RepairRequestHeader,
        slot: u64,
    },
}

struct PeerRateLimit {
    count: u32,
    window_start: std::time::Instant,
}

impl PeerRateLimit {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: std::time::Instant::now(),
        }
    }

    fn check_and_increment(&mut self) -> bool {
        let now = std::time::Instant::now();
        if now.duration_since(self.window_start).as_secs() >= RATE_LIMIT_WINDOW_SECS {
            self.count = 0;
            self.window_start = now;
        }
        if self.count >= MAX_REQUESTS_PER_SECOND {
            return false;
        }
        self.count += 1;
        true
    }
}

#[derive(Default)]
struct ServeRepairStats {
    // by request type
    window_index: u64,
    highest_window_index: u64,
    orphan: u64,
    ancestor_hashes: u64,
    pong: u64,
    legacy: u64,

    // outcomes
    served: u64,
    rate_limited: u64,

    // drop reasons
    drop_deserialize: u64,
    drop_header_invalid: u64,
    drop_not_found: u64,
    drop_fjall_error: u64,
    drop_oversized: u64,
    drop_unsupported: u64,
}

impl ServeRepairStats {
    fn total_dropped(&self) -> u64 {
        self.drop_deserialize
            + self.drop_header_invalid
            + self.drop_not_found
            + self.drop_fjall_error
            + self.drop_oversized
            + self.drop_unsupported
    }

    fn flush(&mut self, metrics: &MetricsSender) {
        let dropped = self.total_dropped();
        log::info!(
            "serve_repair stats: served={} dropped={} rate_limited={} | \
             requests: window_index={} highest_window_index={} orphan={} ancestor_hashes={} pong={} legacy={} | \
             drop reasons: deserialize={} header_invalid={} not_found={} fjall_error={} oversized={} unsupported={}",
            self.served,
            dropped,
            self.rate_limited,
            self.window_index,
            self.highest_window_index,
            self.orphan,
            self.ancestor_hashes,
            self.pong,
            self.legacy,
            self.drop_deserialize,
            self.drop_header_invalid,
            self.drop_not_found,
            self.drop_fjall_error,
            self.drop_oversized,
            self.drop_unsupported,
        );
        metrics.measure(ServeRepairMeasurement::new(
            self.served,
            dropped,
            self.rate_limited,
        ));
        *self = Self::default();
    }
}

fn deserialize_request(packet: &[u8]) -> Option<RepairProtocol> {
    bincode::options()
        .with_limit(packet.len() as u64)
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(packet)
        .ok()
}

fn build_shred_response(shred_data: &[u8], nonce: Nonce) -> Option<Vec<u8>> {
    let size = shred_data.len() + SIZE_OF_NONCE;
    if size > PACKET_DATA_SIZE {
        return None;
    }
    let mut buf = Vec::with_capacity(size);
    buf.extend_from_slice(shred_data);
    buf.extend_from_slice(&nonce.to_le_bytes());
    Some(buf)
}

async fn handle_ping(
    kp: &Keypair,
    socket: &UdpSocket,
    packet: &PacketView,
    from_addr: SocketAddr,
) -> bool {
    if packet.len() != REPAIR_RESPONSE_SERIALIZED_PING_BYTES {
        return false;
    }
    let Ok(RepairResponse::Ping(ping)) = bincode::deserialize(packet) else {
        return false;
    };
    if !ping.verify() {
        return false;
    }

    let pong = solana_core::repair::serve_repair::RepairProtocol::Pong(Pong::new(&ping, kp));
    let raw_pong = bincode::serialize(&pong).unwrap();

    if let Err(e) = socket.send_to(&raw_pong, from_addr).await {
        log::error!("serve_repair: failed to send pong to {from_addr}: {e}");
    }

    true
}

fn validate_header(header: &RepairRequestHeader, my_id: &Pubkey) -> bool {
    if header.recipient != *my_id {
        log::debug!(
            "serve_repair: recipient mismatch: expected={my_id} got={}",
            header.recipient,
        );
        return false;
    }
    if header.sender == *my_id {
        log::debug!("serve_repair: rejected self-repair from {my_id}");
        return false;
    }
    let time_diff_ms = solana_sdk::timing::timestamp().abs_diff(header.timestamp);
    // 10 minute window
    if time_diff_ms > 10 * 60 * 1000 {
        log::debug!(
            "serve_repair: timestamp skew too large: {time_diff_ms}ms from sender={}",
            header.sender,
        );
        return false;
    }
    true
}

pub async fn start_serve_repair(
    exit: CancelRx,
    keypair: Arc<Keypair>,
    socket: UdpSocket,
    shred_store: ShredStore,
    cluster_info: Arc<ClusterInfo>,
    metrics: MetricsSender,
) {
    let socket = Rc::new(socket);
    let my_id = cluster_info.id();

    let task = spawn_local(async move {
        let mut rate_limits: HashMap<SocketAddr, PeerRateLimit> = HashMap::new();
        let mut stats = ServeRepairStats::default();
        let mut last_stats_report = std::time::Instant::now();
        let mut last_rate_limit_cleanup = std::time::Instant::now();

        loop {
            let Some((packet, from_addr)) = recv_shred(&socket).await else {
                continue;
            };

            if handle_ping(&keypair, &socket, &packet, from_addr).await {
                continue;
            }

            // Rate limit per peer
            let rate_limit = rate_limits
                .entry(from_addr)
                .or_insert_with(PeerRateLimit::new);
            if !rate_limit.check_and_increment() {
                stats.rate_limited += 1;
                report_stats_if_needed(&mut stats, &mut last_stats_report, &metrics);
                continue;
            }

            let Some(request) = deserialize_request(&packet) else {
                stats.drop_deserialize += 1;
                report_stats_if_needed(&mut stats, &mut last_stats_report, &metrics);
                continue;
            };

            match request {
                RepairProtocol::WindowIndex {
                    header,
                    slot,
                    shred_index,
                } => {
                    stats.window_index += 1;
                    if !validate_header(&header, &my_id) {
                        stats.drop_header_invalid += 1;
                        report_stats_if_needed(&mut stats, &mut last_stats_report, &metrics);
                        continue;
                    }
                    match shred_store.get_shred(slot, shred_index, ShredType::Data) {
                        Ok(Some(shred_data)) => {
                            if let Some(response) = build_shred_response(&shred_data, header.nonce)
                            {
                                if let Err(e) = socket.send_to(&response, from_addr).await {
                                    log::warn!("serve_repair: send WindowIndex failed: {e}");
                                }
                                stats.served += 1;
                            } else {
                                stats.drop_oversized += 1;
                            }
                        }
                        Ok(None) => stats.drop_not_found += 1,
                        Err(e) => {
                            log::warn!("serve_repair: fjall lookup error: {e}");
                            stats.drop_fjall_error += 1;
                        }
                    }
                }
                RepairProtocol::HighestWindowIndex {
                    header,
                    slot,
                    shred_index,
                } => {
                    stats.highest_window_index += 1;
                    if !validate_header(&header, &my_id) {
                        stats.drop_header_invalid += 1;
                        report_stats_if_needed(&mut stats, &mut last_stats_report, &metrics);
                        continue;
                    }
                    match shred_store.get_slot_shreds(slot) {
                        Ok(shreds) => {
                            let mut sent = false;
                            for shred_data in &shreds {
                                if let Some(idx) =
                                    solana_ledger::shred::layout::get_index(shred_data)
                                    && u64::from(idx) >= shred_index
                                    && let Some(response) =
                                        build_shred_response(shred_data, header.nonce)
                                {
                                    if let Err(e) = socket.send_to(&response, from_addr).await {
                                        log::warn!(
                                            "serve_repair: send HighestWindowIndex failed: {e}"
                                        );
                                    }
                                    sent = true;
                                    break;
                                }
                            }
                            if sent {
                                stats.served += 1;
                            } else {
                                stats.drop_not_found += 1;
                            }
                        }
                        Err(e) => {
                            log::warn!("serve_repair: fjall lookup error: {e}");
                            stats.drop_fjall_error += 1;
                        }
                    }
                }
                RepairProtocol::Orphan { .. } => {
                    stats.orphan += 1;
                    stats.drop_unsupported += 1;
                }
                RepairProtocol::AncestorHashes { .. } => {
                    stats.ancestor_hashes += 1;
                    stats.drop_unsupported += 1;
                }
                RepairProtocol::Pong(_) => {
                    stats.pong += 1;
                }
                _ => {
                    stats.legacy += 1;
                    stats.drop_unsupported += 1;
                }
            }

            report_stats_if_needed(&mut stats, &mut last_stats_report, &metrics);

            // Periodic rate limit map cleanup (every 60s)
            if last_rate_limit_cleanup.elapsed().as_secs() >= 60 {
                rate_limits.retain(|_, rl| rl.window_start.elapsed().as_secs() < 30);
                last_rate_limit_cleanup = std::time::Instant::now();
            }
        }
    });

    exit.await;
    task.cancel().await;
}

fn report_stats_if_needed(
    stats: &mut ServeRepairStats,
    last_report: &mut std::time::Instant,
    metrics: &MetricsSender,
) {
    if last_report.elapsed().as_secs() >= STATS_REPORT_INTERVAL_SECS {
        stats.flush(metrics);
        *last_report = std::time::Instant::now();
    }
}
