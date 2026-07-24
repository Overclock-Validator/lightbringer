//! MTU budget regression (nat-traversal.md §8): at the production
//! `OVERLAY_INITIAL_MTU` of 1280 (IPv6 minimum, MTUD disabled) the QUIC
//! datagram budget is exactly 1242 bytes, and the two-byte v1 shred frame
//! keeps even the 1228-byte shred maximum (merkle coding shreds) inside it.

use std::time::Duration;

use arrayvec::ArrayVec;
use solana_sdk::{pubkey::Pubkey, signer::Signer};

use crate::overlay::gossip::{
    PeerAdvert, PortTaggedAddr, Reachability, RepairEndpoint, SignedPeerAdvert,
};
use crate::overlay::sim::{NodeOptions, SimWorld, crypto};
use crate::overlay::{OverlayMode, packet::{OverlayFrame, SHRED_FRAME_OVERHEAD}};

/// 1280 − 29 (1-RTT header, 8-byte CID, worst-case PN, AEAD tag) − 9
/// (DATAGRAM frame bound).
const DATAGRAM_BUDGET: usize = 1242;
const MAX_SHRED_BYTES: usize = 1228;
const MERKLE_DATA_SHRED_BYTES: usize = 1203;

/// Empirical pin of the budget: a payload of exactly `DATAGRAM_BUDGET`
/// bytes traverses a bare-transport pair at the production MTU; one byte
/// more is refused by quinn (TooLarge) and never arrives.
#[test]
fn datagram_budget_boundary_at_production_mtu() {
    let mut world = SimWorld::new(11);
    let receiver = world.add_transport_node(NodeOptions::default());
    let receiver_addr = world.public_addr(receiver);
    let sender = world.add_transport_node(NodeOptions::default());

    world.transport_send(sender, receiver_addr, vec![0xA5; DATAGRAM_BUDGET]);
    world.transport_send(sender, receiver_addr, vec![0x5A; DATAGRAM_BUDGET + 1]);
    world.run_for(Duration::from_secs(5));

    let received = world.transport_received(receiver);
    assert!(
        received.iter().any(|(_, payload)| payload.len() == DATAGRAM_BUDGET),
        "budget-sized datagram must arrive"
    );
    assert!(
        !received.iter().any(|(_, payload)| payload.len() == DATAGRAM_BUDGET + 1),
        "over-budget datagram must be refused at the sender"
    );
}

/// The maximum shred (1228 B) plus framing stays within the budget, and a
/// max-size shred frame flows end-to-end between overlay nodes at the
/// production MTU. The payload is not a parseable shred, which is fine:
/// turbine falls back to hashing the payload for its seed.
#[test]
fn max_size_shred_frame_fits_and_flows() {
    let frame = OverlayFrame::shred(vec![0xC3; MAX_SHRED_BYTES]).encode().unwrap();
    assert_eq!(frame.len(), MAX_SHRED_BYTES + SHRED_FRAME_OVERHEAD);
    assert!(frame.len() <= DATAGRAM_BUDGET);

    let mut world = SimWorld::new(13);
    let source = world.add_node(NodeOptions {
        mode: OverlayMode::Source,
        ..NodeOptions::default()
    });
    let source_addr = world.public_addr(source);
    let sink = world.add_node(NodeOptions {
        static_peers: vec![source_addr],
        ..NodeOptions::default()
    });

    // The sink's first advert (t=10s) dials the source.
    world.run_for(Duration::from_secs(15));
    let payload = vec![0xC3; MAX_SHRED_BYTES];
    world.inject_shred(source, &payload);
    world.run_for(Duration::from_secs(2));

    assert!(
        world.delivered_shreds(sink).iter().any(|shred| shred == &payload),
        "max-size shred must traverse the overlay at the production MTU"
    );
}

/// The synthetic workload matches real merkle wire sizes: data shreds are
/// 1203 bytes (agave `merkle::ShredData::SIZE_OF_PAYLOAD`), comfortably
/// inside the budget with framing.
#[test]
fn workload_shreds_are_merkle_data_sized() {
    let shreds = crypto::make_signed_shreds(1, 42, 0);
    assert!(!shreds.is_empty());
    for shred in &shreds {
        assert_eq!(shred.len(), MERKLE_DATA_SHRED_BYTES);
        assert!(shred.len() + SHRED_FRAME_OVERHEAD <= DATAGRAM_BUDGET);
    }
}

/// Even a maximally-populated signed advert (four observed mappings, four
/// via peers) stays far below the datagram budget, so control traffic
/// never contends with the MTU.
#[test]
fn maximal_advert_frame_stays_within_budget() {
    let keypair = crypto::derive_keypair(1, 0);
    let mut observed = ArrayVec::new();
    let mut via = ArrayVec::new();
    for i in 0..4u8 {
        observed.push(PortTaggedAddr {
            observer_port: 3478 + u16::from(i),
            mapping: format!("198.51.100.{}:40000", i + 1).parse().unwrap(),
        });
        via.push(Pubkey::new_unique());
    }
    let advert = PeerAdvert {
        pubkey: keypair.pubkey(),
        advert_seq: u64::MAX,
        ttl_ms: u32::MAX,
        reachability: Reachability::Coordinated { observed, via },
        repair: RepairEndpoint::Udp("203.0.113.1:65411".parse().unwrap()),
    };
    let signed = SignedPeerAdvert::sign(advert, &keypair).unwrap();
    let frame = OverlayFrame::peer_advertisement(signed).encode().unwrap();
    assert!(frame.len() < 512, "advert frame too large: {}", frame.len());
    assert!(frame.len() <= DATAGRAM_BUDGET);
}
