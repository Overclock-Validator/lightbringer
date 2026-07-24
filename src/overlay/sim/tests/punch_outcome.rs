//! P5 rung-4 outcome-cache oracle. A random allocator with birthday disabled
//! reaches connected-only once; repeated targeted sends must not restart the
//! ladder for the same peer pair/NAT generation.

use std::time::Duration;

use crate::overlay::sim::{NodeOptions, SimWorld, nat::NatConfig, net::LinkParams};

#[test]
fn random_symmetric_without_opt_in_falls_back_once_then_caches() {
    let mut world = SimWorld::with_trace(0x5055_4E30, false);
    world.set_default_link(
        LinkParams::default().delay(Duration::from_millis(2), Duration::from_millis(6)),
    );
    let v1 = world.add_node(NodeOptions {
        bind_port: 3478,
        ..NodeOptions::default()
    });
    let v2 = world.add_node(NodeOptions {
        bind_port: 3478,
        ..NodeOptions::default()
    });
    let v3 = world.add_node(NodeOptions {
        bind_port: 5321,
        ..NodeOptions::default()
    });
    let via_addrs = vec![world.public_addr(v1), world.public_addr(v2), world.public_addr(v3)];
    let a = world.add_node(NodeOptions {
        nat: vec![NatConfig::symmetric_random()],
        static_peers: via_addrs.clone(),
        bind_port: 51_000,
        zero_config: true,
        ..NodeOptions::default()
    });
    let b = world.add_node(NodeOptions {
        nat: vec![NatConfig::port_restricted_cone()],
        static_peers: vec![via_addrs[0]],
        bind_port: 51_001,
        zero_config: true,
        ..NodeOptions::default()
    });
    let b_pk = world.overlay_pubkey(b);
    world.run_for(Duration::from_secs(45));
    assert!(world.request_direct_path(a, b_pk));
    world.run_for(Duration::from_secs(6));
    assert!(world.peer_connection_addr(a, &b_pk).is_none());
    assert_eq!(world.punch_attempts(a), 1);
    assert!(
        !world.request_direct_path(a, b_pk),
        "the failed NAT-generation tuple must be cached",
    );
    assert_eq!(world.punch_attempts(a), 1);
}
