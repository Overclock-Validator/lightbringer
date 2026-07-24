//! P2 stream-seam tests (nat-traversal.md §6.4/§6.9): the
//! `OverlayTransport` bidirectional-stream surface, exercised over real
//! quinn-proto streams in the low-seam world and over the `MemTransport`
//! mirror in the high-seam tier.

use std::time::Duration;

use crate::overlay::{
    sim::{NodeOptions, SimWorld, highseam::MemTransport, nat::NatConfig, net::LinkParams},
    transport::{OverlayStreamId, OverlayTransport, StreamEvent},
};

/// Concatenated `Data` bytes for one stream, plus terminal flags.
fn stream_outcome(events: &[StreamEvent], stream: OverlayStreamId) -> (Vec<u8>, bool, bool) {
    let mut bytes = Vec::new();
    let mut finished = false;
    let mut failed = false;
    for event in events {
        match event {
            StreamEvent::Data { stream: s, bytes: b } if *s == stream => {
                bytes.extend_from_slice(b)
            }
            StreamEvent::Finished { stream: s } if *s == stream => finished = true,
            StreamEvent::Failed { stream: s } if *s == stream => failed = true,
            _ => {}
        }
    }
    (bytes, finished, failed)
}

fn opened_stream(events: &[StreamEvent]) -> Option<OverlayStreamId> {
    events.iter().find_map(|event| match event {
        StreamEvent::Opened { stream, .. } => Some(*stream),
        _ => None,
    })
}

/// A request/response echo over a real QUIC bidi stream, with a payload
/// large enough to span several packets at the fixed 1280 MTU. FIN
/// delimits both directions — the exact §6.4 exchange shape.
#[test]
fn low_seam_stream_echo_roundtrip() {
    let mut world = SimWorld::new(11);
    let a = world.add_transport_node(NodeOptions::default());
    let b = world.add_transport_node(NodeOptions::default());
    let b_addr = world.public_addr(b);
    let b_pubkey = world.overlay_pubkey(b);

    // Establish the connection via a dial-on-demand datagram.
    world.transport_send(a, b_addr, b"hello".to_vec());
    world.run_for(Duration::from_secs(2));

    let request: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let stream = world
        .transport_open_stream(a, &b_pubkey)
        .expect("connection established, stream opens");
    world.transport_write_stream(a, stream, &request);
    world.transport_finish_stream(a, stream);
    world.run_for(Duration::from_secs(2));

    let b_stream = opened_stream(world.transport_stream_events(b)).expect("B saw the stream open");
    let (got_request, finished, failed) = stream_outcome(world.transport_stream_events(b), b_stream);
    assert!(finished && !failed, "request side must FIN cleanly");
    assert_eq!(got_request, request);

    let mut response = request.clone();
    response.reverse();
    world.transport_write_stream(b, b_stream, &response);
    world.transport_finish_stream(b, b_stream);
    world.run_for(Duration::from_secs(2));

    let (got_response, finished, failed) = stream_outcome(world.transport_stream_events(a), stream);
    assert!(finished && !failed, "response side must FIN cleanly");
    assert_eq!(got_response, response);
}

/// The same exchange across a lossy, delayed link: stream data is
/// retransmitted by QUIC and still arrives complete — the §6.4 reason
/// repair responses ride streams, not datagrams.
#[test]
fn low_seam_stream_survives_loss() {
    let mut world = SimWorld::new(13);
    let a = world.add_transport_node(NodeOptions::default());
    let b = world.add_transport_node(NodeOptions::default());
    let b_addr = world.public_addr(b);
    let b_pubkey = world.overlay_pubkey(b);
    world.set_default_link(
        LinkParams::default()
            .delay(Duration::from_millis(10), Duration::from_millis(40))
            .drop_probability(0.15),
    );

    world.transport_send(a, b_addr, b"hello".to_vec());
    world.run_for(Duration::from_secs(5));

    let request: Vec<u8> = (0..4096u32).map(|i| (i % 199) as u8).collect();
    let stream = world
        .transport_open_stream(a, &b_pubkey)
        .expect("connection established, stream opens");
    world.transport_write_stream(a, stream, &request);
    world.transport_finish_stream(a, stream);
    world.run_for(Duration::from_secs(20));

    let b_stream = opened_stream(world.transport_stream_events(b)).expect("B saw the stream open");
    let (got, finished, failed) = stream_outcome(world.transport_stream_events(b), b_stream);
    assert!(finished && !failed, "stream must complete despite 15% loss");
    assert_eq!(got, request);
}

/// The R2-critical direction: the peer that ACCEPTED a connection from a
/// NATed node opens a stream back toward it over that connection. No new
/// dial, no NAT machinery — the §5 connectivity argument on the wire.
#[test]
fn low_seam_stream_reaches_natted_peer_over_existing_connection() {
    let mut world = SimWorld::new(17);
    let public = world.add_transport_node(NodeOptions::default());
    let public_addr = world.public_addr(public);
    let natted = world.add_transport_node(NodeOptions {
        nat: vec![NatConfig::symmetric_random()],
        ..NodeOptions::default()
    });
    let natted_pubkey = world.overlay_pubkey(natted);

    // The NATed side dials out; that connection is the only path to it.
    world.transport_send(natted, public_addr, b"outbound".to_vec());
    world.run_for(Duration::from_secs(2));

    let stream = world
        .transport_open_stream(public, &natted_pubkey)
        .expect("accepted connection is stream-capable toward the NATed peer");
    world.transport_write_stream(public, stream, b"request-through-nat");
    world.transport_finish_stream(public, stream);
    world.run_for(Duration::from_secs(2));

    let natted_stream =
        opened_stream(world.transport_stream_events(natted)).expect("NATed side saw the stream");
    let (got, finished, failed) = stream_outcome(world.transport_stream_events(natted), natted_stream);
    assert!(finished && !failed);
    assert_eq!(got, b"request-through-nat");

    world.transport_write_stream(natted, natted_stream, b"served-from-behind-nat");
    world.transport_finish_stream(natted, natted_stream);
    world.run_for(Duration::from_secs(2));

    let (got, finished, failed) = stream_outcome(world.transport_stream_events(public), stream);
    assert!(finished && !failed);
    assert_eq!(got, b"served-from-behind-nat");
}

/// MemTransport mirrors the stream contract exactly: open/data/fin both
/// directions, reset surfaces as `Failed`, disconnect kills streams.
#[test]
fn mem_transport_stream_mirror() {
    use crate::overlay::env::{OverlayEnv, SocketId};
    use anyhow::Result;
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use solana_sdk::{signature::Keypair, signer::Signer};
    use std::net::SocketAddr;
    use std::time::Instant;

    struct NullEnv {
        now: Instant,
        rng: StdRng,
    }
    impl OverlayEnv for NullEnv {
        fn now(&self) -> Instant {
            self.now
        }
        fn rng(&mut self) -> &mut dyn RngCore {
            &mut self.rng
        }
        fn send(&mut self, _from: SocketId, _to: SocketAddr, _datagram: &[u8]) {}
        fn bind(&mut self, _port: Option<u16>) -> Result<SocketId> {
            unreachable!()
        }
        fn close(&mut self, _socket: SocketId) {}
    }
    let mut env = NullEnv {
        now: Instant::now(),
        rng: StdRng::seed_from_u64(0),
    };

    let (a_pk, b_pk) = (Keypair::new().pubkey(), Keypair::new().pubkey());
    let (a_addr, b_addr): (SocketAddr, SocketAddr) =
        ("10.0.0.1:1".parse().unwrap(), "10.0.0.2:1".parse().unwrap());
    let mut a = MemTransport::new();
    let mut b = MemTransport::new();
    a.establish(b_pk, b_addr);
    b.establish(a_pk, a_addr);

    // No stream toward an unconnected peer.
    assert!(a.open_stream(&Keypair::new().pubkey()).is_none());

    let stream = a.open_stream(&b_pk).expect("connected peer");
    assert!(a.write_stream(&mut env, stream, b"req"));
    a.finish_stream(&mut env, stream);
    for (to, op) in a.take_stream_ops() {
        assert_eq!(to, b_pk);
        b.deliver_stream_op(a_pk, op);
    }

    let b_stream = match b.poll_stream_event() {
        Some(StreamEvent::Opened { stream, peer }) => {
            assert_eq!(peer, a_pk);
            stream
        }
        other => panic!("expected Opened, got {other:?}"),
    };
    match b.poll_stream_event() {
        Some(StreamEvent::Data { stream, bytes }) => {
            assert_eq!(stream, b_stream);
            assert_eq!(bytes, b"req");
        }
        other => panic!("expected Data, got {other:?}"),
    }
    assert!(matches!(
        b.poll_stream_event(),
        Some(StreamEvent::Finished { stream }) if stream == b_stream
    ));

    // Response direction over the same stream.
    assert!(b.write_stream(&mut env, b_stream, b"resp"));
    b.finish_stream(&mut env, b_stream);
    for (to, op) in b.take_stream_ops() {
        assert_eq!(to, a_pk);
        a.deliver_stream_op(b_pk, op);
    }
    match a.poll_stream_event() {
        Some(StreamEvent::Data { stream: s, bytes }) => {
            assert_eq!(s, stream);
            assert_eq!(bytes, b"resp");
        }
        other => panic!("expected Data, got {other:?}"),
    }
    assert!(matches!(
        a.poll_stream_event(),
        Some(StreamEvent::Finished { stream: s }) if s == stream
    ));
    // Both sides FIN'd: state is reaped, further writes fail.
    assert!(!a.write_stream(&mut env, stream, b"late"));
    assert!(!b.write_stream(&mut env, b_stream, b"late"));

    // Reset surfaces as Failed on the other side.
    let stream = a.open_stream(&b_pk).unwrap();
    for (_, op) in a.take_stream_ops() {
        b.deliver_stream_op(a_pk, op);
    }
    let b_stream = match b.poll_stream_event() {
        Some(StreamEvent::Opened { stream, .. }) => stream,
        other => panic!("expected Opened, got {other:?}"),
    };
    a.reset_stream(&mut env, stream);
    for (_, op) in a.take_stream_ops() {
        b.deliver_stream_op(a_pk, op);
    }
    assert!(matches!(
        b.poll_stream_event(),
        Some(StreamEvent::Failed { stream }) if stream == b_stream
    ));

    // Disconnect fails every live stream with that peer.
    let stream = a.open_stream(&b_pk).unwrap();
    a.disconnect(&b_pk);
    assert!(matches!(
        a.poll_stream_event(),
        Some(StreamEvent::Failed { stream: s }) if s == stream
    ));
    assert!(!a.write_stream(&mut env, stream, b"dead"));
}
