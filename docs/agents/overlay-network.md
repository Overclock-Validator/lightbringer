# Overlay Network Notes

The overlay implementation is isolated under `src/overlay` with a small
integration surface:

- `src/config.rs` parses an optional `[overlay]` section.
- `src/main.rs` starts the overlay runner only when `overlay.enabled = true`.
- `src/turbine_manager.rs` feeds only the packet filter.
- `src/packet_filter.rs` can mirror leader/signature-verified shreds into the
  overlay source channel after the existing filter accepts them.

Overlay sink mode is deliberately isolated from Solana networking. When
`overlay.enabled = true` and `overlay.mode = "sink"`, startup does not require a
`gossip_entrypoint`, does not construct `GossipManager`, does not bind Solana
turbine/repair sockets, and does not start Solana repair serving. Sink still
routes overlay shreds through the packet filter: the filter fetches Solana leader
schedule over RPC and verifies each shred signature against the scheduled leader
before slot metadata can observe it. Sink configs must provide
`overlay.shred_version` locally for slot metadata filtering.

Current feature scope assumes every peer is Tier 2. `TurbineTree` implements the
Solana turbine retransmit shape: root sends to the first layer, and non-root
nodes select the next layer by neighborhood offset and fanout stride. The peer
ordering is deterministic per shred, but uses the overlay peer socket addresses
and the parsed shred id as the seed because overlay stake-weighted identity is
not defined yet.

Source mode never disseminates raw turbine input directly. Solana turbine shreds
first pass through `packet_filter_loop`, which fetches the Solana leader schedule
over RPC and verifies the shred signature against the scheduled leader. Only
validated packets are mirrored to the overlay source channel.

Lightbringer gossip is represented by `LightbringerGossip`. It tracks overlay
addresses plus repair addresses from peer advertisements, prunes stale records by
TTL, and exposes discovered repair peers for the repair integration that follows.
`overlay.repair_addr` is mandatory whenever the overlay is enabled. Sink mode
must not use Solana repair as a fallback; until the overlay repair requester is
wired, generated sink repair requests are logged rather than sent to Solana.

The overlay core is sans-IO behind the seams from
`docs/overlay/nat-traversal.md` §6.9. `OverlayEnv` (`src/overlay/env.rs`) is
the low seam: virtual-clock `now`, seeded `rng`, non-blocking `send`, helper
`bind`. `OverlayTransport` (`src/overlay/transport.rs`) is the high seam over
connections/datagrams. `OverlayQuicTransport` extends quinn-proto's sans-IO
shape upward — `on_datagram`/`on_timer`/`poll_timeout`/`poll_inbound`/
`poll_event`, transmits flushed through `OverlayEnv::send` — and binds the
TLS-recovered peer pubkey to connection state (`peer_identity`). QUIC
keepalive is 10s and max idle timeout 30s (`TransportOptions`), which is what
holds NAT mappings alive. `OverlayCore` (`src/overlay/service.rs`) is the
event-driven runner state machine on top; advert scheduling is
deadline-based, never a sleep. Production IO lives only in the thin driver
`src/overlay/driver_glommio.rs` (socket ownership, kanal channels, timer
waits); `start_overlay_runner` keeps its old signature.

The deterministic discrete-event simulator (`src/overlay/sim/`, cargo
feature `sim`) is a second driver over the same seams: seeded PRNGs
everywhere, virtual time, a per-link fault model (FIFO by default — an
explicit `reorder_probability` exists because unconstrained random delays
trip QUIC loss detection), composable NAT boxes covering the §6.2 taxonomy
(including the field-note dst-port-dependent preset), and seed-derived
crypto (node keypairs, quinn rng/cids/reset key, rustls SecureRandom). Run
scenarios with `cargo run --bin overlay-sim --features sim -- --seed N`; the
printed trace hash is the reproducibility witness. Note trace hashes cover
timing/endpoints/sizes/app payloads, not ciphertext bytes — ring generates
ECDHE keys from its own entropy outside the rustls SecureRandom seam.

Overlay QUIC identity reuses `identity.json`. `OverlayIdentity` follows the same
pattern as Agave's TLS utilities: the Solana Ed25519 secret is encoded as
PKCS#8, and the Solana pubkey is placed in the X.509 SubjectPublicKeyInfo field.
The X.509 certificate signature is not the trust root; custom rustls client and
server verifiers accept certificates that carry a recoverable Solana pubkey and
delegate TLS 1.3 CertificateVerify signature checks to rustls/webpki. Clients
also present the same `identity.json`-derived cert, so inbound and outbound QUIC
handshakes both authenticate an Ed25519 overlay identity. The recovered peer
pubkey is currently logged on handshake and is available for future gossip-level
identity binding.
