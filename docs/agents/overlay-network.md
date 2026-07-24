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

Transport is behind `OverlayQuicTransport`, a glommio driver around the
`quinn-proto` sans-IO QUIC state machine. The runner owns this transport from a
single glommio task because endpoint and connection state must be driven
mutably: UDP receives are fed into `Endpoint::handle`, outgoing `Transmit`
values are written through `glommio::net::UdpSocket`, and QUIC timers are polled
from the same loop.

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
