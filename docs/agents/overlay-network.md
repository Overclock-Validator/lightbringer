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
nodes select the next layer by neighborhood offset and fanout stride. The
shuffle is seeded by the parsed shred id and peer *pubkeys*
(nat-traversal.md §6.7) over the node's usable peer set: established
connections plus peers advertising `Reachability::Direct`. Locally-originated
shreds go through `origin_peers` — the source acts as the leader, handing the
shred to the shuffled root when the shuffle puts the source off-root.

Source mode never disseminates raw turbine input directly. Solana turbine shreds
first pass through `packet_filter_loop`, which fetches the Solana leader schedule
over RPC and verifies the shred signature against the scheduled leader. Only
validated packets are mirrored to the overlay source channel.

Address discovery is identity-first (nat-traversal.md §6.2, phase P3). On
every established connection each side sends `OverlayFrame::AddressObservation`
reporting the peer's observed remote address; the receiver tags it with the
observing peer's identity/inbound port and aggregates per §6.2 in the bounded
`AddressDiscovery` store (`src/overlay/discovery.rs`), which classifies
Public / EIM / PortDependent / Symmetric via the shared `overlay::nat`
classifier and calibrates the EDM allocator discipline (recorded for P5).
Before advertising `Direct`, the node dial-back-confirms its candidate: it
asks a connected helper to dial the candidate from a FRESH source port
(`OverlayEnv::bind` + an isolated probe connection in the QUIC transport with
its own egress `SocketId`); success requires a completed handshake with the
node's identity, so restricted filtering — exercised by the fresh port —
correctly keeps restricted/EDM nodes `Coordinated`. Helper hardening (§9):
per-requester rate limit, privileged-port refusal, short-lived sockets, and
reflection-safety by construction (the helper only ever targets the
requester's own observed source). Auto-advert (§7): operator `advertised_addr`
wins; else a dial-back-confirmed candidate advertises `Direct`; else
`Coordinated` with the §12-Q3 hint policy (fully symmetric → empty observed;
every other flavor → port-tagged observed hints; `via` = connected peers).
Receiver-side F8 closure (§6.2.3): a `Direct` advert no longer authorizes
payload by itself — the send choke point uses identity-gated dial-on-demand
(`queue_datagram_expecting`), so the first shred rides the dial but the
transport releases it only once the connection authenticates as the
advertised identity; a mismatch drops it undelivered and quarantines the
lied-about address (address-keyed, so an innocent node answering there is
never fanned to either). A superseding advert for a different address is
re-confirmable.

Port mapping (nat-traversal.md §6.3, phase P4) upgrades reach for homes
with a cooperative gateway. `src/overlay/portmap.rs` is a sans-IO client
that walks **PCP → NAT-PMP → UPnP IGD** against `overlay.gateway_addr`
(auto-discovered from the default route by the driver when unset): PCP and
NAT-PMP are fixed-layout datagrams on gateway:5351 riding the existing
`OverlayEnv` seam from a dedicated helper socket; SSDP is one more datagram
exchange (the `LOCATION` host is pinned to the gateway IP — an SSDP frame
must never steer HTTP at a third party, §9); the UPnP describe/SOAP
conversation rides a new TCP byte-stream lane on the seam
(`tcp_connect`/`tcp_send`/`tcp_close` + driver-fed `TcpEvent`s — glommio
spawns one task per conn; the sim's gateway answers in-world). Leases renew
at half-life through the granting rung; an unrenewable lease expires and
withdraws the candidate; malformed or spoofed gateway bytes drop inertly
and are counted. A grant alone is NEVER advertised: the §6.2.3 dial-back
grew a candidate kind — the port-mapped candidate is (observed external
IP, granted port), and `DialBackRequest` carries an optional
`probe_port` override (the probe IP stays pinned to the request's own
source; helpers now probe the datagram source rather than the
identity-indexed connection address, which also keeps multi-connection
peers correct). A gateway that grants a port the world cannot reach — CGN,
or a lying gateway — fails the fresh-source probe and the node stays
`Coordinated`. Auto-advert order: operator `advertised_addr` →
dial-back-confirmed observed mapping → dial-back-confirmed port-mapped
address → `Coordinated`.

IPv6 dual advertisement (§6.3 step 2, phase P4): `overlay.bind_addr_v6`
binds a second overlay socket on the same QUIC endpoint (transport egress
picks the socket by destination family). Address observations are
family-split into a second `AddressDiscovery` store. Each advert cycle an
unconfirmed dual-stack node dials up to three peers advertising a v6
`Direct` address over its v6 socket (identity-gated, payload = the cycle's
signed advert) so helpers observe its v6 source; the port mapper requests
a PCP pinhole for the v6 port alongside the v4 mapping. The v6 dial-back
request rides the v6 connection (address-directed), so the helper's
fresh-source probe exercises the RFC 6092 firewall for real — without a
pinhole (or open firewall) it fails and the v6 address is never
advertised, the §4 punchr caution as an invariant. A confirmed (or
operator `advertised_addr_v6`) address rides `Reachability::Direct` listed
BEFORE v4, and the dial path in `send_to_peer` prefers a v6 entry whenever
the node holds a v6 socket, falling back to v4 when the preferred address
is quarantined. No protocol bump: dual addresses ride the existing Direct
`ArrayVec` and the `DialBackRequest` body extension stays inside unfrozen
v1.

Gossip is identity-first (nat-traversal.md §6.1, phase P1).
`LightbringerGossip` keys peers by Ed25519 pubkey in a bounded
`LruBTreeMap` — one entry per node no matter how many addresses it is seen
at. Peer advertisements are `SignedPeerAdvert`s: `PeerAdvert { pubkey,
advert_seq, ttl_ms, reachability, repair }` signed by the advertised
identity; receivers verify before accepting or flood-forwarding, and
`advert_seq` supersession rejects replays. Nodes with an
operator-configured `advertised_addr` advertise `Reachability::Direct`;
everyone else advertises `Coordinated` (there is no fallback to
`bind_addr`). Every send funnels through the core's `send_to_peer` choke
point: prefer the established connection (the transport keeps a
pubkey→address index over TLS-verified identities), dial only `Direct`
peers, otherwise drop and count. Shred retransmit loop suppression is a
bounded LRU dedup keyed on payload hash — the wire frame carries no origin
field.

Repair rides overlay QUIC bidirectional streams (nat-traversal.md §6.4,
phase P2 — R2 complete for every NAT type). The sub-protocol is a fresh
minimal bincode pair in `src/overlay/repair.rs` — a client-opened bidi
stream carries one `RepairReq { WindowIndex | HighestWindowIndex }`, the
server answers `RepairResp { Shred(bytes) | NotFound }`, FIN both ways —
explicitly NOT Solana's `RepairProtocol`: no header/signature/nonce/ping,
because the QUIC connection already authenticates both ends. Responses
never touch the 1242-byte datagram budget. Every overlay node serves:
`OverlayCore` parses and rate-admits inbound requests (per-pubkey
LRU-bounded limiter, 100 req/s) and emits `CoreEvent::RepairRequest`; the
DRIVER does the blocking fjall lookup behind the narrow `RepairStore` seam
(`ShredStore` in production, an in-memory map in the sim) and answers via
`on_repair_response`. Malformed or over-limit streams are reset and
counted, never served.

The requesting side runs the same `RepairManager` loop in both worlds
behind `RepairPeerSource::sample_peer → RepairTarget::{Udp(addr, pubkey),
Overlay(pubkey)}`: Solana mode keeps `ClusterInfo::repair_peers` verbatim
(`SolanaRepairPeers`); sink mode samples the overlay gossip view
(`OverlayRepairPeerSource` over a driver-republished `SharedRepairView`) —
peers advertising `RepairEndpoint::Udp` go out the node's own repair UDP
socket in Solana wire format, `InConnection` peers ride streams over
existing connections only (never dialed; unreachable targets drop and
count). `PeerSample`'s latency-weighted selection is ported keyed by
pubkey and lives in `overlay::repair`. Responses are matched by
`RepairRoute` (UDP source address / stream peer identity); the driver
returns stream responses UDP-shaped (shred ‖ nonce LE) so the outstanding
store and packet filter treat both worlds identically.
`overlay.repair_addr` is optional since P2: unset advertises
`RepairEndpoint::InConnection` (streams serve it); set, it advertises a
Solana-format UDP endpoint — which sink mode does not serve, so sink
operators should leave it unset.

The wire format (v1, still unfrozen) is a two-byte header (version, frame
type) followed by the body: raw shred bytes delimited by the QUIC datagram
boundary, or a bincode `SignedPeerAdvert`. The path MTU is fixed at 1280
(`OVERLAY_INITIAL_MTU`, IPv6 minimum; MTU discovery off), giving a
1242-byte datagram budget — a maximum 1228-byte shred frames to 1230
bytes. The sim's `tests/mtu.rs` pins the boundary empirically.

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

Since P4 the sim world is dual-stack: every host gets a global v6 address
(2001:db8::/32 scheme) and a second overlay socket unless `ipv6: false`;
NATed hosts' v6 sits behind an RFC 6092 default-deny `FirewallBox` (flow
tracking + PCP pinholes — no rewriting), public hosts' v6 is open. A
NATed host may attach a `Gateway` model (`sim/gateway.rs`) at
10.<id>.0.1: it answers real PCP/NAT-PMP bytes on :5351, SSDP on :1900
(and the multicast group), and UPnP HTTP/SOAP over the sim TCP model, with
per-tier modes Off/Grant/Deny/GrantFake/Malformed; grants install
lease-based static mappings on the innermost `NatBox` (so mapping stays
useless behind CGN by construction) or pinholes on the firewall. Static
mappings are full-cone and give the mapped internal socket DNAT flow
symmetry — outbound from a port-forwarded socket egresses the mapped port,
as conntrack does, which is what makes even a symmetric NAT probeable once
mapped. Gateway responses are hand-built independently of the client
codecs (the NatBox-vs-classifier ground-truth split). P4 scenarios in
`SCENARIOS`: `portmap-matrix`, `portmap-lease`, `ipv6-dual-advert`, plus
the v6-family rows `two-node-lossy-v6` and
`keepalive-firewall-v6`/`-control`.

The high-seam tier (`src/overlay/sim/highseam.rs`) swaps the QUIC transport
for `MemTransport`, an in-memory authenticated fake, so hundreds of
`OverlayCore`s run gossip/advert/turbine/repair logic in a deterministic
tick-driven harness (`HighSeamNet`) — this is where the per-phase safety
oracles run (`sim/tests/gossip_oracles.rs`, `advert_security.rs`,
`repair_abuse.rs`, `repair_sampling.rs`). `MemTransport` mirrors the P2
stream seam: stream ops are reliable and ordered (exempt from the drop
model — on real QUIC, loss is stream latency, never stream data loss),
carried by the harness with the same one-tick latency as datagrams. Dev
builds compile the dalek crypto crates at opt-level 3 (see Cargo.toml
profile overrides); without that, ed25519 dominates the sim suite ~100x.

`OverlayTransport` carries the P2 stream surface at both tiers:
`open_stream` (established connections only, by identity), buffered
`write_stream`/`finish_stream`/`reset_stream`, and polled `StreamEvent`s
(`Opened`/`Data`/`Finished`/`Failed`); `OverlayQuicTransport` plumbs the
quinn-proto Streams API sans-IO with transport-unique handles that never
recycle across reconnects. The P2 deliverable scenarios
(`repair-nat-matrix`, `repair-liveness`, `repair-performance` in
`sim/scenario.rs`) assert the §10 P2 definition of done: R2 across every
§6.2 NAT row including a symmetric+CGNAT *server*, gap liveness through
loss/partition/restart, and latency/bytes-per-shred performance rails —
all auto-covered by the determinism suite.

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
