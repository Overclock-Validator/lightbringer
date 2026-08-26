# Lightbringer configuration

Lightbringer reads `Lightbringer.toml` from its current working directory.
There is no command-line configuration-path override. It also creates or loads
`identity.json` in that directory, so use a persistent, private working
directory in production.

Start with the repository template:

```bash
cp Lightbringer.example.toml Lightbringer.toml
```

The example intentionally leaves the overlay disabled. Enable it only after
setting peer addresses and the necessary firewall rules for the deployment.

## Minimal source node

A source joins Solana gossip, receives Turbine shreds, verifies them, and can
forward verified shreds to overlay peers. `gossip_entrypoint` must resolve to
an IPv4 address and must be remote.

```toml
gossip_entrypoint = "198.51.100.20:8001"
storage = "./shred-store"
grpc_addr = "127.0.0.1:3001"

[overlay]
enabled = true
mode = "source"
bind_addr = "0.0.0.0:65410"
static_peers = ["198.51.100.30:65410"]
```

The bootstrap address must be reachable, not merely advertised by gossip. If
the source is healthy but does not receive Turbine packets shortly after
startup, choose another reachable gossip bootstrap before diagnosing the
overlay path.

## Minimal sink node

A sink accepts only overlay traffic. It does not create `GossipManager`, bind
Solana gossip/Turbine/repair sockets, or require `gossip_entrypoint`. It still
fetches the leader schedule over RPC and verifies every received shred before
it enters slot metadata.

```toml
storage = "./shred-store"
grpc_addr = "127.0.0.1:3001"

[overlay]
enabled = true
mode = "sink"
bind_addr = "0.0.0.0:65410"
static_peers = ["198.51.100.20:65410"]
shred_version = 50093 # Replace with the current cluster shred version.
```

`shred_version` is required in sink mode. The value above is illustrative;
obtain the current value from the target cluster and update it before running.
Leave `overlay.repair_addr` unset on a sink so repair is advertised and served
over established authenticated overlay connections.

## Root fields

| Field | Default | Meaning |
| --- | --- | --- |
| `gossip_entrypoint` | none | Required unless enabled overlay sink mode is used. A remote Solana gossip address. Ignored by sink mode if present. |
| `storage` | `./shred-store` | Fjall shred-store directory. Keep it persistent and writable. |
| `grpc_addr` | `127.0.0.1:3001` | Address for the gRPC slot stream. Bind to loopback unless remote access is deliberately protected. |
| `rpc_addr` | `127.0.0.1:3000` | Accepted for compatibility, but no runtime RPC listener currently uses it. |

`identity.json` is not a TOML field. Lightbringer creates it with owner-only
permissions when missing and reuses it as both its Solana and overlay identity.
Back it up securely if a stable node identity matters.

## Solana gossip ports

```toml
[gossip]
gossip_port = 65400
port_range_start = 65401
port_range_end = 65500
```

These are the defaults. All three ports must be non-zero; `gossip_port` must
not overlap the range; the range width (`port_range_end - port_range_start`)
must be at least 26; and the range end plus six must fit in `u16`. A source
needs its configured gossip port and the selected UDP range reachable from
Solana peers. A sink does not bind these Solana sockets.

## Overlay

The optional `[overlay]` section controls authenticated QUIC dissemination and
stream repair. Its defaults are safe but inert because `enabled = false`.

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Starts the overlay runner when true. |
| `mode` | `"sink"` | `"source"` mirrors verified local Turbine shreds; `"sink"` receives verified overlay shreds without Solana sockets. |
| `bind_addr` | `"0.0.0.0:65410"` | IPv4 UDP socket for overlay QUIC and raw punch probes. |
| `bind_addr_v6` | unset | Optional IPv6 UDP overlay socket. |
| `advertised_addr` | unset | Operator-vouched public IPv4 address. Use only when it is stable and reachable. |
| `advertised_addr_v6` | unset | Operator-vouched public IPv6 address. It is advertised before IPv4. |
| `gateway_addr` | unset | PCP/NAT-PMP/UPnP gateway address. If unset, the driver attempts default-gateway discovery. |
| `portmap_local_ip` | unset | LAN address supplied to the gateway; normally inferred from `bind_addr`. |
| `static_peers` | `[]` | Direct bootstrap endpoints dialed outbound. They must accept overlay UDP. |
| `fanout` | `8` | Target overlay Turbine fanout. |
| `repair_addr` | unset | Optional Solana-format repair endpoint to advertise. Leave unset for overlay-only sink repair. |
| `shred_version` | unset | Required `u16` in sink mode; source learns it from gossip. |
| `peer_ttl_ms` | `30000` | Lifetime for received peer adverts, in milliseconds. |

With no operator-advertised address, Lightbringer uses observations,
fresh-source dial-back confirmation, and—when available—PCP, NAT-PMP, or UPnP
port mapping before advertising an address as directly dialable. It does not
blindly advertise its bind address.

### IPv6

Set `bind_addr_v6` only when the host can bind and route IPv6. A confirmed IPv6
candidate is preferred over IPv4. `advertised_addr_v6` is an operator assertion
and skips confirmation, so it must be a real public address reachable on the
configured port.

### NAT traversal

P5 assisted punching is automatic and lazy: it occurs only for an explicitly
targeted coordinated peer, never as proactive gossip-view meshing. Failure
falls back to connected-only behavior; it is not a repair or dissemination
correctness dependency.

```toml
[overlay.nat]
birthday_punch = false
```

Keep `birthday_punch` disabled unless random-symmetric NAT reachability is
worth the cost. When both peers opt in, a bounded attempt may bind 256 helper
sockets and spray 1,024 high ports for up to 20 seconds, using roughly 100 KiB
of traffic and a meaningful part of a CGN subscriber's port budget. Ordinary
EIM, port-dependent, and sequential-assisted paths do not require this flag.

## Metrics and confirmation

Omit `[influxdb]` to use mock/log-only metrics. To enable InfluxDB, set exactly
one of `token` and `token_file`; a token file may be a raw token or JSON with a
`token` field.

```toml
[influxdb]
host = "http://127.0.0.1:18181"
database = "lightbringer"
token_file = "/run/secrets/influxdb-admin-token"
```

`[block_confirmation]` changes gRPC from the normal slot stream to a confirmed
stream:

```toml
[block_confirmation]
mode = "rpc"
rpc_http = "http://127.0.0.1:8899"
rpc_websocket = "ws://127.0.0.1:8900"
```

In `rpc` mode, both URLs are needed for a working confirmed stream. `mode =
"alpenglow"` uses `rpc_http` and optionally `snapshot_source`; when omitted,
each defaults to the configured Alpenglow RPC endpoint. Do not use an
Alpenglow endpoint for mainnet leader-schedule validation.

## Logging and deployment checks

```toml
[log]
quiet = false
```

Set `quiet = true` to emit only warnings and errors. Before exposing a source,
allow the configured UDP gossip range and `overlay.bind_addr` through the host
firewall. Before exposing gRPC beyond loopback, add appropriate network access
control or a trusted proxy; it is not authenticated by this configuration.

For Docker Compose, the repository mounts `Lightbringer.toml` read-only and
uses host networking for the Lightbringer profile. The template's InfluxDB
section targets the Compose observability stack.

For protocol and NAT-traversal detail, see
[the overlay architecture notes](docs/agents/overlay-network.md).
