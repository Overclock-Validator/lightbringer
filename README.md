# Lightbringer

**Lightbringer** is a lightweight Rust-based Solana networking sidecar for ingesting, repairing, caching, and serving recent shred data from Turbine and Repair.

It is designed primarily to run alongside **Mithril**, usually on the same server, where it gives Mithril a local stream of fresh block data without requiring a full RPC validator or high-volume block subscriptions from centralized providers.

Lightbringer is now part of Mithril’s normal block ingestion path: Mithril can manage Lightbringer through its own configuration, generate the Lightbringer config, launch it as a sidecar, and consume its gRPC block stream directly.

Lightbringer can also run as a standalone edge service, but the main intended use case is pairing it with Mithril so the two together can operate independently from RPC providers for streaming in recent blocks.

Because Lightbringer does not maintain an AccountsDB, vote engine, or full RPC layer, it can stay relatively small while still participating in Solana’s live data path.

## Configuration

See [CONFIG.md](CONFIG.md) for source and sink templates, every supported
setting, overlay/NAT-traversal behavior, firewall requirements, and Compose
notes. [Lightbringer.example.toml](Lightbringer.example.toml) is a safe
starting point with the overlay disabled by default.

Lightbringer currently:

* Receives shreds via Turbine.
* Filters invalid or duplicate traffic early.
* Detects slot gaps and issues targeted repair requests to Solana gossip peers.
* Validates repair responses before block reassembly.
* Reuses [Agave](https://github.com/anza-xyz/agave)/Solana crates for protocol compatibility, including gossip, shred types, deshredding, decoding, and repair protocol serialization.
* Implements its own lightweight pipeline around those primitives, including Turbine ingestion, packet filtering, slot-gap tracking, repair orchestration, shred caching, block streaming, and Mithril integration.
* Serves deshredded blocks over gRPC.
* Serves raw shreds over a local HTTP/debug API.
* Optionally gates gRPC block streams on confirmed-slot notifications from RPC WebSocket, which is useful for Mithril’s current execution path.

Lightbringer performs lightweight validation, including shred signature verification, leader-schedule sanity checks, duplicate suppression, and repair-response validation. It is not a full validator and does not replace full block execution or application-level fork-choice logic. Consumers such as Mithril remain responsible for deeper validation and execution behavior.

---

## Architecture

Lightbringer is written in Rust and built as a staged pipeline using **Glommio**’s thread-per-core async model, with **kanal** channels connecting internal stages.

At a high level:

1. Shreds are received from Solana Turbine.
2. Incoming traffic is filtered and deduplicated.
3. Slot gaps are detected.
4. Missing shreds are requested through targeted repair.
5. Repair responses are validated.
6. Blocks are reassembled.
7. Downstream consumers can read deshredded blocks, raw shreds, or confirmed-block streams.

---

## Relationship To Agave

Lightbringer is not a fork of [Agave](https://github.com/anza-xyz/agave) and does not run Agave’s validator pipeline.

It reuses selected [Agave](https://github.com/anza-xyz/agave)/Solana crates where doing so helps maintain compatibility with the live network, especially for gossip, shred types, deshredding, decoding, and repair protocol serialization.

Lightbringer implements its own lightweight pipeline around those primitives, including Turbine ingestion, packet filtering, slot-gap tracking, repair orchestration, shred caching, block streaming, and Mithril integration.

---

## Mithril Integration

Lightbringer was built to reduce Mithril’s dependence on RPC providers for recent blocks coming through Turbine and Repair.

When paired with Mithril, Lightbringer provides the live block data path locally, while Mithril handles execution and higher-level logic. In current Mithril deployments, Lightbringer is integrated into Mithril’s configuration and can be treated as a managed sidecar dependency rather than a separate service that users must wire up manually.

Together, Lightbringer and Mithril can run as a single server-side system that is much less dependent on external RPC infrastructure for live or recent block execution.

Typical deployment options include:

* Running Lightbringer as a Mithril-managed sidecar.
* Running Lightbringer alongside Mithril on the same host.
* Running Lightbringer as a sidecar process in the same container, VM, or pod as Mithril.
* Running Lightbringer as a standalone edge service for other downstream consumers.

---

## Running via Docker

The repo ships a top-level `Dockerfile` for Lightbringer itself and a `docker-compose.yml` that wires it up alongside its observability stack (InfluxDB 3 + Grafana). Compose splits this into three pieces:

* **Observability stack** (`influxdb3`, `influxdb3-init`, `grafana`) — started by default.
* **Lightbringer** — gated behind the `lightbringer` Compose profile, since it needs `Lightbringer.toml` configured first and runs with `network_mode: host` to reach Turbine/gossip/repair UDP ports.
* **Cloudflare Tunnel** for remote Grafana access — gated behind the `grafana-tunnel` profile.

Prerequisite: Docker Engine with the Compose v2 plugin (`docker compose version`).

### 1. Configure secrets and config

`secrets/.gitignore` keeps everything out of git except `*.example`/`*.example.*` files, so copy each one and fill in real values:

```bash
cp secrets/influxdb-admin-token.example.json secrets/influxdb-admin-token.json
cp secrets/grafana-admin-password.example secrets/grafana-admin-password
```

Generate an InfluxDB 3 admin token (it must start with `apiv3_`) into the token file:

```bash
printf '{"token": "apiv3_%s", "name": "admin", "description": "Admin token for local Lightbringer observability"}\n' \
  "$(openssl rand -hex 32)" > secrets/influxdb-admin-token.json
```

Put a long random password in `secrets/grafana-admin-password` — this becomes the Grafana `admin` login password:

```bash
openssl rand -base64 24 > secrets/grafana-admin-password
```

Both files must stay readable by the (non-root) containers — `chmod 644` each file and keep the `secrets/` directory itself private with `chmod 700`. The `secrets-preflight` service checks this on every `docker compose up` and fails fast if it's wrong.

If you're also running Lightbringer via Compose (step 3), copy the app config too:

```bash
cp Lightbringer.example.toml Lightbringer.toml
```

and set at least `gossip_entrypoint` to a real Solana gossip entrypoint address (see [CONFIG.md](CONFIG.md)). The example's `[influxdb]` block is already pointed at the compose stack.

If you plan to expose Grafana externally, also provide a Cloudflare Tunnel token:

```bash
cp secrets/cloudflare-tunnel-token.example secrets/cloudflare-tunnel-token
```

### 2. Start the observability stack

```bash
docker compose up -d
```

This brings up `influxdb3` (bound to `127.0.0.1:18181`), creates the `lightbringer` database and its tables via `influxdb3-init`, and starts `grafana` (bound to `127.0.0.1:3300`).

### 3. Start Lightbringer

```bash
docker compose --profile lightbringer up -d
```

This builds the image from the top-level `Dockerfile`, mounts `Lightbringer.toml` read-only into the container, and persists shred storage in the `lightbringer-data` volume.

### 4. (Optional) Expose Grafana via Cloudflare Tunnel

```bash
docker compose --profile grafana-tunnel up -d
```

Tear things down with `docker compose down` (add `--profile lightbringer --profile grafana-tunnel` to also stop those services, or `-v` to drop volumes too).

### Where the Grafana monitor lives

Grafana runs as the `grafana` service, published on the Docker host at:

```
http://127.0.0.1:3300
```

Log in as `admin` with the password from `secrets/grafana-admin-password`. It's pre-provisioned (via `docker/grafana/provisioning`) with an InfluxDB datasource and the dashboards under `docker/grafana/dashboards/` — aggregate stats, memory, repair timing, and slot completion timing. With the `grafana-tunnel` profile enabled, Grafana is also reachable at whatever hostname your Cloudflare Tunnel token routes to.

---

## Current Status

### Milestone 1: Core Turbine / Repair Pipeline

Implemented or in progress:

* Ingest incoming shreds into a rolling cache.
* Detect slot gaps and issue repair requests.
* Perform lightweight validation, including sigverify, leader-schedule checks, and duplicate filtering.
* Validate repair responses.
* Reassemble blocks.
* Serve deshredded blocks over gRPC.
* Serve raw shreds over a local HTTP/debug API.
* Support confirmed-block streaming for Mithril.
* Continue performance optimizations.

### Milestone 2: Active Repair Participation

Near-term work:

* Allow Lightbringer to serve repair requests itself.
* Let Lightbringer/Mithril systems return data to the network instead of only consuming shred traffic.
* Make the shred retention cache window configurable.
* Improve network robustness by increasing the number of systems that can help backstop recent shred availability.

### Milestone 3: Mithril and Alpenglow Support

Planned work:

* Adapt Lightbringer’s networking and block-streaming interfaces for Alpenglow’s consensus and shred distribution models.
* Provide lower-latency streams that Mithril can use for closer-to-tip execution.
* Explore pre-confirmation block-streaming support for downstream systems such as Mithril.

### Milestone 4: Mesh and Ops Tooling

Future work:

* Tunable retention policies and hard resource caps.
* Prometheus metrics.
* Tracing hooks.
* Additional operational tooling.




