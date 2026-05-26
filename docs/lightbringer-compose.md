# Lightbringer Docker Compose

This stack runs InfluxDB 3 Core and Grafana with the four Lightbringer dashboards:

- Absolute Slot Completion Time
- Absolute Repair Time
- Lightbringer Aggregate Stats
- Lightbringer Memory

The dashboards use the metrics Lightbringer emits today:

- `slot` events tagged as `completion` or `repair_initiate`
- `memory` samples with RSS and virtual memory bytes

The aggregate and memory dashboards also include freshness and growth panels so a stopped Lightbringer process, stalled metrics writer, or sustained RSS increase is visible without opening InfluxDB directly.
Additional production signals such as repair request timeouts, repair peer quality, gossip peer count, packet filter/drop counts, shred store size, and gRPC request latency require new Rust instrumentation before Grafana can graph them truthfully.

The default `docker compose up` path starts only InfluxDB and Grafana. The Lightbringer process is behind the `lightbringer` profile because it uses host networking and Linux `io_uring` permissions.
Grafana and Lightbringer wait for the InfluxDB healthcheck before starting.
An init container creates the configured InfluxDB database and the `slot` and `memory` tables before Grafana or Lightbringer starts.

## Files

- `docker-compose.yml`: InfluxDB, Grafana, and optional Lightbringer service.
- `Dockerfile`: Linux runtime image for Lightbringer.
- `Lightbringer.example.toml`: template for the local `Lightbringer.toml` runtime config.
- `docker/influxdb/init-database.sh`: idempotent InfluxDB database and table creation.
- `docker/grafana/provisioning`: Grafana datasource and dashboard provider.
- `docker/grafana/dashboards`: provisioned classic dashboard JSON.
- `secrets/*.example`: placeholder secret examples only.

InfluxDB data is persisted in a named volume mounted at `/var/lib/influxdb3`.
The server still writes to `/var/lib/influxdb3/data`; mounting the parent preserves the image's `influxdb3` user ownership on first volume initialization.
Lightbringer reads the repository-root `Lightbringer.toml` file directly; Docker Compose mounts that file into the container as read-only config.

## Setup

Create local secrets. Do not commit these files.

```sh
mkdir -p secrets
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/secrets:/secrets" influxdb:3.9.2-core \
  influxdb3 create token --admin --name admin --offline --output-file /secrets/influxdb-admin-token.json
openssl rand -base64 32 > secrets/grafana-admin-password
chmod 700 secrets
chmod 444 secrets/influxdb-admin-token.json secrets/grafana-admin-password
```

Docker Compose file-backed secrets are mounted from host files. Docker documents that `uid`, `gid`, and `mode` are not implemented for file-sourced secrets, so the source files must be readable by the non-root users in the InfluxDB and Grafana containers. Keep the `secrets` directory private and let only the files be container-readable.

Create a local Lightbringer config. Do not commit this file.

```sh
cp Lightbringer.example.toml Lightbringer.toml
```

Set `gossip_entrypoint` in `Lightbringer.toml` before starting the Lightbringer profile.
The config accepts either `ip:port` or `host:port`; hostnames are resolved to IPv4 at startup.
Keep the Docker default InfluxDB section unless you intentionally change the compose stack:

```toml
[influxdb]
host = "http://127.0.0.1:18181"
database = "lightbringer"
token_file = "/run/secrets/influxdb-admin-token"
```

The `token_file` value points at the Docker secret mounted into the Lightbringer container.
For non-Docker local runs, replace it with a local token file path or use `token = "..."`.
Lightbringer reads config at startup; restart the container after changing `Lightbringer.toml`.

## Validate Configuration

After creating the local secret files, verify the compose model before starting services:

```sh
docker compose config
```

## Start Observability Only

```sh
docker compose up -d --build influxdb3 grafana
```

Grafana is bound to localhost by default:

```text
http://127.0.0.1:3300
```

InfluxDB is bound to localhost by default:

```text
http://127.0.0.1:18181
```

## Start Lightbringer

Lightbringer is Linux-only in practice because Glommio depends on `io_uring`.
Use a Linux host with kernel 5.8+ and a Docker runtime that permits the configured locked-memory ulimit.
The compose service uses:

- `network_mode: host`, needed for Solana gossip, turbine, and repair UDP behavior.
- `security_opt: seccomp=unconfined`, because Docker's default seccomp profile blocks `io_uring`.
- `ulimits.memlock: -1`, because `io_uring` registered buffers are charged against locked memory limits.

Start the full stack only on a host where the configured UDP ports are available:

```sh
docker compose --profile lightbringer up -d --build
```

Default Lightbringer host ports:

- Gossip UDP: `65400`
- Solana dynamic UDP range: `65401-65500`
- Debug RPC: `127.0.0.1:13000`
- gRPC: `127.0.0.1:13001`

Override these in `Lightbringer.toml` if the host already uses them.
Agave's dynamic port range validator requires `gossip.port_range_end - gossip.port_range_start` to be at least `25`.
The same Agave path also requires `gossip.port_range_end + 6 <= 65535` for QUIC companion ports.

## Shared Server Safety

On a shared server, first run only:

```sh
docker compose up -d --build influxdb3 grafana
```

Use an SSH tunnel instead of exposing Grafana publicly:

```sh
ssh -L 3300:127.0.0.1:3300 ubuntu@SERVER_IP
```

Do not run the `lightbringer` profile on a shared server until you have checked the configured UDP ports and confirmed no existing workload depends on them.
