#!/usr/bin/env sh
set -eu

error() {
  printf '%s\n' "$*" >&2
  exit 1
}

toml_string() {
  printf '%s' "$1" | jq -Rs .
}

require_u16() {
  u16_name="$1"
  u16_value="$2"
  case "$u16_value" in
    ''|*[!0-9]*) error "$u16_name must be an integer between 0 and 65535" ;;
  esac
  [ "$u16_value" -le 65535 ] || error "$u16_name must be <= 65535"
}

require_nonzero_u16() {
  require_u16 "$1" "$2"
  [ "$2" -ne 0 ] || error "$1 must be non-zero"
}

resolve_gossip_entrypoint() {
  value="$1"
  case "$value" in
    \[*\]:*) printf '%s' "$value"; return ;;
    *:*) ;;
    *) error "LIGHTBRINGER_GOSSIP_ENTRYPOINT must be host:port or ip:port" ;;
  esac

  host="${value%:*}"
  port="${value##*:}"
  require_nonzero_u16 LIGHTBRINGER_GOSSIP_ENTRYPOINT_PORT "$port"

  case "$host" in
    ''|*[!0-9.]*)
      resolved="$(getent ahostsv4 "$host" || true)"
      resolved="${resolved%%[	 ]*}"
      [ -n "$resolved" ] || error "failed to resolve LIGHTBRINGER_GOSSIP_ENTRYPOINT host: $host"
      printf '%s:%s' "$resolved" "$port"
      ;;
    *)
      printf '%s' "$value"
      ;;
  esac
}

: "${LIGHTBRINGER_GOSSIP_ENTRYPOINT:?set LIGHTBRINGER_GOSSIP_ENTRYPOINT}"

token_file="${INFLUXDB_ADMIN_TOKEN_FILE:-/run/secrets/influxdb-admin-token}"
[ -r "$token_file" ] || error "InfluxDB token file is missing or unreadable: $token_file"

influxdb_token="$(jq -r '.token // empty' "$token_file")"
[ -n "$influxdb_token" ] || error "InfluxDB token file does not contain a token field"
case "$influxdb_token" in
  apiv3_*) ;;
  *) error "InfluxDB token must start with apiv3_" ;;
esac

storage="${LIGHTBRINGER_STORAGE:-/var/lib/lightbringer/shred-store}"
rpc_addr="${LIGHTBRINGER_RPC_ADDR:-127.0.0.1:13000}"
grpc_addr="${LIGHTBRINGER_GRPC_ADDR:-127.0.0.1:13001}"
influxdb_host="${LIGHTBRINGER_INFLUXDB_HOST:-http://127.0.0.1:18181}"
influxdb_database="${LIGHTBRINGER_INFLUXDB_DATABASE:-lightbringer}"
gossip_entrypoint="$(resolve_gossip_entrypoint "$LIGHTBRINGER_GOSSIP_ENTRYPOINT")"
gossip_port="${LIGHTBRINGER_GOSSIP_PORT:-65400}"
port_range_start="${LIGHTBRINGER_PORT_RANGE_START:-65401}"
port_range_end="${LIGHTBRINGER_PORT_RANGE_END:-65500}"
log_quiet="${LIGHTBRINGER_LOG_QUIET:-false}"
quic_port_offset=6

require_nonzero_u16 LIGHTBRINGER_GOSSIP_PORT "$gossip_port"
require_nonzero_u16 LIGHTBRINGER_PORT_RANGE_START "$port_range_start"
require_nonzero_u16 LIGHTBRINGER_PORT_RANGE_END "$port_range_end"
[ "$port_range_start" -le "$port_range_end" ] || error "LIGHTBRINGER_PORT_RANGE_START must be <= LIGHTBRINGER_PORT_RANGE_END"
if [ $((port_range_end - port_range_start)) -lt 25 ]; then
  error "LIGHTBRINGER_PORT_RANGE_END - LIGHTBRINGER_PORT_RANGE_START must be at least 25"
fi
if [ $((port_range_end + quic_port_offset)) -gt 65535 ]; then
  error "LIGHTBRINGER_PORT_RANGE_END + $quic_port_offset must be <= 65535"
fi
if [ "$gossip_port" -ge "$port_range_start" ] && [ "$gossip_port" -le "$port_range_end" ]; then
  error "LIGHTBRINGER_GOSSIP_PORT must not overlap LIGHTBRINGER_PORT_RANGE_START..LIGHTBRINGER_PORT_RANGE_END"
fi

case "$log_quiet" in
  true|false) ;;
  *) error "LIGHTBRINGER_LOG_QUIET must be true or false" ;;
esac

mkdir -p "$storage"

cat > Lightbringer.toml <<EOF
gossip_entrypoint = $(toml_string "$gossip_entrypoint")
storage = $(toml_string "$storage")
rpc_addr = $(toml_string "$rpc_addr")
grpc_addr = $(toml_string "$grpc_addr")

[gossip]
gossip_port = $gossip_port
port_range_start = $port_range_start
port_range_end = $port_range_end

[influxdb]
host = $(toml_string "$influxdb_host")
database = $(toml_string "$influxdb_database")
token = $(toml_string "$influxdb_token")

[log]
quiet = $log_quiet
EOF

exec lightbringer "$@"
