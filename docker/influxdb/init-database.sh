#!/usr/bin/env sh
set -eu

error() {
  printf '%s\n' "$*" >&2
  exit 1
}

validate_retention_period() {
  value="$1"
  case "$value" in
    ''|none) return 0 ;;
  esac

  rest="$value"
  while [ -n "$rest" ]; do
    number="$(printf '%s' "$rest" | sed -n 's/^\([0-9][0-9]*\).*/\1/p')"
    [ -n "$number" ] || error "INFLUXDB_RETENTION_PERIOD must be empty, none, or a duration using h, d, w, mo, or y"
    rest="${rest#"$number"}"
    case "$rest" in
      mo*) rest="${rest#mo}" ;;
      h*|d*|w*|y*) rest="${rest#?}" ;;
      *) error "INFLUXDB_RETENTION_PERIOD must be empty, none, or a duration using h, d, w, mo, or y" ;;
    esac
  done
}

token_file="${INFLUXDB_ADMIN_TOKEN_FILE:-/run/secrets/influxdb-admin-token}"
[ -r "$token_file" ] || error "InfluxDB token file is missing or unreadable: $token_file"

token="$(sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$token_file" | head -n 1)"
[ -n "$token" ] || error "InfluxDB token file does not contain a token field"
case "$token" in
  apiv3_*) ;;
  *) error "InfluxDB token must start with apiv3_" ;;
esac
export INFLUXDB3_AUTH_TOKEN="$token"

database="${INFLUXDB_DATABASE:-lightbringer}"
case "$database" in
  [A-Za-z0-9]*) ;;
  *)
    error "INFLUXDB_DATABASE must start with a letter or number and contain only letters, numbers, underscore, dash, or slash"
    ;;
esac
case "$database" in
  *[!A-Za-z0-9_/-]*)
    error "INFLUXDB_DATABASE must start with a letter or number and contain only letters, numbers, underscore, dash, or slash"
    ;;
esac
[ "${#database}" -le 64 ] || error "INFLUXDB_DATABASE must be 64 characters or fewer"

influxdb_url="${INFLUXDB_URL:-http://influxdb3:8181}"
retention_period="${INFLUXDB_RETENTION_PERIOD:-}"
validate_retention_period "$retention_period"

output_file="$(mktemp)"
trap 'rm -f "$output_file"' EXIT

run_create() {
  ready_message="$1"
  exists_message="$2"
  failure_message="$3"
  shift 3

  : >"$output_file"
  set +e
  "$@" >"$output_file" 2>&1
  status="$?"
  set -e

  if [ "$status" -eq 0 ]; then
    printf '%s\n' "$ready_message"
  elif grep -Eiq 'already.*exists|exists.*already|resource that already exists|409 Conflict' "$output_file"; then
    printf '%s\n' "$exists_message"
  else
    printf '%s\n' "$failure_message" >&2
    cat "$output_file" >&2
    exit "$status"
  fi
}

if [ -n "$retention_period" ]; then
  run_create \
    "InfluxDB database is ready: $database" \
    "InfluxDB database already exists: $database" \
    "Failed to create InfluxDB database $database" \
    influxdb3 create database \
      --host "$influxdb_url" \
      --retention-period "$retention_period" \
      "$database"
else
  run_create \
    "InfluxDB database is ready: $database" \
    "InfluxDB database already exists: $database" \
    "Failed to create InfluxDB database $database" \
    influxdb3 create database \
      --host "$influxdb_url" \
      "$database"
fi

run_create \
  'InfluxDB table is ready: slot' \
  'InfluxDB table already exists: slot' \
  'Failed to create InfluxDB table slot' \
  influxdb3 create table \
    --host "$influxdb_url" \
    --database "$database" \
    --tags kind \
    --fields slot:int64 \
    slot

run_create \
  'InfluxDB table is ready: memory' \
  'InfluxDB table already exists: memory' \
  'Failed to create InfluxDB table memory' \
  influxdb3 create table \
    --host "$influxdb_url" \
    --database "$database" \
    --tags kind \
    --fields rss_bytes:int64,virtual_bytes:int64 \
    memory

run_create \
  'InfluxDB table is ready: serve_repair' \
  'InfluxDB table already exists: serve_repair' \
  'Failed to create InfluxDB table serve_repair' \
  influxdb3 create table \
    --host "$influxdb_url" \
    --database "$database" \
    --tags kind \
    --fields requests_served:int64,requests_dropped:int64,requests_rate_limited:int64 \
    serve_repair
