#!/usr/bin/env sh
set -eu

token_file="${INFLUXDB_ADMIN_TOKEN_FILE:-/run/secrets/influxdb-admin-token}"
if [ ! -r "$token_file" ]; then
  printf 'InfluxDB token file is missing or unreadable: %s\n' "$token_file" >&2
  exit 1
fi

INFLUXDB_ADMIN_TOKEN="$(jq -r '.token // empty' "$token_file")"
if [ -z "$INFLUXDB_ADMIN_TOKEN" ]; then
  printf 'InfluxDB token file does not contain a token field\n' >&2
  exit 1
fi
case "$INFLUXDB_ADMIN_TOKEN" in
  apiv3_*) ;;
  *)
    printf 'InfluxDB token must start with apiv3_\n' >&2
    exit 1
    ;;
esac
export INFLUXDB_ADMIN_TOKEN

exec /run.sh "$@"
