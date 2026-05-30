#!/usr/bin/env sh
set -eu

error() {
  printf '%s\n' "$*" >&2
  exit 1
}

require_other_read() {
  path="$1"
  label="$2"

  [ -f "$path" ] || error "$label is missing at $path"

  mode="$(stat -c '%a' "$path")" || error "failed to inspect $label permissions"
  case "$mode" in
    *[4567]) ;;
    *)
      error "$label must be readable by non-root containers. Use chmod 644 for the file and keep its directory private with chmod 700."
      ;;
  esac
}

influxdb_token_file="${INFLUXDB_ADMIN_TOKEN_FILE:-/run/secrets/influxdb-admin-token}"
grafana_password_file="${GRAFANA_ADMIN_PASSWORD_FILE:-/run/secrets/grafana-admin-password}"

require_other_read "$influxdb_token_file" "InfluxDB token file"
require_other_read "$grafana_password_file" "Grafana password file"

if [ -n "${LIGHTBRINGER_CONFIG_FILE:-}" ]; then
  require_other_read "$LIGHTBRINGER_CONFIG_FILE" "Lightbringer config file"
fi

token="$(sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$influxdb_token_file" | head -n 1)"
[ -n "$token" ] || error "InfluxDB token file does not contain a token field"
case "$token" in
  apiv3_*) ;;
  *) error "InfluxDB token must start with apiv3_" ;;
esac

[ -s "$grafana_password_file" ] || error "Grafana password file must not be empty"

printf '%s\n' "Compose inputs are readable by non-root containers"
