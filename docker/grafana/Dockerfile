ARG GRAFANA_VERSION=13.0.1-security-01

FROM grafana/grafana:${GRAFANA_VERSION}

USER root

RUN if command -v apk >/dev/null 2>&1; then \
      apk add --no-cache curl jq; \
    else \
      apt-get update \
      && apt-get install -y --no-install-recommends ca-certificates curl jq \
      && rm -rf /var/lib/apt/lists/*; \
    fi

COPY docker/grafana/entrypoint.sh /usr/local/bin/lightbringer-grafana-entrypoint
RUN chmod +x /usr/local/bin/lightbringer-grafana-entrypoint

USER grafana

ENTRYPOINT ["lightbringer-grafana-entrypoint"]
