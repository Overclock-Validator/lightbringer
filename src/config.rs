use std::{net::SocketAddr, path::PathBuf};

use anyhow::anyhow;
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use http::Uri;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use solana_net_utils::MINIMUM_VALIDATOR_PORT_RANGE_WIDTH;
use solana_quic_definitions::QUIC_PORT_OFFSET;

#[derive(Serialize, Deserialize)]
pub struct InfluxDbConfig {
    pub host: String,
    pub database: String,
    pub token: String,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct BlockConfirmationConfig {
    #[serde_as(as = "DisplayFromStr")]
    pub rpc_websocket: Uri,
    #[serde_as(as = "DisplayFromStr")]
    pub rpc_http: Uri,
}

fn default_gossip_port() -> u16 {
    65400
}

fn default_port_range_start() -> u16 {
    65401
}

fn default_port_range_end() -> u16 {
    65500
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipConfig {
    #[serde(default = "default_gossip_port")]
    pub gossip_port: u16,
    #[serde(default = "default_port_range_start")]
    pub port_range_start: u16,
    #[serde(default = "default_port_range_end")]
    pub port_range_end: u16,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            gossip_port: default_gossip_port(),
            port_range_start: default_port_range_start(),
            port_range_end: default_port_range_end(),
        }
    }
}

impl GossipConfig {
    pub fn port_range(self) -> (u16, u16) {
        (self.port_range_start, self.port_range_end)
    }
}

/// Logger configuration.
///
/// When `quiet` is true, only Warn/Error level logs are emitted. Runtime
/// `quiet = true` overrides the build-time `debug` Cargo feature.
#[derive(Serialize, Deserialize, Default)]
pub struct LogConfig {
    #[serde(default)]
    pub quiet: bool,
}

#[derive(Serialize, Deserialize)]
struct ConfigRaw {
    gossip_entrypoint: Option<String>,
    storage: String,
    rpc_addr: String,
    grpc_addr: String,
    #[serde(default)]
    gossip: GossipConfig,
    influxdb: Option<InfluxDbConfig>,
    block_confirmation: Option<BlockConfirmationConfig>,
    log: Option<LogConfig>,
}

impl Default for ConfigRaw {
    fn default() -> Self {
        Self {
            gossip_entrypoint: None,
            storage: "./shred-store".to_string(),
            rpc_addr: "127.0.0.1:3000".to_string(),
            grpc_addr: "127.0.0.1:3001".to_string(),
            gossip: GossipConfig::default(),
            influxdb: None,
            block_confirmation: None,
            log: None,
        }
    }
}

pub struct Config {
    pub gossip_entrypoint: SocketAddr,
    pub storage: PathBuf,
    pub rpc_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub gossip: GossipConfig,
    pub influxdb: Option<InfluxDbConfig>,
    pub block_confirmation: Option<BlockConfirmationConfig>,
    pub log: Option<LogConfig>,
}

impl TryFrom<ConfigRaw> for Config {
    type Error = anyhow::Error;

    fn try_from(value: ConfigRaw) -> Result<Self, Self::Error> {
        let gossip_entrypoint: SocketAddr = value
            .gossip_entrypoint
            .ok_or_else(|| anyhow!("`gossip_entrypoint` must be specified in config"))?
            .parse()
            .map_err(|e| anyhow!("invalid `gossip_entrypoint`: {e}"))?;

        let storage = PathBuf::from(value.storage);

        let rpc_addr: SocketAddr = value
            .rpc_addr
            .parse()
            .map_err(|e| anyhow!("invalid `rpc_addr`: {e}"))?;

        let grpc_addr: SocketAddr = value
            .grpc_addr
            .parse()
            .map_err(|e| anyhow!("invalid `grpc_addr`: {e}"))?;

        if value.gossip.gossip_port == 0 {
            return Err(anyhow!("`gossip.gossip_port` must be non-zero"));
        }
        if value.gossip.port_range_start == 0 || value.gossip.port_range_end == 0 {
            return Err(anyhow!("`gossip.port_range_*` values must be non-zero"));
        }
        if value.gossip.port_range_start > value.gossip.port_range_end {
            return Err(anyhow!(
                "`gossip.port_range_start` must be <= `gossip.port_range_end`"
            ));
        }
        if value
            .gossip
            .port_range_end
            .saturating_sub(value.gossip.port_range_start)
            < MINIMUM_VALIDATOR_PORT_RANGE_WIDTH
        {
            return Err(anyhow!(
                "`gossip.port_range_end - gossip.port_range_start` must be at least {MINIMUM_VALIDATOR_PORT_RANGE_WIDTH}"
            ));
        }
        if value
            .gossip
            .port_range_end
            .checked_add(QUIC_PORT_OFFSET)
            .is_none()
        {
            return Err(anyhow!(
                "`gossip.port_range_end + {QUIC_PORT_OFFSET}` must fit in u16"
            ));
        }
        if (value.gossip.port_range_start..=value.gossip.port_range_end)
            .contains(&value.gossip.gossip_port)
        {
            return Err(anyhow!(
                "`gossip.gossip_port` must not overlap `gossip.port_range_start..=gossip.port_range_end`"
            ));
        }

        Ok(Self {
            gossip_entrypoint,
            storage,
            rpc_addr,
            grpc_addr,
            gossip: value.gossip,
            influxdb: value.influxdb,
            block_confirmation: value.block_confirmation,
            log: value.log,
        })
    }
}

impl Config {
    pub fn parse() -> Self {
        let config: ConfigRaw = Figment::new()
            .merge(Serialized::defaults(ConfigRaw::default()))
            .merge(Toml::file("Lightbringer.toml"))
            .extract()
            .expect(
                "invalid Lightbringer.toml: check syntax and types (e.g. [log] quiet must be bool)",
            );
        config.try_into().expect("invalid config values")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::providers::{Format, Serialized, Toml};

    fn parse_toml(toml: &str) -> ConfigRaw {
        Figment::new()
            .merge(Serialized::defaults(ConfigRaw::default()))
            .merge(Toml::string(toml))
            .extract()
            .expect("toml extract failed")
    }

    const REQUIRED: &str = r#"
gossip_entrypoint = "127.0.0.1:8000"
storage = "/tmp/shred-store"
rpc_addr = "127.0.0.1:3000"
grpc_addr = "127.0.0.1:3001"
"#;

    #[test]
    fn log_section_absent_yields_none() {
        let raw = parse_toml(REQUIRED);
        assert!(raw.log.is_none());
    }

    #[test]
    fn log_quiet_true_parses() {
        let toml = format!("{REQUIRED}\n[log]\nquiet = true\n");
        let raw = parse_toml(&toml);
        let log = raw.log.expect("log section");
        assert!(log.quiet);
    }

    #[test]
    fn log_section_without_quiet_field_defaults_false() {
        let toml = format!("{REQUIRED}\n[log]\n");
        let raw = parse_toml(&toml);
        let log = raw.log.expect("log section");
        assert!(!log.quiet);
    }

    #[test]
    fn log_quiet_false_parses() {
        let toml = format!("{REQUIRED}\n[log]\nquiet = false\n");
        let raw = parse_toml(&toml);
        let log = raw.log.expect("log section");
        assert!(!log.quiet);
    }

    #[test]
    fn log_quiet_invalid_type_errors() {
        let toml = format!("{REQUIRED}\n[log]\nquiet = \"yes\"\n");
        let result: Result<ConfigRaw, _> = Figment::new()
            .merge(Serialized::defaults(ConfigRaw::default()))
            .merge(Toml::string(&toml))
            .extract();
        assert!(result.is_err(), "expected parse error for non-bool quiet");
    }

    #[test]
    fn config_passes_log_through() {
        let toml = format!("{REQUIRED}\n[log]\nquiet = true\n");
        let raw = parse_toml(&toml);
        let cfg: Config = raw.try_into().expect("validate");
        assert!(cfg.log.expect("log").quiet);
    }

    #[test]
    fn gossip_config_defaults_to_existing_ports() {
        let raw = parse_toml(REQUIRED);
        let cfg: Config = raw.try_into().expect("validate");
        assert_eq!(
            cfg.gossip,
            GossipConfig {
                gossip_port: 65400,
                port_range_start: 65401,
                port_range_end: 65500,
            }
        );
    }

    #[test]
    fn gossip_config_can_override_ports() {
        let toml = format!(
            "{REQUIRED}\n[gossip]\ngossip_port = 55000\nport_range_start = 55001\nport_range_end = 55100\n"
        );
        let raw = parse_toml(&toml);
        let cfg: Config = raw.try_into().expect("validate");
        assert_eq!(cfg.gossip.gossip_port, 55000);
        assert_eq!(cfg.gossip.port_range(), (55001, 55100));
    }

    #[test]
    fn gossip_config_rejects_invalid_port_range() {
        let toml = format!(
            "{REQUIRED}\n[gossip]\ngossip_port = 55000\nport_range_start = 55100\nport_range_end = 55001\n"
        );
        let raw = parse_toml(&toml);
        let result: Result<Config, _> = raw.try_into();
        assert!(result.is_err(), "expected invalid port range to fail");
    }

    #[test]
    fn gossip_config_rejects_too_narrow_port_range() {
        let toml = format!(
            "{REQUIRED}\n[gossip]\ngossip_port = 55000\nport_range_start = 55001\nport_range_end = 55010\n"
        );
        let raw = parse_toml(&toml);
        let result: Result<Config, _> = raw.try_into();
        assert!(result.is_err(), "expected narrow port range to fail");
    }

    #[test]
    fn gossip_config_rejects_port_range_that_overflows_quic_offset() {
        let toml = format!(
            "{REQUIRED}\n[gossip]\ngossip_port = 55000\nport_range_start = 65500\nport_range_end = 65535\n"
        );
        let raw = parse_toml(&toml);
        let result: Result<Config, _> = raw.try_into();
        assert!(
            result.is_err(),
            "expected high port range to fail QUIC offset validation"
        );
    }

    #[test]
    fn gossip_config_rejects_overlapping_gossip_port() {
        let toml = format!(
            "{REQUIRED}\n[gossip]\ngossip_port = 55010\nport_range_start = 55001\nport_range_end = 55100\n"
        );
        let raw = parse_toml(&toml);
        let result: Result<Config, _> = raw.try_into();
        assert!(result.is_err(), "expected overlapping gossip port to fail");
    }
}
