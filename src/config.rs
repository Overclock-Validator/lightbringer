use std::{net::SocketAddr, path::PathBuf};

use anyhow::anyhow;
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use http::Uri;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

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

        Ok(Self {
            gossip_entrypoint,
            storage,
            rpc_addr,
            grpc_addr,
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
}
