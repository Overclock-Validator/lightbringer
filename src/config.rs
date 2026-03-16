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

#[derive(Serialize, Deserialize)]
struct ConfigRaw {
    gossip_entrypoint: Option<String>,
    storage: String,
    rpc_addr: String,
    grpc_addr: String,
    influxdb: Option<InfluxDbConfig>,
    block_confirmation: Option<BlockConfirmationConfig>,
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
        })
    }
}

impl Config {
    pub fn parse() -> Self {
        let config: ConfigRaw = Figment::new()
            .merge(Serialized::defaults(ConfigRaw::default()))
            .merge(Toml::file("Lightbringer.toml"))
            .extract()
            .expect("invalid config file");
        config.try_into().expect("invalid config values")
    }
}
