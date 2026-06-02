mod block_conf;
#[cfg(test)]
mod coding;
mod config;
mod gossip_manager;
mod grpc_slot_stream;
mod leader_schedule;
mod metrics;
mod packet_filter;
mod repair;
mod repair_delivery;
mod rpc;
mod solana_rpc;
mod store;
mod thread_manager;
mod turbine_manager;
mod types;
mod util;

use std::{
    io::{ErrorKind, Write},
    path::PathBuf,
    sync::{Arc, atomic::AtomicU64},
};

use fjall::Database;
use glommio::enclose;
use gossip_manager::GossipManager;
use repair::request::RepairManager;
use simple_logger::SimpleLogger;
use solana_sdk::signature::{Keypair, Signer};
use store::{shred::ShredStore, slot_meta::SlotMetadataStore};
use thread_manager::ThreadManager;
use turbine_manager::start_turbine_manager;

use crate::{
    block_conf::BlockConfStream,
    config::{Config, InfluxDbConfig, LogConfig},
    grpc_slot_stream::shred_source::{
        ConfirmedSlotShreds, SlotMetaShreds, confirmed_slot_shreds_glommio_runner,
    },
    metrics::{MetricsSender, start_metrics_thread},
    packet_filter::packet_filter_loop,
    repair::socket::start_repair_socket_runner,
    repair_delivery::start_serve_repair,
    rpc::DebugRpcInit,
    solana_rpc::SolanaRpcClient,
    util::std_to_glommio_socket,
};

fn init_fjall(
    storage: PathBuf,
    shred_cutoff_slot: Arc<AtomicU64>,
) -> fjall::Result<fjall::Database> {
    Database::builder(&storage)
        .cache_size(1024 * 1024 * 1024) // 1 GiB cache
        .with_compaction_filter_factories(store::shred::compaction_filter_factories(
            shred_cutoff_slot,
        ))
        .open()
}

/// Install `simple_logger`. Level is `Warn` when `log_cfg.quiet` is true,
/// otherwise picked by the `debug` Cargo feature (Debug if enabled, Info
/// otherwise).
fn init_logger(log_cfg: Option<&LogConfig>) -> Result<(), log::SetLoggerError> {
    let quiet = log_cfg.map(|c| c.quiet).unwrap_or(false);
    let level = if quiet {
        log::LevelFilter::Warn
    } else {
        #[cfg(feature = "debug")]
        {
            log::LevelFilter::Debug
        }
        #[cfg(not(feature = "debug"))]
        {
            log::LevelFilter::Info
        }
    };
    SimpleLogger::new()
        .with_level(level)
        .with_module_level("solana_metrics", log::LevelFilter::Warn)
        .with_module_level("solana_gossip::cluster_info", log::LevelFilter::Warn)
        .init()
}

fn init_influxdb_client(config: InfluxDbConfig) -> influxdb::Client {
    influxdb::Client::new(config.host, config.database).with_token(config.token)
}

const KEYPAIR_PATH: &str = "identity.json";

fn parse_keypair(bytes: &[u8]) -> anyhow::Result<Keypair> {
    let raw: Vec<u8> = serde_json::from_slice(bytes)?;
    Keypair::try_from(raw.as_slice()).map_err(|e| anyhow::anyhow!("invalid keypair: {e}"))
}

fn create_keypair_file() -> anyhow::Result<Keypair> {
    let kp = Keypair::new();
    let bytes = serde_json::to_vec(&kp.to_bytes().to_vec())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(KEYPAIR_PATH)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    log::info!("generated new keypair at {KEYPAIR_PATH}: {}", kp.pubkey());
    Ok(kp)
}

fn load_or_create_keypair() -> anyhow::Result<Keypair> {
    match std::fs::read(KEYPAIR_PATH) {
        Ok(bytes) => {
            let kp = parse_keypair(&bytes)?;
            log::info!("loaded keypair from {KEYPAIR_PATH}: {}", kp.pubkey());
            Ok(kp)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => create_keypair_file(),
        Err(e) => Err(e.into()),
    }
}

fn main() {
    let conf = Config::parse();

    init_logger(conf.log.as_ref()).unwrap();

    let shred_cutoff_slot = Arc::new(AtomicU64::new(0));
    let lsm_ks = init_fjall(conf.storage, shred_cutoff_slot.clone()).unwrap();

    let keypair = Arc::new(load_or_create_keypair().expect("failed to load or create identity"));

    let (gossip, sockets) =
        GossipManager::new(conf.gossip_entrypoint, keypair.clone(), conf.gossip).unwrap();
    let version = gossip.version;

    let mut threadpool = ThreadManager::<8>::new();

    let (metrics, metrics_rx) = MetricsSender::new();
    let metrics_client = conf.influxdb.map(init_influxdb_client);
    let (metrics_exit_tx, metrics_exit_rx) = oneshot::channel();
    std::thread::spawn(enclose!((metrics) move || {
        start_metrics_thread(metrics_client, metrics_rx, metrics, metrics_exit_rx);
    }));

    let my_contact_info = gossip.lookup_my_info();

    let cluster_info = gossip.get_cluster_info();

    let my_tvu_addr = my_contact_info
        .tvu(solana_gossip::contact_info::Protocol::UDP)
        .unwrap();
    log::info!("me: {my_tvu_addr:?}");

    let (filter_tx, filter_rx) = kanal::unbounded_async();
    let (slot_store_tx, slot_store_rx) = kanal::unbounded_async();
    let (slot_meta_tx, slot_meta_rx) = kanal::unbounded_async();

    // Turbine shred receiver
    threadpool.spawn(enclose!((filter_tx) move |exit| async move {
        let res = start_turbine_manager(exit, my_tvu_addr, filter_tx).await;
        if let Err(e) = res {
            log::error!("failed to start turbine manager: {e}");
        }
    }));

    // Shred filter
    threadpool.spawn(move |exit| packet_filter_loop(exit, filter_rx, slot_meta_tx.to_sync()));

    // Slot repair
    let (repair_tx, repair_rx) = kanal::bounded_async(10000);
    // Allow up to 20 slots to queue for repair.
    let (repair_socket_tx, repair_socket_rx) = kanal::bounded_async(20);
    let (repair_manager_tx, repair_manager_rx) = kanal::unbounded_async();

    threadpool.spawn(
        enclose!((cluster_info, keypair, repair_socket_tx, filter_tx, metrics) move |exit| async {
            let repair_manager =
                RepairManager::new(
                    repair_rx,
                    repair_socket_tx,
                    repair_manager_rx,
                    filter_tx,
                    cluster_info,
                    keypair,
                    metrics,
                );
            repair_manager.start_repair_manager_loop(exit).await
        }),
    );
    let serve_repair_keypair = keypair.clone();
    let serve_repair_socket = sockets.serve_repair_socket;
    threadpool.spawn(move |exit| async move {
        start_repair_socket_runner(
            exit,
            keypair,
            std_to_glommio_socket(sockets.repair_socket),
            repair_socket_rx,
            repair_manager_tx,
        )
        .await
    });

    // Shred storage
    let shred_store = ShredStore::new(lsm_ks, shred_cutoff_slot, cluster_info.clone()).unwrap();
    threadpool.spawn(
        enclose!((shred_store) move |exit| shred_store.batch_listener_loop(exit, slot_store_rx)),
    );

    // Serve repair
    let my_serve_repair_addr = my_contact_info
        .serve_repair(solana_gossip::contact_info::Protocol::UDP)
        .unwrap();
    log::info!("serve_repair: {my_serve_repair_addr:?}");
    threadpool.spawn(
        enclose!((shred_store, cluster_info, metrics) move |exit| async move {
            start_serve_repair(
                exit,
                serve_repair_keypair,
                std_to_glommio_socket(serve_repair_socket),
                shred_store,
                cluster_info,
                metrics,
            )
            .await
        }),
    );

    let slot_meta_store = SlotMetadataStore::new(version);
    let (grpc_slot_meta_tx, grpc_slot_meta_rx) = kanal::bounded_async(1000);
    threadpool.spawn(enclose!((metrics) move |exit| {
        slot_meta_store.packet_listener_loop(exit, slot_meta_rx, repair_tx, grpc_slot_meta_tx, slot_store_tx, metrics)
    }));

    let (grpc_cancel_tx, grpc_cancel_rx) = oneshot::channel();
    let grpc_shred_store = shred_store.clone();
    let grpc_thread = if let Some(block_conf_config) = conf.block_confirmation {
        let (grpc_tx, grpc_rx) = kanal::bounded_async(1000);
        threadpool.spawn(enclose!((shred_store) async move |exit| {
            let rpc = SolanaRpcClient::new(block_conf_config.rpc_http.to_string());
            let block_conf = match BlockConfStream::new(rpc, block_conf_config.rpc_websocket).await {
                Ok(stream) => stream,
                Err(e) => {
                    log::error!("failed to create block confirmation stream: {e}");
                    return;
                }
            };
            confirmed_slot_shreds_glommio_runner(block_conf, grpc_slot_meta_rx, shred_store, grpc_tx, exit).await;
        }));

        std::thread::spawn(move || {
            grpc_slot_stream::start_grpc_server(
                conf.grpc_addr,
                ConfirmedSlotShreds::new(grpc_rx),
                grpc_shred_store,
                grpc_cancel_rx,
            )
        })
    } else {
        std::thread::spawn(move || {
            grpc_slot_stream::start_grpc_server(
                conf.grpc_addr,
                SlotMetaShreds::new(grpc_slot_meta_rx),
                grpc_shred_store,
                grpc_cancel_rx,
            )
        })
    };

    threadpool.spawn_rpc_with_cancel_handler(
        DebugRpcInit {
            listen_addr: conf.rpc_addr,
            shred_store,
        },
        move || {
            if let Err(e) = gossip.stop() {
                log::warn!("failed to stop gossip service {e}");
            }
            _ = grpc_cancel_tx.send(());
            _ = metrics_exit_tx.send(());
            if let Err(e) = grpc_thread.join() {
                log::warn!("failed to stop grpc thread {e:?}");
            }
        },
    );
}
