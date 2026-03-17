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
mod rpc;
mod solana_rpc;
mod store;
mod thread_manager;
mod turbine_manager;
mod types;
mod util;

use std::{path::PathBuf, sync::Arc};

use fjall::Database;
use glommio::enclose;
use gossip_manager::GossipManager;
use repair::request::RepairManager;
use simple_logger::SimpleLogger;
use solana_sdk::signature::Keypair;
use store::{shred::ShredStore, slot_meta::SlotMetadataStore};
use thread_manager::ThreadManager;
use turbine_manager::start_turbine_manager;

use crate::{
    block_conf::BlockConfStream,
    config::{Config, InfluxDbConfig},
    grpc_slot_stream::shred_source::{
        ConfirmedSlotShreds, SlotMetaShreds, confirmed_slot_shreds_glommio_runner,
    },
    metrics::{MetricsSender, start_metrics_thread, points::MemoryMeasurement},
    packet_filter::packet_filter_loop,
    repair::{
        outstanding_timers::OutstandingTimerStore,
        peer_manager::{RepairPeers, RepairRequestMapper},
        socket::start_repair_socket_runner,
    },
    rpc::DebugRpcInit,
    solana_rpc::SolanaRpcClient,
    util::std_to_glommio_socket,
};

fn init_fjall(storage: PathBuf) -> fjall::Result<fjall::Database> {
    let builder = Database::builder(&storage).cache_size(1024 * 1024 * 1024); // 1 GiB cache

    builder.open()
}

fn init_logger() -> Result<(), log::SetLoggerError> {
    SimpleLogger::new()
        .with_level({
            #[cfg(feature = "debug")]
            {
                log::LevelFilter::Debug
            }
            #[cfg(not(feature = "debug"))]
            {
                log::LevelFilter::Info
            }
        })
        .with_module_level("solana_metrics", log::LevelFilter::Warn)
        .with_module_level("solana_gossip::cluster_info", log::LevelFilter::Warn)
        .init()
}

fn init_influxdb_client(config: InfluxDbConfig) -> influxdb::Client {
    influxdb::Client::new(config.host, config.database).with_token(config.token)
}

fn main() {
    let conf = Config::parse();

    init_logger().unwrap();

    let lsm_ks = init_fjall(conf.storage).unwrap();

    let keypair = Arc::new(Keypair::new());

    let (gossip, sockets) = GossipManager::new(conf.gossip_entrypoint, keypair.clone()).unwrap();
    let version = gossip.version;

    let mut threadpool = ThreadManager::<8>::new();

    let (metrics, metrics_rx) = MetricsSender::new();
    let metrics_client = conf.influxdb.map(init_influxdb_client);
    let (metrics_exit_tx, metrics_exit_rx) = oneshot::channel();
    std::thread::spawn(move || {
        start_metrics_thread(metrics_client, metrics_rx, metrics_exit_rx);
    });

    let metrics_for_mem = metrics.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(10));
            if let Some(measurement) = MemoryMeasurement::sample() {
                metrics_for_mem.measure(measurement);
            }
        }
    });

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

    // Shred Filter
    threadpool.spawn(move |exit| packet_filter_loop(exit, filter_rx, slot_meta_tx.to_sync()));

    // Slot Repair
    let (repair_tx, repair_rx) = kanal::bounded_async(10000);
    // allow upto 20 slots to be queued for repairing at a time
    let (repair_socket_tx, repair_socket_rx) = kanal::bounded_async(20);
    let (repair_manager_tx, repair_manager_rx) = kanal::unbounded_async();

    let repair_timeout = OutstandingTimerStore::default();
    let repair_peers = RepairPeers::new(cluster_info);
    let repair_request_mapper = RepairRequestMapper::new(repair_peers, keypair.clone());

    threadpool.spawn(enclose!((repair_request_mapper, repair_socket_tx, repair_timeout, filter_tx, metrics) move |exit| async {
        let repair_manager =
            RepairManager::new(
                repair_rx,
                repair_socket_tx,
                repair_manager_rx,
                filter_tx,
                repair_timeout,
                repair_request_mapper,
                metrics,
            );
        repair_manager.start_repair_manager_loop(exit).await
    }));
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
    threadpool.spawn(move |exit| async move {
        repair_timeout
            .timeout_watcher_loop(exit, repair_socket_tx, repair_request_mapper)
            .await
    });

    // Shred Storage
    let shred_store = ShredStore::new(lsm_ks).unwrap();
    threadpool.spawn(
        enclose!((shred_store) move |exit| shred_store.slot_listener_loop(exit, slot_store_rx)),
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
