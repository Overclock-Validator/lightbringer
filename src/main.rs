// TODO: something for monitoring

mod gossip_manager;
mod repair;
mod rpc;
mod store;
mod thread_manager;
mod turbine_manager;
mod types;
#[cfg(test)]
mod coding;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::Parser;
use fjall::{Config, Keyspace, PersistMode};
use glommio::{enclose, spawn_local};
use gossip_manager::GossipManager;
use repair::peer_manager::start_repair_peer_manager;
use simple_logger::SimpleLogger;
use store::{shred::ShredStore, slot_meta::SlotMetadataStore};
use thread_manager::ThreadManager;
use turbine_manager::start_turbine_manager;

use crate::{rpc::DebugRpcInit, thread_manager::CancelRx};

#[derive(Parser, Debug)]
struct Args {
    entrypoint: SocketAddr,
    #[arg(default_value = "./shred-store")]
    storage: PathBuf,
    #[arg(default_value = "127.0.0.1:3000")]
    rpc_addr: SocketAddr,
}

fn init_fjall(storage: PathBuf) -> fjall::Result<fjall::Keyspace> {
    let config = Config::new(storage).cache_size(1024 * 1024 * 1024); // 1 GiB cache

    config.open()
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

async fn fjall_persistence_loop(exit: CancelRx, ks: Keyspace) {
    let ks2 = ks.clone();
    let executor = glommio::executor();
    let db_persist = spawn_local(async move {
        loop {
            // sync every 15 minutes
            glommio::timer::sleep(Duration::from_secs(15 * 60)).await;
            if let Err(e) = executor
                .spawn_blocking(enclose!((ks) move || ks.persist(PersistMode::SyncAll)))
                .await
            {
                log::error!("failed to persist fjall keyspace: {e}");
            }
        }
    });
    exit.await;
    db_persist.cancel().await;

    let executor = glommio::executor();
    if let Err(e) = executor
        .spawn_blocking(move || ks2.persist(PersistMode::SyncAll))
        .await
    {
        log::error!("failed to persist fjall keyspace: {e}");
    }
}

fn main() {
    let args = Args::parse();

    init_logger().unwrap();

    let lsm_ks = init_fjall(args.storage).unwrap();
    let persist_ks = lsm_ks.clone();

    let gossip = GossipManager::new(args.entrypoint).unwrap();
    let version = gossip.version;

    let mut threadpool = ThreadManager::<5>::new();

    // fjall persist thread
    threadpool.spawn(move |exit| fjall_persistence_loop(exit, persist_ks));

    let cluster_info = gossip.get_cluster_info();
    threadpool.spawn(move |exit| start_repair_peer_manager(exit, cluster_info));

    let my_contact_info = gossip.lookup_my_info();
    let my_tvu_addr = my_contact_info
        .tvu(solana_gossip::contact_info::Protocol::UDP)
        .unwrap();
    log::info!("me: {my_tvu_addr:?}");

    let (slot_store_tx, slot_store_rx) = kanal::unbounded_async();
    let (slot_meta_tx, slot_meta_rx) = kanal::unbounded_async();

    threadpool.spawn(move |exit| async move {
        let res = start_turbine_manager(exit, my_tvu_addr, slot_store_tx, slot_meta_tx).await;
        if let Err(e) = res {
            log::error!("failed to start turbine manager: {e}");
        }
    });

    let shred_store = ShredStore::new(&lsm_ks, version).unwrap();
    threadpool.spawn(
        enclose!((shred_store) move |exit| shred_store.packet_listener_loop(exit, slot_store_rx)),
    );

    let slot_meta_store = SlotMetadataStore::new(version);
    threadpool.spawn(move |exit| slot_meta_store.packet_listener_loop(exit, slot_meta_rx));

    threadpool.spawn_rpc_with_cancel_handler(
        DebugRpcInit {
            listen_addr: args.rpc_addr,
            shred_store,
        },
        move || {
            if let Err(e) = gossip.stop() {
                log::warn!("failed to stop gossip service {e}");
            }
        },
    );
}
