// TODO: something for monitoring

#[cfg(test)]
mod coding;
mod gossip_manager;
mod leader_schedule;
mod packet_filter;
mod repair;
mod rpc;
mod store;
mod thread_manager;
mod turbine_manager;
mod types;
mod util;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use clap::Parser;
use fjall::{Config, Keyspace, PersistMode};
use glommio::{enclose, spawn_local};
use gossip_manager::GossipManager;
use repair::request::RepairRequestManager;
use simple_logger::SimpleLogger;
use solana_sdk::signature::Keypair;
use store::{shred::ShredStore, slot_meta::SlotMetadataStore};
use thread_manager::ThreadManager;
use turbine_manager::start_turbine_manager;

use crate::{
    packet_filter::packet_filter_loop, repair::socket::start_repair_socket_runner,
    rpc::DebugRpcInit, thread_manager::CancelRx, util::std_to_glommio_socket,
};

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

    let keypair = Arc::new(Keypair::new());

    let (gossip, sockets) = GossipManager::new(args.entrypoint, keypair.clone()).unwrap();
    let version = gossip.version;

    let mut threadpool = ThreadManager::<7>::new();

    // fjall persist thread
    threadpool.spawn(move |exit| fjall_persistence_loop(exit, persist_ks));

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
    threadpool.spawn(move |exit| {
        packet_filter_loop(
            exit,
            filter_rx,
            slot_store_tx.to_sync(),
            slot_meta_tx.to_sync(),
        )
    });

    // Slot Repair
    let (repair_tx, repair_rx) = kanal::bounded_async(10000);
    // allow upto 20 slots to be queued for repairing at a time
    let (repair_socket_tx, repair_socket_rx) = kanal::bounded_async(20);
    threadpool.spawn(enclose!((keypair) move |exit| async {
        let repair_manager =
            RepairRequestManager::new(cluster_info, repair_rx, keypair, repair_socket_tx);
        repair_manager.start_repair_manager_loop(exit).await
    }));
    threadpool.spawn(move |exit| async move {
        start_repair_socket_runner(
            exit,
            keypair,
            std_to_glommio_socket(sockets.repair_socket),
            repair_socket_rx,
            filter_tx,
        )
        .await
    });

    // Shred Storage
    let shred_store = ShredStore::new(&lsm_ks, version).unwrap();
    threadpool.spawn(
        enclose!((shred_store) move |exit| shred_store.packet_listener_loop(exit, slot_store_rx)),
    );

    // Shred Metadata Storage (timeout etc)
    let slot_meta_store = SlotMetadataStore::new(version);
    threadpool
        .spawn(move |exit| slot_meta_store.packet_listener_loop(exit, slot_meta_rx, repair_tx));

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
