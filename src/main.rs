// TODO: something for monitoring

mod thread_manager;
mod gossip_manager;
mod turbine_manager;
mod repair;
mod store;
mod types;

use std::{net::SocketAddr, path::PathBuf, sync::{atomic::{AtomicBool, Ordering}, Arc}, time::Duration};

use clap::Parser;
use fjall::{Config, PersistMode};
use gossip_manager::GossipManager;
use repair::peer_manager::start_repair_peer_manager;
use store::{shred::ShredStore, slot_meta::SlotMetadataStore};
use thread_manager::ThreadManager;
use turbine_manager::start_turbine_manager;

#[derive(Parser, Debug)]
struct Args {
    entrypoint: SocketAddr,
    #[arg(default_value = "./shred-store")]
    storage: PathBuf,
}

fn init_fjall(storage: PathBuf) -> fjall::Result<fjall::Keyspace> {
    let config = Config::new(storage)
        .cache_size(1 * 1024 * 1024 * 1024); // 1 GiB cache

    config.open()
}

fn main() {
    let args = Args::parse();

    simple_logger::init_with_level({
        #[cfg(feature = "debug")]
        {
            log::Level::Debug
        }
        #[cfg(not(feature = "debug"))]
        {
            log::Level::Info
        }
    }).unwrap();

    let lsm_ks = init_fjall(args.storage).unwrap();
    let persist_ks = lsm_ks.clone();
    let stop_db_persist = Arc::new(AtomicBool::new(false));

    let stop_db_persist_rx = stop_db_persist.clone();
    // TODO: should we have a dedicated threadpool purely for fjall?;
    let db_persist = std::thread::spawn(move || {
        while !stop_db_persist_rx.load(Ordering::SeqCst) {
            // sync every 15 minutes
            std::thread::sleep(Duration::from_secs(15 * 60));
            if let Err(e) = persist_ks.persist(PersistMode::SyncAll) {
                log::error!("failed to persist fjall keyspace: {e}");
            }
        }
    });


    let gossip = GossipManager::new(args.entrypoint).unwrap();

    let mut threadpool = ThreadManager::<4>::new();

    let cluster_info = gossip.get_cluster_info();
    threadpool.spawn(move |exit| start_repair_peer_manager(exit, cluster_info));

    let my_contact_info = gossip.lookup_my_info();
    let my_tvu_addr =  my_contact_info.tvu(solana_gossip::contact_info::Protocol::UDP).unwrap();
    log::info!("me: {my_tvu_addr:?}");

    let (slot_store_tx, slot_store_rx) = kanal::unbounded_async();
    let (slot_meta_tx, slot_meta_rx) = kanal::unbounded_async();

    threadpool.spawn(move |exit| async move {
        let res = start_turbine_manager(exit, my_tvu_addr, slot_store_tx, slot_meta_tx).await;
        if let Err(e) = res {
            log::error!("failed to start turbine manager: {e}");
        }
    });

    let shred_store = ShredStore::new(&lsm_ks).unwrap();
    threadpool.spawn(move |exit| shred_store.packet_listener_loop(exit, slot_store_rx));

    let slot_meta_store = SlotMetadataStore::default();
    threadpool.spawn(move |exit| slot_meta_store.packet_listener_loop(exit, slot_meta_rx));

    threadpool.join_with_cancel_handler(move || {
        stop_db_persist.store(true, Ordering::SeqCst);
        if let Err(e) = db_persist.join() {
            log::error!("failed to join fjall persist thread: {e:?}");
        };

        if let Err(e) = gossip.stop() {
            log::warn!("failed to stop gossip service {e}");
        }
    });
}
