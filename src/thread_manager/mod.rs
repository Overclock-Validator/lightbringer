use arrayvec::ArrayVec;
use glommio::{ExecutorJoinHandle, LocalExecutorBuilder, Task, spawn_local};

use crate::rpc::{DebugRpcInit, debug_rpc_listener};

pub type CancelRx = Task<()>;

pub struct ThreadManager<const CAP: usize> {
    cancel_tx: kanal::AsyncSender<()>,
    cancel_rx: kanal::AsyncReceiver<()>,
    threads: ArrayVec<ExecutorJoinHandle<()>, CAP>,
}

impl<const CAP: usize> ThreadManager<CAP> {
    pub fn new() -> Self {
        let (cancel_tx, cancel_rx) = kanal::bounded_async(1);
        Self {
            cancel_tx,
            cancel_rx,
            threads: ArrayVec::new(),
        }
    }

    /// Spawn a thread with a local executor
    /// the first argument is the
    pub fn spawn<F: Future<Output = ()> + 'static>(
        &mut self,
        inner: impl FnOnce(CancelRx) -> F + Send + 'static,
    ) {
        if self.threads.len() == CAP {
            panic!("thread pool is full");
        }

        let cancel_rx = self.cancel_rx.clone();
        let handle = LocalExecutorBuilder::default()
            .spawn(move || async move {
                let cancel_rx = spawn_local(async move { cancel_rx.recv().await.unwrap() });
                inner(cancel_rx).await;
            })
            .unwrap();
        self.threads.push(handle);
    }

    pub fn spawn_rpc_with_cancel_handler(
        self,
        init_args: DebugRpcInit,
        on_cancel: impl FnOnce() + 'static,
    ) {
        let cancel_tx = self.cancel_tx.clone();
        let handle = LocalExecutorBuilder::default()
            .spawn(move || async move {
                debug_rpc_listener(init_args).await;
                log::info!("Received CTRL+C, stopping");
                let cnt = cancel_tx.receiver_count();
                for _ in 0..cnt {
                    if let Err(e) = cancel_tx.send(()).await {
                        log::warn!("failed to send cancel signal: {e}");
                    }
                }
            })
            .unwrap();

        if let Err(e) = handle.join() {
            log::error!("rpc thread panicked: {e:?}");
        };

        on_cancel();

        for thread in self.threads {
            if let Err(e) = thread.join() {
                log::error!("thread panicked: {e:?}");
            }
        }

        std::mem::drop(self.cancel_tx);
    }
}
