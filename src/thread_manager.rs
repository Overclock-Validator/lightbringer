use arrayvec::ArrayVec;
use glommio::{ExecutorJoinHandle, LocalExecutorBuilder, Task, spawn_local};

pub type CancelRx = Task<()>;

pub struct ThreadManager<const CAP: usize> {
    cancel_tx: kanal::Sender<()>,
    cancel_rx: kanal::AsyncReceiver<()>,
    threads: ArrayVec<ExecutorJoinHandle<()>, CAP>,
}

impl<const CAP: usize> ThreadManager<CAP> {
    pub fn new() -> Self {
        let (cancel_tx, cancel_rx) = kanal::bounded_async(1);
        Self {
            cancel_tx: cancel_tx.to_sync(),
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

    /// wait for all threads to finish
    /// also sets up ctrl-c handler to stop all threads
    pub fn join_with_cancel_handler(self, on_cancel: impl FnOnce() + 'static) {
        let tx = self.cancel_tx;
        ctrlc::set_handler(move || {
            let cnt = tx.receiver_count();
            for _ in 0..cnt {
                if let Err(e) = tx.send(()) {
                    log::warn!("failed to send cancel signal: {e}");
                }
            }
        })
        .expect("failed to set ctrlc handler");

        self.cancel_rx.to_sync().recv().unwrap();
        log::info!("Received CTRL+C, stopping");

        on_cancel();

        for thread in self.threads {
            if let Err(e) = thread.join() {
                log::error!("thread panicked: {e:?}");
            }
        }
    }
}
