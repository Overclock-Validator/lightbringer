use std::time::Duration;

use influxdb::WriteQuery;
use kanal::{AsyncReceiver, AsyncSender};
use tokio::{runtime, task::spawn, time::sleep};

use crate::metrics::points::DataPoint;

pub mod points;

#[derive(Clone)]
pub struct MetricsSender(AsyncSender<WriteQuery>);

impl MetricsSender {
    pub fn new() -> (Self, AsyncReceiver<WriteQuery>) {
        let (tx, rx) = kanal::unbounded_async();
        (Self(tx), rx)
    }

    pub fn measure<M: DataPoint>(&self, measurement: M) {
        _ = self.0.try_send(measurement.into_query(M::measurement()));
    }
}

async fn metrics_loop(client: influxdb::Client, rx: AsyncReceiver<WriteQuery>) {
    let mut reqs = Vec::with_capacity(100);
    loop {
        sleep(Duration::from_secs(5)).await;
        if let Ok(cnt) = rx.drain_into(&mut reqs)
            && cnt == 0
        {
            if let Ok(v) = rx.recv().await {
                reqs.push(v);
            } else {
                break;
            }
        }
        if let Err(e) = client.query(&reqs).await {
            log::warn!("failed to write metrics to influxdb: {e}");
        }
        log::debug!("flushed {} metrics to influxdb", reqs.len());
        reqs.clear();
    }
}

async fn mock_metrics_loop(rx: AsyncReceiver<WriteQuery>) {
    log::info!("running in metrics in mock mode, metrics will be logged to trace");
    let mut reqs = Vec::with_capacity(100);
    loop {
        sleep(Duration::from_secs(5)).await;
        if let Ok(cnt) = rx.drain_into(&mut reqs)
            && cnt == 0
        {
            if let Ok(v) = rx.recv().await {
                reqs.push(v);
            } else {
                break;
            }
        }
        for req in reqs.drain(..) {
            log::trace!("metrics: {req:?}");
        }
    }
}

pub fn start_metrics_thread(
    client: Option<influxdb::Client>,
    rx: AsyncReceiver<WriteQuery>,
    exit: oneshot::Receiver<()>,
) {
    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create metrics runtime");
    rt.block_on(async move {
        let metrics_task = if let Some(client) = client {
            spawn(metrics_loop(client, rx))
        } else {
            spawn(mock_metrics_loop(rx))
        };
        exit.await.ok();
        metrics_task.abort();
    })
}
