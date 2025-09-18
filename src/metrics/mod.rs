use std::time::Duration;

use glommio::{spawn_local, timer::sleep};
use influxdb::WriteQuery;
use kanal::{AsyncReceiver, AsyncSender};

use crate::{metrics::points::DataPoint, thread_manager::CancelRx};

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

pub async fn metrics_loop(exit: CancelRx, client: influxdb::Client, rx: AsyncReceiver<WriteQuery>) {
    let task = spawn_local(async move {
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
    });
    exit.await;
    task.cancel().await;
}

pub async fn mock_metrics_loop(exit: CancelRx, rx: AsyncReceiver<WriteQuery>) {
    log::info!("running in metrics in mock mode, metrics will be logged to trace");
    let task = spawn_local(async move {
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
    });
    exit.await;
    task.cancel().await;
}
