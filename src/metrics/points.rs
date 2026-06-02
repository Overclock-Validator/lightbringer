use std::{
    fmt::Display,
    time::{SystemTime, UNIX_EPOCH},
};

use influxdb::{InfluxDbWriteable, Timestamp};

pub trait DataPoint: InfluxDbWriteable {
    fn measurement() -> &'static str;
}

fn now() -> Timestamp {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    Timestamp::Milliseconds(timestamp_ms)
}

pub enum SlotMeasurementKind {
    Completion,
    RepairInitiate,
}

impl Display for SlotMeasurementKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotMeasurementKind::Completion => write!(f, "completion"),
            SlotMeasurementKind::RepairInitiate => write!(f, "repair_initiate"),
        }
    }
}

impl From<SlotMeasurementKind> for influxdb::Type {
    fn from(value: SlotMeasurementKind) -> Self {
        Self::Text(value.to_string())
    }
}

#[derive(InfluxDbWriteable)]
pub struct SlotMeasurement {
    time: Timestamp,
    slot: u64,
    #[influxdb(tag)]
    kind: SlotMeasurementKind,
}

impl SlotMeasurement {
    pub fn completion(slot: u64) -> Self {
        Self {
            time: now(),
            slot,
            kind: SlotMeasurementKind::Completion,
        }
    }

    pub fn repair(slot: u64) -> Self {
        Self {
            time: now(),
            slot,
            kind: SlotMeasurementKind::RepairInitiate,
        }
    }
}

impl DataPoint for SlotMeasurement {
    fn measurement() -> &'static str {
        "slot"
    }
}

#[derive(InfluxDbWriteable)]
pub struct ServeRepairMeasurement {
    time: Timestamp,
    requests_served: u64,
    requests_dropped: u64,
    requests_rate_limited: u64,
    #[influxdb(tag)]
    kind: ServeRepairMeasurementKind,
}

pub enum ServeRepairMeasurementKind {
    Aggregate,
}

impl Display for ServeRepairMeasurementKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeRepairMeasurementKind::Aggregate => write!(f, "aggregate"),
        }
    }
}

impl From<ServeRepairMeasurementKind> for influxdb::Type {
    fn from(value: ServeRepairMeasurementKind) -> Self {
        Self::Text(value.to_string())
    }
}

impl ServeRepairMeasurement {
    pub fn new(requests_served: u64, requests_dropped: u64, requests_rate_limited: u64) -> Self {
        Self {
            time: now(),
            requests_served,
            requests_dropped,
            requests_rate_limited,
            kind: ServeRepairMeasurementKind::Aggregate,
        }
    }
}

impl DataPoint for ServeRepairMeasurement {
    fn measurement() -> &'static str {
        "serve_repair"
    }
}

const PAGE_SIZE: u64 = 4096; // x86_64 Linux

pub enum MemoryMeasurementKind {
    Process,
}

impl Display for MemoryMeasurementKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryMeasurementKind::Process => write!(f, "process"),
        }
    }
}

impl From<MemoryMeasurementKind> for influxdb::Type {
    fn from(value: MemoryMeasurementKind) -> Self {
        Self::Text(value.to_string())
    }
}

#[derive(InfluxDbWriteable)]
pub struct MemoryMeasurement {
    time: Timestamp,
    rss_bytes: u64,
    virtual_bytes: u64,
    #[influxdb(tag)]
    kind: MemoryMeasurementKind,
}

impl MemoryMeasurement {
    pub async fn sample() -> Option<Self> {
        let statm = tokio::fs::read_to_string("/proc/self/statm").await.ok()?;
        let mut fields = statm.split_whitespace();
        let virtual_pages: u64 = fields.next()?.parse().ok()?;
        let rss_pages: u64 = fields.next()?.parse().ok()?;
        Some(Self {
            time: now(),
            rss_bytes: rss_pages * PAGE_SIZE,
            virtual_bytes: virtual_pages * PAGE_SIZE,
            kind: MemoryMeasurementKind::Process,
        })
    }
}

impl DataPoint for MemoryMeasurement {
    fn measurement() -> &'static str {
        "memory"
    }
}
