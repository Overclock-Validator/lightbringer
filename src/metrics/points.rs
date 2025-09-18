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
