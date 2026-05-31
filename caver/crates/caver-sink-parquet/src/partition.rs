use chrono::{DateTime, Utc};
use uuid::Uuid;

pub const DEFAULT_CLASS_UID: &str = "0000";

/// Build the S3 key for a batch:
/// `<class_uid>/dt=YYYY-MM-DD/hour=HH/sensor=<sensor_id>/<YYYYMMDDTHHMMSS>-<uuid12>.parquet`
pub fn build_key(class_uid: &str, sensor_id: &str, ts: DateTime<Utc>) -> String {
    let date = ts.format("%Y-%m-%d");
    let hour = ts.format("%H");
    let ts_str = ts.format("%Y%m%dT%H%M%S");
    let file_id = &Uuid::new_v4().simple().to_string()[..12];
    format!("{class_uid}/dt={date}/hour={hour}/sensor={sensor_id}/{ts_str}-{file_id}.parquet")
}
