//! OCSF lake partition key + filename generation.
//!
//! Scheme: `<class_uid>/dt=YYYY-MM-DD/hour=HH/sensor=<sensor_id>/<file>.parquet`
//! File:   `<YYYYMMDDTHHmmss>-<uuid12>.parquet`

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Generate the full S3 key for a Parquet file.
///
/// ```
/// use caver_sink_parquet::partition::partition_key;
/// use chrono::{TimeZone, Utc};
///
/// let t = Utc.with_ymd_and_hms(2026, 5, 28, 14, 0, 0).unwrap();
/// let key = partition_key("4002", "edge-01", t, "abc123456789");
/// assert_eq!(key, "4002/dt=2026-05-28/hour=14/sensor=edge-01/20260528T140000-abc123456789.parquet");
/// ```
pub fn partition_key(
    class_uid: &str,
    sensor_id: &str,
    ts: DateTime<Utc>,
    file_id: &str,
) -> String {
    format!(
        "{}/dt={}/hour={:02}/sensor={}/{}-{}.parquet",
        class_uid,
        ts.format("%Y-%m-%d"),
        ts.hour(),
        sensor_id,
        ts.format("%Y%m%dT%H%M%S"),
        file_id,
    )
}

/// Generate a new unique file ID (12-char UUID prefix, lowercase hex).
pub fn new_file_id() -> String {
    Uuid::new_v4().simple().to_string()[..12].to_string()
}

// ---------------------------------------------------------------------------
// Re-export chrono helper used by partition_key callers.
// ---------------------------------------------------------------------------
use chrono::Timelike as _;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn key_format() {
        let t = Utc.with_ymd_and_hms(2026, 5, 28, 9, 3, 7).unwrap();
        let k = partition_key("4002", "edge-01", t, "aabbccddeeff");
        assert_eq!(
            k,
            "4002/dt=2026-05-28/hour=09/sensor=edge-01/20260528T090307-aabbccddeeff.parquet"
        );
    }

    #[test]
    fn midnight_hour_zero() {
        let t = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let k = partition_key("0000", "s1", t, "x");
        assert!(k.contains("hour=00"), "{k}");
    }

    #[test]
    fn new_file_id_length() {
        let id = new_file_id();
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
    }
}
