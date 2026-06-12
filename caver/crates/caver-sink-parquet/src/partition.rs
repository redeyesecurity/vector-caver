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

/// Build the caver_staging S3 key (PARQUET-CONTRACT, RES-splunk-caver#1800),
/// matching the Python collector's `_build_staging_key`:
/// `<staging_prefix>/<source>/year=YYYY/month=MM/day=DD/<writer>_YYYYMMDD_HHMMSS_<uuid8>.parquet`
pub fn build_staging_key(
    staging_prefix: &str,
    source: &str,
    writer_name: &str,
    ts: DateTime<Utc>,
) -> String {
    let file_id = &Uuid::new_v4().simple().to_string()[..8];
    format!(
        "{staging_prefix}/{source}/year={y}/month={m}/day={d}/{writer_name}_{ymd}_{hms}_{file_id}.parquet",
        y = ts.format("%Y"),
        m = ts.format("%m"),
        d = ts.format("%d"),
        ymd = ts.format("%Y%m%d"),
        hms = ts.format("%H%M%S"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn staging_key_shape() {
        let ts = Utc.with_ymd_and_hms(2026, 6, 12, 15, 4, 5).unwrap();
        let key = build_staging_key("uf/ocsf", "edge-01", "collector", ts);
        let parts: Vec<&str> = key.split('/').collect();
        assert_eq!(
            &parts[..6],
            &["uf", "ocsf", "edge-01", "year=2026", "month=06", "day=12"]
        );
        let fname = parts[6];
        assert!(
            fname.starts_with("collector_20260612_150405_") && fname.ends_with(".parquet"),
            "contract filename violated: {fname}"
        );
        // <writer>_<YYYYMMDD>_<HHMMSS>_<8 hex>.parquet
        let id = fname
            .trim_end_matches(".parquet")
            .rsplit('_')
            .next()
            .unwrap();
        assert_eq!(id.len(), 8);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
