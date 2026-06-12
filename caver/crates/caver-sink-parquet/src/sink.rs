use crate::partition::{build_key, build_staging_key, DEFAULT_CLASS_UID};
use crate::writer::{rows_to_parquet, rows_to_staging_parquet};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Object-store writer: `(bucket, key, body)` → `Err(reason)` sends the
/// batch to the DLQ. Build one with [`crate::transport::s3_put_fn`] or
/// inject your own (tests).
pub type PutFn = Arc<dyn Fn(&str, &str, Vec<u8>) -> Result<(), String> + Send + Sync>;

/// Object layout written to the lake. Mirrors the Python sink's `layout`
/// config (caver-collector#843).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Layout {
    /// caver_staging PARQUET-CONTRACT (RES-splunk-caver#1800):
    /// `uf/ocsf/<source>/year=/month=/day=/` with typed columns — the shape
    /// the caver compactor + lake reader serve. Default, so collector output
    /// is queryable out of the box (parity with the Python sink).
    #[default]
    CaverStaging,
    /// Sink-original `<class_uid>/dt=` layout with all-string columns.
    /// NOT served by the Caver lake — opt in only for a non-caver consumer.
    Native,
}

pub struct Config {
    pub bucket: String,
    pub sensor_id: String,
    pub class_uid_field: String,
    pub batch_size: usize,
    pub dlq_path: Option<PathBuf>,
    pub layout: Layout,
    /// caver_staging: source-name path segment; `None` → `sensor_id`
    /// (falling back to `"collector"`), like the Python sink.
    pub source: Option<String>,
    /// caver_staging: filename writer prefix
    /// (`<writer>_YYYYMMDD_HHMMSS_<id>.parquet`).
    pub writer_name: String,
    /// caver_staging: key prefix ahead of the source segment.
    pub staging_prefix: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bucket: "caver-lake".into(),
            sensor_id: hostname(),
            class_uid_field: "class_uid".into(),
            batch_size: 500,
            dlq_path: None,
            layout: Layout::default(),
            source: None,
            writer_name: "collector".into(),
            staging_prefix: "uf/ocsf".into(),
        }
    }
}

fn hostname() -> String {
    // Try the environment variable first (set by most Unix shells / container runtimes).
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    // Fall back to reading /etc/hostname on Linux / macOS.
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    "collector".into()
}

/// Prepare one event row for the caver_staging contract, mirroring the
/// Python sink's `_event_to_staging_row`: `_time` defaults to now (epoch
/// seconds) when missing or unparseable; `index` defaults to `"main"`;
/// `class_uid` becomes `"0"` when missing OR empty (Python `or 0`); the
/// remaining required string columns default to `""`.
fn staging_row(row: &HashMap<String, String>, now: DateTime<Utc>) -> HashMap<String, String> {
    let mut out = row.clone();
    let time_ok = out
        .get("_time")
        .is_some_and(|s| crate::schema::parse_f64(s).is_some());
    if !time_ok {
        out.insert(
            "_time".into(),
            format!("{:.6}", now.timestamp_micros() as f64 / 1e6),
        );
    }
    let cu_empty = out.get("class_uid").is_none_or(|s| s.is_empty());
    if cu_empty {
        out.insert("class_uid".into(), "0".into());
    }
    out.entry("index".into()).or_insert_with(|| "main".into());
    for col in ["class_name", "host", "source", "sourcetype", "_raw"] {
        out.entry(col.into()).or_default();
    }
    out
}

/// Epoch seconds (fractional) → UTC datetime; `None` on out-of-range.
fn epoch_to_datetime(t: f64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(t as i64, (t.fract() * 1e9) as u32)
}

struct Inner {
    buf: Vec<HashMap<String, String>>,
    accepted: u64,
    dropped: u64,
    flushes: u64,
    put_errors: u64,
}

/// OCSF-partitioned Parquet sink. Mirrors the Python `CaverParquetSink`.
///
/// `put_fn`: injectable S3/MinIO writer; if `None`, caller must call `drain()` manually.
pub struct ParquetSink {
    cfg: Config,
    /// Resolved caver_staging source segment (`cfg.source` → `cfg.sensor_id`
    /// → `"collector"`), like the Python sink's `source_name`.
    source_name: String,
    put_fn: Option<PutFn>,
    inner: Mutex<Inner>,
}

impl ParquetSink {
    pub fn new(cfg: Config, put_fn: Option<PutFn>) -> Self {
        let source_name = cfg
            .source
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| Some(cfg.sensor_id.clone()).filter(|s| !s.is_empty()))
            .unwrap_or_else(|| "collector".into());
        Self {
            cfg,
            source_name,
            put_fn,
            inner: Mutex::new(Inner {
                buf: Vec::new(),
                accepted: 0,
                dropped: 0,
                flushes: 0,
                put_errors: 0,
            }),
        }
    }

    /// Accept an event (flat string map).
    /// Flushes when the batch reaches `cfg.batch_size`.
    pub fn send(&self, event: HashMap<String, String>) {
        let should_flush = {
            let mut g = self.inner.lock().unwrap();
            g.buf.push(event);
            g.accepted += 1;
            g.buf.len() >= self.cfg.batch_size
        };
        if should_flush {
            self.flush();
        }
    }

    /// Force a flush of whatever is buffered.
    pub fn flush(&self) {
        let batch = {
            let mut g = self.inner.lock().unwrap();
            if g.buf.is_empty() {
                return;
            }
            std::mem::take(&mut g.buf)
        };

        let now = Utc::now();
        let (key, encoded, rows) = match self.cfg.layout {
            Layout::CaverStaging => {
                let rows: Vec<HashMap<String, String>> =
                    batch.iter().map(|r| staging_row(r, now)).collect();
                // Partition by the first row's event time, like the Python
                // sink's `_build_staging_key(rows[0])`.
                // Non-finite `_time` (parse accepts "inf"/"NaN") keys to flush
                // time rather than a bogus 1970 partition.
                let ts = rows[0]
                    .get("_time")
                    .and_then(|s| crate::schema::parse_f64(s))
                    .filter(|t| t.is_finite())
                    .and_then(epoch_to_datetime)
                    .unwrap_or(now);
                let key = build_staging_key(
                    &self.cfg.staging_prefix,
                    &self.source_name,
                    &self.cfg.writer_name,
                    ts,
                );
                let encoded = rows_to_staging_parquet(&rows);
                (key, encoded, rows)
            }
            Layout::Native => {
                let class_uid = batch[0]
                    .get(&self.cfg.class_uid_field)
                    .map(|s| s.as_str())
                    .unwrap_or(DEFAULT_CLASS_UID);
                let key = build_key(class_uid, &self.cfg.sensor_id, now);
                let encoded = rows_to_parquet(&batch);
                (key, encoded, batch)
            }
        };

        match encoded {
            Ok(bytes) => {
                if let Some(ref put) = self.put_fn {
                    match put(&self.cfg.bucket, &key, bytes) {
                        Ok(()) => {
                            let mut g = self.inner.lock().unwrap();
                            g.flushes += 1;
                        }
                        Err(e) => {
                            let mut g = self.inner.lock().unwrap();
                            g.dropped += rows.len() as u64;
                            g.put_errors += 1;
                            drop(g);
                            self.to_dlq(&rows, &format!("put: {e}"));
                        }
                    }
                }
            }
            Err(e) => {
                let mut g = self.inner.lock().unwrap();
                g.dropped += rows.len() as u64;
                drop(g);
                self.to_dlq(&rows, &format!("serialize: {e}"));
            }
        }
    }

    pub fn stats(&self) -> HashMap<String, u64> {
        let g = self.inner.lock().unwrap();
        HashMap::from([
            ("accepted".into(), g.accepted),
            ("dropped".into(), g.dropped),
            ("flushes".into(), g.flushes),
            ("put_errors".into(), g.put_errors),
            ("buf_size".into(), g.buf.len() as u64),
        ])
    }

    fn to_dlq(&self, rows: &[HashMap<String, String>], reason: &str) {
        let Some(dlq) = &self.cfg.dlq_path else {
            return;
        };
        let _ = std::fs::create_dir_all(dlq);
        let stamp = Utc::now().format("%Y%m%dT%H%M%S");
        let id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let path = dlq.join(format!("dlq-{stamp}-{id}.ndjson"));
        if let Ok(mut f) = std::fs::File::create(&path) {
            use std::io::Write;
            for row in rows {
                if let Ok(line) = serde_json::to_string(row) {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
        let _ = reason;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[test]
    fn flush_on_batch_size() {
        let captured: Arc<StdMutex<Vec<(String, String, Vec<u8>)>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let cap2 = captured.clone();
        let put: PutFn = Arc::new(move |bucket: &str, key: &str, body: Vec<u8>| {
            cap2.lock().unwrap().push((bucket.into(), key.into(), body));
            Ok(())
        });

        let cfg = Config {
            batch_size: 2,
            ..Config::default()
        };
        let sink = ParquetSink::new(cfg, Some(put));

        sink.send(HashMap::from([
            ("class_uid".into(), "2003".into()),
            ("x".into(), "1".into()),
        ]));
        assert_eq!(captured.lock().unwrap().len(), 0, "no flush yet");

        sink.send(HashMap::from([
            ("class_uid".into(), "2003".into()),
            ("x".into(), "2".into()),
        ]));
        let puts = captured.lock().unwrap().len();
        assert_eq!(puts, 1, "flushed on batch_size=2");

        let stats = sink.stats();
        assert_eq!(stats["accepted"], 2);
        assert_eq!(stats["flushes"], 1);
    }

    #[test]
    fn manual_flush() {
        let captured: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
        let cap2 = captured.clone();
        let put: PutFn = Arc::new(move |_b, _k, body| {
            cap2.lock().unwrap().push(body);
            Ok(())
        });

        let cfg = Config {
            batch_size: 100,
            ..Config::default()
        };
        let sink = ParquetSink::new(cfg, Some(put));

        sink.send(HashMap::from([("class_uid".into(), "2003".into())]));
        assert!(captured.lock().unwrap().is_empty());
        sink.flush();
        let puts = captured.lock().unwrap().len();
        assert_eq!(puts, 1);
    }

    #[test]
    fn staging_row_defaults() {
        let now = Utc::now();
        let row = HashMap::from([
            ("class_uid".into(), "".into()),
            ("_time".into(), "not-a-float".into()),
            ("msg".into(), "hi".into()),
        ]);
        let out = staging_row(&row, now);
        // Unparseable _time replaced with now (epoch seconds).
        let t: f64 = out["_time"].parse().expect("numeric _time");
        assert!((t - now.timestamp_micros() as f64 / 1e6).abs() < 1e-3);
        assert_eq!(
            out["class_uid"], "0",
            "empty class_uid -> 0 (Python `or 0`)"
        );
        assert_eq!(out["index"], "main");
        for col in ["class_name", "host", "source", "sourcetype", "_raw"] {
            assert_eq!(out[col], "", "{col} defaults to empty string");
        }
        assert_eq!(out["msg"], "hi", "payload preserved");

        // Parseable _time and non-empty class_uid pass through untouched.
        let row2 = HashMap::from([
            ("_time".into(), "1765551845.25".into()),
            ("class_uid".into(), "4002".into()),
            ("index".into(), "win".into()),
        ]);
        let out2 = staging_row(&row2, now);
        assert_eq!(out2["_time"], "1765551845.25");
        assert_eq!(out2["class_uid"], "4002");
        assert_eq!(out2["index"], "win");
    }

    #[test]
    fn staging_flush_partitions_by_event_time() {
        let captured: Arc<StdMutex<Vec<(String, Vec<u8>)>>> = Arc::new(StdMutex::new(Vec::new()));
        let cap2 = captured.clone();
        let put: PutFn = Arc::new(move |_b, key: &str, body: Vec<u8>| {
            cap2.lock().unwrap().push((key.into(), body));
            Ok(())
        });

        let cfg = Config {
            batch_size: 1,
            source: Some("edge-src".into()),
            ..Config::default()
        };
        assert_eq!(cfg.layout, Layout::CaverStaging, "staging is the default");
        let sink = ParquetSink::new(cfg, Some(put));

        // 2026-06-12 15:04:05 UTC
        sink.send(HashMap::from([
            ("_time".into(), "1781276645.0".into()),
            ("msg".into(), "hello".into()),
        ]));

        let puts = captured.lock().unwrap();
        assert_eq!(puts.len(), 1);
        let (key, body) = &puts[0];
        assert!(
            key.starts_with(
                "uf/ocsf/edge-src/year=2026/month=06/day=12/collector_20260612_150405_"
            ),
            "staging key from event _time, source override: {key}"
        );
        assert!(key.ends_with(".parquet"));
        assert_eq!(&body[..4], b"PAR1");
    }

    #[test]
    fn staging_flush_without_time_keys_to_now() {
        let captured: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let cap2 = captured.clone();
        let put: PutFn = Arc::new(move |_b, key: &str, _body| {
            cap2.lock().unwrap().push(key.into());
            Ok(())
        });

        let cfg = Config {
            batch_size: 1,
            source: Some("edge-src".into()),
            ..Config::default()
        };
        let sink = ParquetSink::new(cfg, Some(put));
        let before = Utc::now();
        sink.send(HashMap::from([("msg".into(), "no time field".into())]));

        let keys = captured.lock().unwrap();
        assert_eq!(keys.len(), 1);
        // staging_row injected _time = now, so the key partitions on today.
        let expected = format!("uf/ocsf/edge-src/year={}", before.format("%Y"));
        assert!(
            keys[0].starts_with(&expected),
            "keyed to now, got {}",
            keys[0]
        );
    }

    #[test]
    fn source_name_resolution_chain() {
        let cfg = Config {
            source: None,
            sensor_id: "sensor-9".into(),
            ..Config::default()
        };
        assert_eq!(ParquetSink::new(cfg, None).source_name, "sensor-9");

        let cfg = Config {
            source: Some("".into()),
            sensor_id: "".into(),
            ..Config::default()
        };
        assert_eq!(ParquetSink::new(cfg, None).source_name, "collector");
    }

    #[test]
    fn put_failure_counts_and_dlqs() {
        let dlq =
            std::env::temp_dir().join(format!("caver-sink-dlq-{}", uuid::Uuid::new_v4().simple()));
        let put: PutFn = Arc::new(|_b, _k, _body| Err("connection refused".into()));

        let cfg = Config {
            batch_size: 2,
            dlq_path: Some(dlq.clone()),
            ..Config::default()
        };
        let sink = ParquetSink::new(cfg, Some(put));
        sink.send(HashMap::from([("class_uid".into(), "2003".into())]));
        sink.send(HashMap::from([("class_uid".into(), "2003".into())]));

        let stats = sink.stats();
        assert_eq!(stats["accepted"], 2);
        assert_eq!(stats["dropped"], 2, "failed batch counted dropped");
        assert_eq!(stats["put_errors"], 1);
        assert_eq!(stats["flushes"], 0, "failed put is not a flush");

        let dlq_files: Vec<_> = std::fs::read_dir(&dlq)
            .expect("dlq dir created")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(dlq_files.len(), 1, "one DLQ file for the failed batch");
        let body = std::fs::read_to_string(dlq_files[0].path()).unwrap();
        assert_eq!(body.lines().count(), 2, "both events preserved as ndjson");
        std::fs::remove_dir_all(&dlq).ok();
    }
}
