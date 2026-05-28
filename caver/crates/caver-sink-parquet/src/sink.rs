//! `ParquetSink` — batching accumulator with timer-based flush.
//!
//! Accumulates events up to `config.batch_size` or `config.flush_seconds`,
//! then serializes to Parquet and calls `put_fn(bucket, key, data)`.
//! On `put_fn` failure, writes raw NDJSON to `dlq_path` if configured.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use serde_json::Value;
use thiserror::Error;

use crate::partition::{new_file_id, partition_key};
use crate::schema::{events_to_parquet, SchemaError};

/// Sink configuration — mirrors the Python `caver_parquet` sink config.
#[derive(Debug, Clone)]
pub struct Config {
    /// S3/MinIO bucket name.
    pub bucket: String,
    /// Sensor identifier embedded in the partition path.
    /// Defaults to the system hostname when empty.
    pub sensor_id: String,
    /// Event field used as the OCSF class discriminator.
    /// Default: `"class_uid"`.
    pub class_uid_field: String,
    /// Flush after accumulating this many events.
    pub batch_size: usize,
    /// Flush after this many seconds even if `batch_size` not reached.
    pub flush_seconds: f64,
    /// On upload failure, write NDJSON fallback here.
    pub dlq_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            sensor_id: String::new(),
            class_uid_field: "class_uid".into(),
            batch_size: 500,
            flush_seconds: 30.0,
            dlq_path: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("schema error: {0}")]
    Schema(#[from] SchemaError),
    #[error("put error: {0}")]
    Put(String),
    #[error("dlq write failed: {0}")]
    Dlq(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Injectable upload function.
pub type PutFn =
    Arc<dyn Fn(&str, &str, Vec<u8>) -> Result<(), String> + Send + Sync>;

struct State {
    buffer: Vec<Value>,
    last_flush: Instant,
}

/// Batching Parquet sink.
///
/// Thread-safe via `Arc<Mutex<State>>`. Call `push` for each event;
/// `flush` is called automatically when thresholds are met.
/// Call `flush` explicitly before drop to drain any remaining events.
pub struct ParquetSink {
    config: Config,
    put_fn: PutFn,
    state: Mutex<State>,
}

impl ParquetSink {
    pub fn new(config: Config, put_fn: PutFn) -> Self {
        Self {
            config,
            put_fn,
            state: Mutex::new(State {
                buffer: Vec::new(),
                last_flush: Instant::now(),
            }),
        }
    }

    /// Push one event; flushes when batch is full or timer expired.
    pub fn push(&self, event: Value) -> Result<(), SinkError> {
        let mut st = self.state.lock().unwrap();
        st.buffer.push(event);
        let should_flush = st.buffer.len() >= self.config.batch_size
            || st.last_flush.elapsed()
                >= Duration::from_secs_f64(self.config.flush_seconds);
        if should_flush {
            let batch = std::mem::take(&mut st.buffer);
            st.last_flush = Instant::now();
            drop(st); // release lock before I/O
            self.flush_batch(batch)?;
        }
        Ok(())
    }

    /// Drain the buffer immediately regardless of thresholds.
    pub fn flush(&self) -> Result<(), SinkError> {
        let mut st = self.state.lock().unwrap();
        if st.buffer.is_empty() {
            return Ok(());
        }
        let batch = std::mem::take(&mut st.buffer);
        st.last_flush = Instant::now();
        drop(st);
        self.flush_batch(batch)
    }

    fn flush_batch(&self, events: Vec<Value>) -> Result<(), SinkError> {
        if events.is_empty() {
            return Ok(());
        }

        // Determine class_uid for partition key (use first event's value or "0000").
        let class_uid = events
            .first()
            .and_then(|e| e.get(&self.config.class_uid_field))
            .and_then(Value::as_str)
            .unwrap_or("0000")
            .to_string();

        let sensor = if self.config.sensor_id.is_empty() {
            hostname()
        } else {
            self.config.sensor_id.clone()
        };

        let now = Utc::now();
        let file_id = new_file_id();
        let key = partition_key(&class_uid, &sensor, now, &file_id);

        let parquet_bytes = events_to_parquet(&events)?;

        match (self.put_fn)(&self.config.bucket, &key, parquet_bytes) {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(dlq) = &self.config.dlq_path {
                    self.write_dlq(dlq, &events)?;
                }
                Err(SinkError::Put(e))
            }
        }
    }

    fn write_dlq(&self, path: &PathBuf, events: &[Value]) -> Result<(), SinkError> {
        use std::io::Write;
        std::fs::create_dir_all(path)
            .map_err(|e| SinkError::Dlq(e.to_string()))?;
        let file_name = format!("{}.ndjson", new_file_id());
        let dlq_file = path.join(file_name);
        let mut f = std::fs::File::create(&dlq_file)
            .map_err(|e| SinkError::Dlq(e.to_string()))?;
        for ev in events {
            let line = serde_json::to_string(ev)
                .map_err(|e| SinkError::Dlq(e.to_string()))?;
            writeln!(f, "{line}").map_err(|e| SinkError::Dlq(e.to_string()))?;
        }
        Ok(())
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counting_put(counter: Arc<AtomicUsize>) -> PutFn {
        Arc::new(move |_bucket, _key, _data| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    #[test]
    fn flushes_on_batch_size() {
        let counter = Arc::new(AtomicUsize::new(0));
        let cfg = Config { batch_size: 3, ..Default::default() };
        let sink = ParquetSink::new(cfg, counting_put(counter.clone()));

        for _ in 0..3 {
            sink.push(json!({"class_uid": "4002"})).unwrap();
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn explicit_flush_drains_partial_batch() {
        let counter = Arc::new(AtomicUsize::new(0));
        let cfg = Config { batch_size: 100, ..Default::default() };
        let sink = ParquetSink::new(cfg, counting_put(counter.clone()));

        sink.push(json!({"class_uid": "4002"})).unwrap();
        sink.push(json!({"class_uid": "4002"})).unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        sink.flush().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dlq_written_on_put_failure() {
        let dlq = tempfile::tempdir().unwrap();
        let cfg = Config {
            batch_size: 1,
            dlq_path: Some(dlq.path().to_path_buf()),
            ..Default::default()
        };
        let fail_put: PutFn = Arc::new(|_, _, _| Err("put failed".into()));
        let sink = ParquetSink::new(cfg, fail_put);

        let result = sink.push(json!({"class_uid": "4002"}));
        assert!(matches!(result, Err(SinkError::Put(_))));

        let dlq_files: Vec<_> = std::fs::read_dir(dlq.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(dlq_files.len(), 1, "expected one DLQ file");
    }

    #[test]
    fn flush_empty_is_noop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let sink = ParquetSink::new(Config::default(), counting_put(counter.clone()));
        sink.flush().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn class_uid_fallback_when_missing() {
        let got_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let got_key_clone = got_key.clone();
        let capture_put: PutFn = Arc::new(move |_, key, _| {
            *got_key_clone.lock().unwrap() = Some(key.to_string());
            Ok(())
        });
        let cfg = Config { batch_size: 1, ..Default::default() };
        let sink = ParquetSink::new(cfg, capture_put);
        sink.push(json!({"no_class_uid": "here"})).unwrap();
        let key = got_key.lock().unwrap().clone().unwrap();
        assert!(key.starts_with("0000/"), "expected 0000 fallback, got: {key}");
    }
}
