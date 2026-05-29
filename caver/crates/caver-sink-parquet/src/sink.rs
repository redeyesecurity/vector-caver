use crate::partition::{build_key, DEFAULT_CLASS_UID};
use crate::writer::rows_to_parquet;
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub type PutFn = Arc<dyn Fn(&str, &str, Vec<u8>) + Send + Sync>;

pub struct Config {
    pub bucket: String,
    pub sensor_id: String,
    pub class_uid_field: String,
    pub batch_size: usize,
    pub dlq_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bucket: "caver-lake".into(),
            sensor_id: hostname(),
            class_uid_field: "class_uid".into(),
            batch_size: 500,
            dlq_path: None,
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

struct Inner {
    buf: Vec<HashMap<String, String>>,
    accepted: u64,
    dropped: u64,
    flushes: u64,
}

/// OCSF-partitioned Parquet sink. Mirrors the Python `CaverParquetSink`.
///
/// `put_fn`: injectable S3/MinIO writer; if `None`, caller must call `drain()` manually.
pub struct ParquetSink {
    cfg: Config,
    put_fn: Option<PutFn>,
    inner: Mutex<Inner>,
}

impl ParquetSink {
    pub fn new(cfg: Config, put_fn: Option<PutFn>) -> Self {
        Self {
            cfg,
            put_fn,
            inner: Mutex::new(Inner {
                buf: Vec::new(),
                accepted: 0,
                dropped: 0,
                flushes: 0,
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

        let class_uid = batch[0]
            .get(&self.cfg.class_uid_field)
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_CLASS_UID);

        let key = build_key(class_uid, &self.cfg.sensor_id, Utc::now());

        match rows_to_parquet(&batch) {
            Ok(bytes) => {
                if let Some(ref put) = self.put_fn {
                    put(&self.cfg.bucket, &key, bytes);
                    let mut g = self.inner.lock().unwrap();
                    g.flushes += 1;
                }
            }
            Err(e) => {
                let mut g = self.inner.lock().unwrap();
                g.dropped += batch.len() as u64;
                drop(g);
                self.to_dlq(&batch, &format!("serialize: {e}"));
            }
        }
    }

    pub fn stats(&self) -> HashMap<String, u64> {
        let g = self.inner.lock().unwrap();
        HashMap::from([
            ("accepted".into(), g.accepted),
            ("dropped".into(), g.dropped),
            ("flushes".into(), g.flushes),
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
        });

        let cfg = Config { batch_size: 2, ..Config::default() };
        let sink = ParquetSink::new(cfg, Some(put));

        sink.send(HashMap::from([("class_uid".into(), "2003".into()), ("x".into(), "1".into())]));
        assert_eq!(captured.lock().unwrap().len(), 0, "no flush yet");

        sink.send(HashMap::from([("class_uid".into(), "2003".into()), ("x".into(), "2".into())]));
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
        });

        let cfg = Config { batch_size: 100, ..Config::default() };
        let sink = ParquetSink::new(cfg, Some(put));

        sink.send(HashMap::from([("class_uid".into(), "2003".into())]));
        assert!(captured.lock().unwrap().is_empty());
        sink.flush();
        let puts = captured.lock().unwrap().len();
        assert_eq!(puts, 1);
    }
}
