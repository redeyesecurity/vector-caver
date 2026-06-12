use crate::partition::{build_key, build_staging_key, DEFAULT_CLASS_UID};
use crate::writer::{rows_to_parquet, rows_to_staging_parquet};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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
    /// Timer-flush tick interval, in seconds (the Python sink's
    /// `flush_seconds`). The background flusher started by
    /// [`ParquetSink::start_flusher`] wakes this often; without it a
    /// below-`batch_size` buffer never ships until shutdown
    /// (caver-collector#901). `0` is clamped to `1` by
    /// [`ParquetSink::start_flusher`] (the Vector layer rejects it loudly
    /// at config build time instead).
    pub flush_seconds: u64,
    /// Freshness backstop, in seconds (the Python sink's
    /// `flush_max_age_seconds`, caver-collector#888): a timer tick drains a
    /// below-`batch_size` buffer only once its oldest event has waited this
    /// long. `0` = drain on every tick. Batch-full and shutdown flushes are
    /// unaffected.
    pub flush_max_age_seconds: u64,
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
            flush_seconds: 30,
            flush_max_age_seconds: 300,
        }
    }
}

/// Charset safe to embed raw in an object key (and the SigV4 canonical
/// path). Anything outside it (`/`, spaces, non-ASCII) breaks the staging
/// layout or 403s whole batches; all-dot segments confuse path-mapped
/// tooling. Mirrors the Vector config layer's `is_key_safe` — enforced here
/// too because the hostname default and direct crate consumers bypass that
/// layer (caver-collector#899).
fn key_safe(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !s.bytes().all(|b| b == b'.')
}

fn hostname() -> String {
    // Try the environment variable first (set by most Unix shells / container runtimes).
    if let Ok(h) = std::env::var("HOSTNAME") {
        if key_safe(&h) {
            return h;
        }
    }
    // Fall back to reading /etc/hostname on Linux / macOS.
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = h.trim();
        if key_safe(trimmed) {
            return trimmed.to_owned();
        }
    }
    // Empty, unset, or key-unsafe (we have met a corrupted-hostname box in
    // the wild — garbage non-ASCII bytes): a safe constant beats a key that
    // 403s every batch.
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
    /// Arrival time of `buf[0]` — drives the `flush_max_age_seconds`
    /// freshness backstop. Set when the buffer goes empty→non-empty,
    /// cleared when it is taken for a flush.
    oldest: Option<Instant>,
    accepted: u64,
    dropped: u64,
    flushes: u64,
    put_errors: u64,
    timer_skips: u64,
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
    /// Background timer-flush thread (the Python sink's `_flush_loop`),
    /// started by [`Self::start_flusher`]. The pair is the stop signal:
    /// flag under the mutex, condvar to cut the tick wait short.
    flusher: Mutex<Option<std::thread::JoinHandle<()>>>,
    stop: Arc<(Mutex<bool>, Condvar)>,
}

impl ParquetSink {
    /// The Vector config layer validates `source`/`sensor_id`/`writer_name`/
    /// `staging_prefix` at boot and rejects bad values loudly. The crate is
    /// also consumable directly, so the contract is enforced here too —
    /// sanitize-with-fallback rather than panic, because by the time `new`
    /// runs we are the data plane (caver-collector#899). A non-contract key
    /// would either 403 the whole batch (SigV4 canonical path) or be silently
    /// skipped by the compactor.
    pub fn new(mut cfg: Config, put_fn: Option<PutFn>) -> Self {
        let source_name = cfg
            .source
            .clone()
            .filter(|s| key_safe(s))
            .or_else(|| Some(cfg.sensor_id.clone()).filter(|s| key_safe(s)))
            .unwrap_or_else(|| "collector".into());
        // PARQUET-CONTRACT filename regex: the compactor skips files whose
        // writer prefix doesn't start with a letter.
        if !cfg
            .writer_name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic())
            || !key_safe(&cfg.writer_name)
        {
            cfg.writer_name = "collector".into();
        }
        let trimmed = cfg.staging_prefix.trim_matches('/');
        cfg.staging_prefix = if !trimmed.is_empty() && trimmed.split('/').all(key_safe) {
            trimmed.to_owned()
        } else {
            "uf/ocsf".into()
        };
        // Native layout embeds sensor_id raw in the partition key
        // (`sensor=<sensor_id>`); same sanitize-with-fallback as the staging
        // source chain above (caver-collector#898 item 4, carried from the
        // PR #20 review).
        if !key_safe(&cfg.sensor_id) {
            cfg.sensor_id = "collector".into();
        }
        Self {
            cfg,
            source_name,
            put_fn,
            inner: Mutex::new(Inner {
                buf: Vec::new(),
                oldest: None,
                accepted: 0,
                dropped: 0,
                flushes: 0,
                put_errors: 0,
                timer_skips: 0,
            }),
            flusher: Mutex::new(None),
            stop: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    /// Start the background timer-flush thread (the Python sink's
    /// `_flush_loop`): every `cfg.flush_seconds` it drains a non-empty
    /// buffer whose oldest event has aged past `cfg.flush_max_age_seconds`
    /// (`0` = drain on every tick). Without it a below-`batch_size` buffer
    /// never ships until shutdown (caver-collector#901).
    ///
    /// Holds only a `Weak` to the sink, so dropping the last `Arc` ends the
    /// thread; [`Self::stop_flusher`] (or `Drop`) joins it promptly. Idempotent.
    pub fn start_flusher(self: &Arc<Self>) {
        let mut g = self.flusher.lock().unwrap();
        if g.is_some() {
            return;
        }
        // A fresh start after a stop must not see the old stop flag.
        *self.stop.0.lock().unwrap() = false;
        let weak = Arc::downgrade(self);
        let stop = Arc::clone(&self.stop);
        let tick = Duration::from_secs(self.cfg.flush_seconds.max(1));
        *g = Some(
            std::thread::Builder::new()
                .name("caver-parquet-flush".into())
                .spawn(move || {
                    let (lock, cvar) = &*stop;
                    let mut stopped = lock.lock().unwrap();
                    while !*stopped {
                        let (guard, timeout) = cvar.wait_timeout(stopped, tick).unwrap();
                        stopped = guard;
                        if *stopped {
                            return;
                        }
                        if timeout.timed_out() {
                            // Release the stop lock during the flush (a PUT
                            // can block for the full retry deadline) so
                            // stop_flusher() is never blocked on it.
                            drop(stopped);
                            let Some(sink) = weak.upgrade() else { return };
                            // Known divergence from Python's try/except
                            // _flush_loop: a panic in flush() would kill
                            // this thread for the life of the process. The
                            // prod flush path has no panicking call today
                            // (transport/writer unwraps are test-only);
                            // accepted rather than papered over with
                            // catch_unwind.
                            sink.flush_if_aged();
                            drop(sink);
                            stopped = lock.lock().unwrap();
                        }
                    }
                })
                .expect("spawn caver-parquet-flush thread"),
        );
    }

    /// Signal and join the timer-flush thread. Does NOT drain the buffer —
    /// callers (and the Vector sink's shutdown path) follow with
    /// [`Self::flush`]. Safe to call without a prior
    /// [`Self::start_flusher`]; idempotent.
    pub fn stop_flusher(&self) {
        {
            let (lock, cvar) = &*self.stop;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        // Bind the guard explicitly: holding the handle lock across the
        // join is what stops start_flusher() from resetting the stop flag
        // while an old thread is still alive.
        let mut flusher = self.flusher.lock().unwrap();
        if let Some(handle) = flusher.take() {
            // Self-join guard: the flusher holds a strong Arc for the
            // duration of each tick's flush (between `upgrade` and `drop`),
            // so it can end up running the FINAL Arc drop — then `Drop`
            // calls stop_flusher() on the flusher thread itself, and
            // joining would panic (pthread EDEADLK). The thread is already
            // on its way out (it re-checks the stop flag, set above, right
            // after dropping its Arc): detach instead.
            if handle.thread().id() == std::thread::current().id() {
                return;
            }
            // The thread may be mid-flush; the join is bounded by the
            // transport's put_deadline_ms.
            let _ = handle.join();
        }
    }

    /// Timer-tick body: drain the buffer only if it is non-empty and its
    /// oldest event has aged past the freshness backstop
    /// (caver-collector#888 semantics; `flush_max_age_seconds == 0` =
    /// drain on every tick).
    fn flush_if_aged(&self) {
        let aged = {
            let mut g = self.inner.lock().unwrap();
            if g.buf.is_empty() {
                return;
            }
            let aged = self.cfg.flush_max_age_seconds == 0
                || g.oldest.is_none_or(|t| {
                    t.elapsed() >= Duration::from_secs(self.cfg.flush_max_age_seconds)
                });
            if !aged {
                g.timer_skips += 1;
            }
            aged
        };
        if aged {
            self.flush();
        }
    }

    /// Accept an event (flat string map).
    /// Flushes when the batch reaches `cfg.batch_size`.
    pub fn send(&self, event: HashMap<String, String>) {
        let should_flush = {
            let mut g = self.inner.lock().unwrap();
            if g.buf.is_empty() {
                g.oldest = Some(Instant::now());
            }
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
            g.oldest = None;
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
                // class_uid is event-derived: a `/` or `..` here would break
                // the SigV4 canonical path and 403 (→ DLQ) the whole batch,
                // so key-unsafe values fall back like missing ones
                // (caver-collector#898 item 4).
                let class_uid = batch[0]
                    .get(&self.cfg.class_uid_field)
                    .map(|s| s.as_str())
                    .filter(|s| key_safe(s))
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
            ("timer_skips".into(), g.timer_skips),
        ])
    }

    /// Row-shape note for replay tooling: in `CaverStaging` layout the DLQ
    /// ndjson rows are POST-prep (`staging_row` applied: string-typed
    /// `_time`, injected `index`/`class_uid` defaults), while `Native` rows
    /// are the raw accepted maps. Matches the Python sink; anything replaying
    /// a DLQ must handle both shapes (caver-collector#899 item 5).
    ///
    /// Alongside each `dlq-*.ndjson` a same-stem `.reason` sidecar records
    /// why the batch landed here (`put: …` / `serialize: …`) so triage
    /// doesn't have to correlate timestamps with collector logs
    /// (caver-collector#898 item 5). Kept out of the ndjson itself so replay
    /// tooling streams pure rows.
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
        let _ = std::fs::write(dlq.join(format!("dlq-{stamp}-{id}.reason")), reason);
    }
}

impl Drop for ParquetSink {
    fn drop(&mut self) {
        // The flusher holds only a `Weak`, so it cannot keep the sink alive;
        // join it anyway so a dropped sink never leaves a stray timer thread.
        // No drain here — shutdown paths call `stop_flusher()` + `flush()`
        // explicitly; a blocking PUT inside `Drop` would be a surprise.
        self.stop_flusher();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[test]
    fn flush_on_batch_size() {
        #[allow(clippy::type_complexity)] // test capture buffer
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

    /// Poll `cond` until true or the deadline passes. Generous deadline +
    /// condition polling keeps timer tests schedule-independent (the PR #21
    /// flaky-test lesson: never race real timing against tight margins).
    fn wait_for(deadline: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        cond()
    }

    #[test]
    fn timer_flush_ships_below_batch_buffer() {
        let puts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let p2 = Arc::clone(&puts);
        let put: PutFn = Arc::new(move |_b, _k, _body| {
            p2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        let cfg = Config {
            batch_size: 100,
            flush_seconds: 1,
            // 0 = drain on every tick: the flush must come from the timer
            // alone, with no age wait to race against.
            flush_max_age_seconds: 0,
            ..Config::default()
        };
        let sink = Arc::new(ParquetSink::new(cfg, Some(put)));
        sink.send(HashMap::from([("class_uid".into(), "2003".into())]));
        sink.start_flusher();
        assert!(
            wait_for(Duration::from_secs(30), || {
                puts.load(std::sync::atomic::Ordering::SeqCst) >= 1
            }),
            "timer flush never shipped the below-batch buffer"
        );
        sink.stop_flusher();
        assert_eq!(sink.stats()["flushes"], 1);
    }

    #[test]
    fn timer_skips_below_age_buffer() {
        let puts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let p2 = Arc::clone(&puts);
        let put: PutFn = Arc::new(move |_b, _k, _body| {
            p2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        let cfg = Config {
            batch_size: 100,
            flush_seconds: 1,
            // An age no test run can reach: every tick must skip, under any
            // scheduling.
            flush_max_age_seconds: 3600,
            ..Config::default()
        };
        let sink = Arc::new(ParquetSink::new(cfg, Some(put)));
        sink.send(HashMap::from([("class_uid".into(), "2003".into())]));
        sink.start_flusher();
        assert!(
            wait_for(Duration::from_secs(30), || {
                sink.stats()["timer_skips"] >= 1
            }),
            "timer never ticked over the below-age buffer"
        );
        sink.stop_flusher();
        assert_eq!(
            puts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "below-age buffer must not ship on the timer path"
        );
        // The backstop never blocks the explicit drain.
        sink.flush();
        assert_eq!(puts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn aged_buffer_ships_on_tick() {
        let puts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let p2 = Arc::clone(&puts);
        let put: PutFn = Arc::new(move |_b, _k, _body| {
            p2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        let cfg = Config {
            batch_size: 100,
            flush_seconds: 1,
            flush_max_age_seconds: 1,
            ..Config::default()
        };
        let sink = Arc::new(ParquetSink::new(cfg, Some(put)));
        sink.send(HashMap::from([("class_uid".into(), "2003".into())]));
        sink.start_flusher();
        // Eventually-aged is schedule-independent: ticks keep coming and
        // age only grows, so the drain must happen within the deadline.
        assert!(
            wait_for(Duration::from_secs(30), || {
                puts.load(std::sync::atomic::Ordering::SeqCst) >= 1
            }),
            "aged buffer never shipped"
        );
        sink.stop_flusher();
    }

    #[test]
    fn stop_flusher_is_idempotent_and_joins() {
        let put: PutFn = Arc::new(move |_b, _k, _body| Ok(()));
        let cfg = Config {
            flush_seconds: 1,
            ..Config::default()
        };
        let sink = Arc::new(ParquetSink::new(cfg, Some(put)));
        sink.stop_flusher(); // no-op without a start
        sink.start_flusher();
        sink.start_flusher(); // idempotent
        sink.stop_flusher();
        sink.stop_flusher();
        assert!(
            sink.flusher.lock().unwrap().is_none(),
            "flusher thread joined"
        );
        // Restart after stop works (the stop flag is reset).
        sink.start_flusher();
        assert!(sink.flusher.lock().unwrap().is_some());
        sink.stop_flusher();
    }

    /// Regression (PR #22 review): the flusher holds a strong `Arc` for the
    /// duration of each tick's flush, so it can end up running the FINAL
    /// `Arc` drop — `Drop` then calls `stop_flusher()` on the flusher
    /// thread itself, which must detach rather than self-join (a self-join
    /// is a pthread EDEADLK → panic inside `Drop`). The panic hook counts
    /// panics on the named flusher thread; the marker `Arc` proves the sink
    /// (and its captured `put_fn`) was fully dropped.
    #[test]
    fn final_arc_drop_on_flusher_thread_detaches_instead_of_self_joining() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        static FLUSHER_PANICS: AtomicUsize = AtomicUsize::new(0);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if std::thread::current().name() == Some("caver-parquet-flush") {
                FLUSHER_PANICS.fetch_add(1, Ordering::SeqCst);
            }
            prev(info);
        }));

        // `entered` flips once the flusher is mid-PUT (holding its upgraded
        // strong Arc); `release` then lets the PUT finish.
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let marker = Arc::new(());
        let (e2, r2, m2) = (
            Arc::clone(&entered),
            Arc::clone(&release),
            Arc::clone(&marker),
        );
        let put: PutFn = Arc::new(move |_b, _k, _body| {
            let _held_until_sink_drop = &m2;
            e2.store(true, Ordering::SeqCst);
            let (lock, cvar) = &*r2;
            let mut go = lock.lock().unwrap();
            while !*go {
                go = cvar.wait(go).unwrap();
            }
            Ok(())
        });
        let cfg = Config {
            batch_size: 100,
            flush_seconds: 1,
            flush_max_age_seconds: 0,
            ..Config::default()
        };
        let sink = Arc::new(ParquetSink::new(cfg, Some(put)));
        sink.send(HashMap::from([("class_uid".into(), "2003".into())]));
        sink.start_flusher();
        assert!(
            wait_for(Duration::from_secs(30), || entered.load(Ordering::SeqCst)),
            "flusher never reached the PUT"
        );
        // The flusher's upgraded Arc is now the co-owner; make it the last.
        drop(sink);
        {
            let (lock, cvar) = &*release;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        // Fully dropped (the put_fn released the marker) and no panic on
        // the flusher thread.
        assert!(
            wait_for(Duration::from_secs(30), || Arc::strong_count(&marker) == 1),
            "sink was never dropped — flusher likely wedged"
        );
        assert_eq!(
            FLUSHER_PANICS.load(Ordering::SeqCst),
            0,
            "self-join panic in Drop"
        );
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
        #[allow(clippy::type_complexity)] // test capture buffer
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

        // Key-unsafe candidates fall through the chain like empty ones — a
        // corrupted hostname (garbage non-ASCII bytes, seen in the wild) or a
        // slash must never reach the staging key path.
        let cfg = Config {
            source: Some("bad/segment".into()),
            sensor_id: "Matt\u{2019}s-box".into(),
            ..Config::default()
        };
        assert_eq!(ParquetSink::new(cfg, None).source_name, "collector");
    }

    #[test]
    fn contract_enforced_in_new_for_direct_consumers() {
        // writer_name must start with a letter and be key-safe (the
        // compactor's PARQUET-CONTRACT filename regex); staging_prefix is
        // trimmed and each segment validated. The Vector config layer rejects
        // these loudly at boot; the crate sanitizes with the defaults.
        let cfg = Config {
            writer_name: "9starts-with-digit".into(),
            staging_prefix: "/uf/ocsf/".into(),
            ..Config::default()
        };
        let sink = ParquetSink::new(cfg, None);
        assert_eq!(sink.cfg.writer_name, "collector");
        assert_eq!(sink.cfg.staging_prefix, "uf/ocsf", "slashes trimmed");

        let cfg = Config {
            writer_name: "agent".into(),
            staging_prefix: "uf//ocsf".into(), // empty middle segment
            ..Config::default()
        };
        let sink = ParquetSink::new(cfg, None);
        assert_eq!(sink.cfg.writer_name, "agent", "valid name kept");
        assert_eq!(sink.cfg.staging_prefix, "uf/ocsf", "bad prefix -> default");
    }

    #[test]
    fn key_safe_charset() {
        assert!(key_safe("edge-01.local_x"));
        assert!(!key_safe(""));
        assert!(!key_safe("a b"));
        assert!(!key_safe("a/b"));
        assert!(!key_safe(".."));
        assert!(!key_safe("naïve"));
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
            .map(|e| e.path())
            .collect();
        assert_eq!(
            dlq_files.len(),
            2,
            "ndjson + reason sidecar for the failed batch"
        );
        let ndjson = dlq_files
            .iter()
            .find(|p| p.extension().is_some_and(|e| e == "ndjson"))
            .expect("ndjson file present");
        let body = std::fs::read_to_string(ndjson).unwrap();
        assert_eq!(body.lines().count(), 2, "both events preserved as ndjson");
        let reason_path = dlq_files
            .iter()
            .find(|p| p.extension().is_some_and(|e| e == "reason"))
            .expect("reason sidecar present");
        assert_eq!(
            reason_path.file_stem(),
            ndjson.file_stem(),
            "sidecar shares the ndjson stem"
        );
        let reason = std::fs::read_to_string(reason_path).unwrap();
        assert!(
            reason.starts_with("put: ") && reason.contains("connection refused"),
            "reason records why: {reason}"
        );
        std::fs::remove_dir_all(&dlq).ok();
    }

    #[test]
    fn native_layout_sanitizes_partition_values() {
        let captured: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let cap2 = captured.clone();
        let put: PutFn = Arc::new(move |_b, key: &str, _body| {
            cap2.lock().unwrap().push(key.into());
            Ok(())
        });

        // Key-unsafe sensor_id falls back in new(); event-derived class_uid
        // with a slash falls back to DEFAULT_CLASS_UID in flush().
        let cfg = Config {
            batch_size: 1,
            layout: Layout::Native,
            sensor_id: "Matt\u{2019}s-box".into(),
            ..Config::default()
        };
        let sink = ParquetSink::new(cfg, Some(put.clone()));
        assert_eq!(sink.cfg.sensor_id, "collector", "unsafe sensor_id replaced");
        sink.send(HashMap::from([("class_uid".into(), "../2003/evil".into())]));

        // Safe values pass through untouched.
        let cfg = Config {
            batch_size: 1,
            layout: Layout::Native,
            sensor_id: "edge-01".into(),
            ..Config::default()
        };
        let sink = ParquetSink::new(cfg, Some(put));
        assert_eq!(sink.cfg.sensor_id, "edge-01");
        sink.send(HashMap::from([("class_uid".into(), "2003".into())]));

        let keys = captured.lock().unwrap();
        assert_eq!(keys.len(), 2);
        assert!(
            keys[0].starts_with("0000/") && keys[0].contains("/sensor=collector/"),
            "unsafe values sanitized: {}",
            keys[0]
        );
        assert!(
            keys[1].starts_with("2003/") && keys[1].contains("/sensor=edge-01/"),
            "safe values kept: {}",
            keys[1]
        );
    }
}
