use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use futures::{StreamExt, stream::BoxStream};
use vector_lib::{
    EstimatedJsonEncodedSizeOf,
    internal_event::{
        ComponentEventsDropped, CountByteSize, EventsSent, InternalEventHandle as _, Output,
        UNINTENTIONAL,
    },
};

use crate::{
    event::{Event, EventArray, EventContainer, EventStatus, Finalizable, Value},
    sinks::util::StreamSink,
};

/// Stream adapter over [`caver_sink_parquet::ParquetSink`].
///
/// The inner sink is synchronous (batching, Parquet encoding, and the signed
/// S3 PUT with retry backoff all block), so every interaction with it runs
/// under [`tokio::task::spawn_blocking`] — a slow or unreachable object store
/// must never stall the async topology (caver-collector#894).
///
/// Acknowledgement semantics: events are marked `Delivered` once accepted by
/// the inner batcher. A later PUT failure is handled inside the crate (batch
/// to the DLQ as ndjson, `dropped`/`put_errors` stats), not by re-driving
/// Vector's acknowledgement machinery. Those failures ARE surfaced here:
/// after every blocking call the crate's failure counters are diffed and any
/// increment is logged at error level and emitted as
/// `ComponentEventsDropped` (`component_discarded_events_total`).
pub struct CaverParquetSink {
    parquet: Arc<caver_sink_parquet::ParquetSink>,
    /// Whether the inner sink writes failed batches to a DLQ (drives the
    /// failure log's "recoverable or gone" wording).
    dlq_enabled: bool,
    /// Whether the inner sink writes the caver_staging layout: Vector log
    /// conventions (`timestamp`, `message`) are aliased onto the contract's
    /// `_time`/`_raw` columns so event time and raw payload survive.
    staging: bool,
}

impl CaverParquetSink {
    pub const fn new(
        parquet: Arc<caver_sink_parquet::ParquetSink>,
        dlq_enabled: bool,
        staging: bool,
    ) -> Self {
        Self {
            parquet,
            dlq_enabled,
            staging,
        }
    }
}

/// Render a flattened event value as the flat string the lake schema expects.
fn value_to_string(value: &Value) -> String {
    match value {
        Value::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        Value::Timestamp(ts) => ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        other => other.to_string(),
    }
}

/// Alias Vector log conventions onto the caver_staging contract columns,
/// without clobbering values the pipeline set explicitly:
/// `timestamp` (RFC 3339, the flattened form of `Value::Timestamp`) → `_time`
/// (epoch seconds), `message` → `_raw`. Anything still missing afterwards is
/// defaulted by the crate's row prep (`_time` → now, `_raw` → `""`).
fn alias_staging_fields(row: &mut HashMap<String, String>) {
    if !row.contains_key("_time") {
        if let Some(ts) = row
            .get("timestamp")
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        {
            row.insert(
                "_time".to_string(),
                format!("{:.6}", ts.timestamp_micros() as f64 / 1e6),
            );
        }
    }
    if !row.contains_key("_raw") {
        if let Some(msg) = row.get("message") {
            row.insert("_raw".to_string(), msg.clone());
        }
    }
}

/// Snapshot the inner sink's failure counters (`dropped` events, `put_errors`).
fn failure_counters(parquet: &caver_sink_parquet::ParquetSink) -> (u64, u64) {
    let stats = parquet.stats();
    (
        stats.get("dropped").copied().unwrap_or(0),
        stats.get("put_errors").copied().unwrap_or(0),
    )
}

/// Surface inner-sink flush failures: events are already acked `Delivered`
/// (accept-time ack contract), so a silent counter bump would otherwise look
/// like a healthy pipeline while data is lost.
fn report_flush_failures(dropped: u64, put_errors: u64, dlq_enabled: bool) {
    if dropped == 0 && put_errors == 0 {
        return;
    }
    error!(
        message = "Caver lake flush failed.",
        dropped_events = dropped,
        put_errors = put_errors,
        dlq_enabled,
        recoverable = dlq_enabled,
    );
    if dropped > 0 {
        emit!(ComponentEventsDropped::<UNINTENTIONAL> {
            count: dropped as usize,
            reason: "Parquet encode or object-store PUT failed; batch went to the DLQ if `dlq_path` is set, otherwise it is gone.",
        });
    }
}

#[async_trait]
impl StreamSink<EventArray> for CaverParquetSink {
    async fn run(self: Box<Self>, mut input: BoxStream<'_, EventArray>) -> Result<(), ()> {
        let events_sent = register!(EventsSent::from(Output(None)));

        while let Some(mut events) = input.next().await {
            let finalizers = events.take_finalizers();
            let byte_size = events.estimated_json_encoded_size_of();
            let count = events.len();

            // Flatten each log to dotted-key string rows (the lake contract).
            let rows: Vec<HashMap<String, String>> = events
                .into_events()
                .filter_map(|event| match event {
                    Event::Log(log) => Some(match log.all_event_fields() {
                        Some(fields) => fields
                            .map(|(k, v)| (k.to_string(), value_to_string(v)))
                            .collect(),
                        // A log whose root isn't an object (e.g. a scalar from
                        // a raw codec) still ships, keyed as `message`.
                        None => {
                            HashMap::from([("message".to_string(), value_to_string(log.value()))])
                        }
                    }),
                    // Unreachable in practice: `Input::log()` means the
                    // topology never hands this sink a metric/trace array.
                    _ => None,
                })
                .map(|mut row: HashMap<String, String>| {
                    if self.staging {
                        alias_staging_fields(&mut row);
                    }
                    row
                })
                .collect();

            let parquet = Arc::clone(&self.parquet);
            let accepted = tokio::task::spawn_blocking(move || {
                let before = failure_counters(&parquet);
                for row in rows {
                    // May trigger a blocking flush (Parquet encode + signed PUT
                    // with up to ~30s retry backoff) when the batch fills.
                    parquet.send(row);
                }
                let after = failure_counters(&parquet);
                (
                    after.0.saturating_sub(before.0),
                    after.1.saturating_sub(before.1),
                )
            })
            .await;

            match accepted {
                Ok((dropped, put_errors)) => {
                    finalizers.update_status(EventStatus::Delivered);
                    events_sent.emit(CountByteSize(count, byte_size));
                    report_flush_failures(dropped, put_errors, self.dlq_enabled);
                }
                // The blocking task panicked; don't claim delivery.
                Err(join_error) => {
                    error!(message = "Caver lake send task panicked.", %join_error);
                    finalizers.update_status(EventStatus::Errored);
                }
            }
        }

        // Flush any partial batch on shutdown so a clean stop loses nothing.
        let parquet = Arc::clone(&self.parquet);
        match tokio::task::spawn_blocking(move || {
            let before = failure_counters(&parquet);
            parquet.flush();
            let after = failure_counters(&parquet);
            (
                after.0.saturating_sub(before.0),
                after.1.saturating_sub(before.1),
            )
        })
        .await
        {
            Ok((dropped, put_errors)) => {
                report_flush_failures(dropped, put_errors, self.dlq_enabled)
            }
            Err(join_error) => {
                error!(message = "Caver lake final flush task panicked.", %join_error)
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::event::{BatchNotifier, BatchStatus, LogEvent};

    /// Drives `run()` end-to-end with an injected `PutFn`: asserts the
    /// accept-time-ack contract (batch acked `Delivered`) and that a full
    /// batch produced exactly one correctly partitioned PUT.
    #[tokio::test]
    async fn delivers_batch_and_puts_partitioned_object() {
        let captured: Arc<Mutex<Vec<(String, String, usize)>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = Arc::clone(&captured);
        let put_fn: caver_sink_parquet::PutFn =
            Arc::new(move |bucket: &str, key: &str, bytes: Vec<u8>| {
                cap.lock()
                    .unwrap()
                    .push((bucket.to_string(), key.to_string(), bytes.len()));
                Ok(())
            });

        let cfg = caver_sink_parquet::Config {
            bucket: "test-bucket".into(),
            sensor_id: "test-sensor".into(),
            batch_size: 2,
            layout: caver_sink_parquet::Layout::Native,
            ..Default::default()
        };
        let parquet = Arc::new(caver_sink_parquet::ParquetSink::new(cfg, Some(put_fn)));
        let sink = Box::new(CaverParquetSink::new(parquet, false, false));

        let (batch, mut receiver) = BatchNotifier::new_with_receiver();
        let mut log = LogEvent::default();
        log.insert("class_uid", "4002");
        log.insert("message", "hello lake");
        let log = log.with_batch_notifier(&batch);
        drop(batch);
        let input = futures::stream::iter(vec![EventArray::Logs(vec![log.clone(), log])]);

        sink.run(Box::pin(input)).await.unwrap();

        assert_eq!(receiver.try_recv(), Ok(BatchStatus::Delivered));
        let puts = captured.lock().unwrap();
        assert_eq!(puts.len(), 1, "one full batch must produce exactly one PUT");
        let (bucket, key, size) = &puts[0];
        assert_eq!(bucket, "test-bucket");
        assert!(
            key.starts_with("4002/dt=") && key.contains("/sensor=test-sensor/"),
            "lake partition layout violated: {key}"
        );
        assert!(*size > 0, "empty parquet object");
    }

    /// Staging default end-to-end: the PUT lands under the caver_staging key
    /// layout, partitioned by the event's `timestamp` (aliased to `_time`).
    #[tokio::test]
    async fn staging_layout_puts_contract_key_from_event_timestamp() {
        let captured: Arc<Mutex<Vec<(String, String, usize)>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = Arc::clone(&captured);
        let put_fn: caver_sink_parquet::PutFn =
            Arc::new(move |bucket: &str, key: &str, bytes: Vec<u8>| {
                cap.lock()
                    .unwrap()
                    .push((bucket.to_string(), key.to_string(), bytes.len()));
                Ok(())
            });

        let cfg = caver_sink_parquet::Config {
            bucket: "test-bucket".into(),
            sensor_id: "test-sensor".into(),
            batch_size: 1,
            ..Default::default()
        };
        assert_eq!(
            cfg.layout,
            caver_sink_parquet::Layout::CaverStaging,
            "staging is the crate default"
        );
        let parquet = Arc::new(caver_sink_parquet::ParquetSink::new(cfg, Some(put_fn)));
        let sink = Box::new(CaverParquetSink::new(parquet, false, true));

        let (batch, mut receiver) = BatchNotifier::new_with_receiver();
        let mut log = LogEvent::default();
        log.insert("class_uid", "4002");
        log.insert("message", "hello lake");
        // 2026-06-12 15:04:05 UTC — flattened by `value_to_string` to RFC 3339,
        // then aliased to `_time` and used for the year=/month=/day= partition.
        log.insert(
            "timestamp",
            Value::Timestamp(chrono::DateTime::from_timestamp(1781276645, 0).unwrap()),
        );
        let log = log.with_batch_notifier(&batch);
        drop(batch);
        let input = futures::stream::iter(vec![EventArray::Logs(vec![log])]);

        sink.run(Box::pin(input)).await.unwrap();

        assert_eq!(receiver.try_recv(), Ok(BatchStatus::Delivered));
        let puts = captured.lock().unwrap();
        assert_eq!(puts.len(), 1);
        let (_, key, size) = &puts[0];
        assert!(
            key.starts_with(
                "uf/ocsf/test-sensor/year=2026/month=06/day=12/collector_20260612_150405_"
            ) && key.ends_with(".parquet"),
            "caver_staging contract key violated: {key}"
        );
        assert!(*size > 0, "empty parquet object");
    }

    #[test]
    fn alias_staging_fields_maps_vector_conventions() {
        // timestamp -> _time, message -> _raw.
        let mut row = HashMap::from([
            (
                "timestamp".to_string(),
                "2026-06-12T15:04:05.250Z".to_string(),
            ),
            ("message".to_string(), "raw line".to_string()),
        ]);
        alias_staging_fields(&mut row);
        assert_eq!(row["_time"], "1781276645.250000");
        assert_eq!(row["_raw"], "raw line");

        // Explicit `_time`/`_raw` win over the aliases.
        let mut row = HashMap::from([
            ("timestamp".to_string(), "2026-06-12T15:04:05Z".to_string()),
            ("_time".to_string(), "1700000000.0".to_string()),
            ("message".to_string(), "msg".to_string()),
            ("_raw".to_string(), "original raw".to_string()),
        ]);
        alias_staging_fields(&mut row);
        assert_eq!(row["_time"], "1700000000.0");
        assert_eq!(row["_raw"], "original raw");

        // Unparseable timestamp: leave it to the crate's now-default.
        let mut row = HashMap::from([("timestamp".to_string(), "not-a-date".to_string())]);
        alias_staging_fields(&mut row);
        assert!(!row.contains_key("_time"));
    }
}
