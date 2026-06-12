use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use futures::{StreamExt, stream::BoxStream};
use vector_lib::{
    EstimatedJsonEncodedSizeOf,
    internal_event::{CountByteSize, EventsSent, InternalEventHandle as _, Output},
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
/// Vector's acknowledgement machinery.
pub struct CaverParquetSink {
    parquet: Arc<caver_sink_parquet::ParquetSink>,
}

impl CaverParquetSink {
    pub const fn new(parquet: Arc<caver_sink_parquet::ParquetSink>) -> Self {
        Self { parquet }
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
                    Event::Log(log) => log.all_event_fields().map(|fields| {
                        fields
                            .map(|(k, v)| (k.to_string(), value_to_string(v)))
                            .collect()
                    }),
                    _ => None,
                })
                .collect();

            let parquet = Arc::clone(&self.parquet);
            let accepted = tokio::task::spawn_blocking(move || {
                for row in rows {
                    // May trigger a blocking flush (Parquet encode + signed PUT
                    // with up to ~30s retry backoff) when the batch fills.
                    parquet.send(row);
                }
            })
            .await;

            match accepted {
                Ok(()) => {
                    finalizers.update_status(EventStatus::Delivered);
                    events_sent.emit(CountByteSize(count, byte_size));
                }
                // The blocking task panicked; don't claim delivery.
                Err(_) => finalizers.update_status(EventStatus::Errored),
            }
        }

        // Flush any partial batch on shutdown so a clean stop loses nothing.
        let parquet = Arc::clone(&self.parquet);
        _ = tokio::task::spawn_blocking(move || parquet.flush()).await;

        Ok(())
    }
}
