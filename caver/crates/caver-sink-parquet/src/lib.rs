//! `caver-sink-parquet` — OCSF-partitioned Parquet sink for the caver lake.
//!
//! Writes batches of OCSF events to S3/MinIO using the caver partition scheme:
//! `s3://<bucket>/<class_uid>/dt=YYYY-MM-DD/hour=HH/sensor=<sensor_id>/<ts>-<uuid>.parquet`
//!
//! Tracked: caver-collector#268
//!
//! # Usage
//!
//! ```no_run
//! use caver_sink_parquet::{Config, ParquetSink, PutFn};
//! use std::sync::Arc;
//! use serde_json::json;
//!
//! let cfg = Config {
//!     bucket: "caver-lake".into(),
//!     sensor_id: "edge-01".into(),
//!     batch_size: 500,
//!     flush_seconds: 30.0,
//!     ..Default::default()
//! };
//!
//! // In production, replace with an s3/MinIO put implementation.
//! let put: PutFn = Arc::new(|bucket, key, data| {
//!     println!("would PUT {}/{} ({} bytes)", bucket, key, data.len());
//!     Ok(())
//! });
//!
//! let sink = ParquetSink::new(cfg, put);
//! sink.push(json!({"class_uid": "4002", "time": 1779962400000u64})).unwrap();
//! sink.flush().unwrap();
//! ```

pub mod partition;
pub mod schema;
pub mod sink;

pub use sink::{Config, ParquetSink, PutFn, SinkError};
