//! OCSF-partitioned Parquet sink to S3/MinIO for the caver lake.
//! Tracked: caver-collector#268

pub mod partition;
pub mod schema;
pub mod sink;
pub mod writer;

pub use sink::{Config, ParquetSink, PutFn};
