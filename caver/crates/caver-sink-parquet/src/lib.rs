//! OCSF-partitioned Parquet sink to S3/MinIO for the caver lake.
//! Tracked: caver-collector#268

pub mod partition;
pub mod schema;
pub mod sigv4;
pub mod sink;
pub mod transport;
pub mod writer;

pub use sink::{Config, ParquetSink, PutFn};
pub use transport::{s3_put_fn, S3Config, S3Transport, TransportError};
