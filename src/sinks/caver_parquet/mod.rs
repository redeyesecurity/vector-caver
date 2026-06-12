//! `caver_parquet` sink: OCSF-partitioned Parquet batches to S3/MinIO for
//! the Caver lake, backed by the `caver-sink-parquet` crate
//! (`caver/crates/caver-sink-parquet`).

mod config;
mod sink;

pub use config::CaverParquetConfig;
