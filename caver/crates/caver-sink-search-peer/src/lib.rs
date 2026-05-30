//! `caver_search_peer` sink — pushes OCSF events to RES-splunk-caver via
//! its HEC-compatible endpoint (`POST /services/collector`).
//!
//! Tracked: caver-collector#72
//!
//! # Protocol
//!
//! RES-splunk-caver exposes the Splunk HEC API at `/services/collector`.
//! This sink batches Vector events into newline-delimited HEC JSON and POSTs
//! them in one request per batch.  Each event is wrapped as:
//!
//! ```json
//! {"event": <original_json>, "sourcetype": "ocsf", "time": <unix_seconds>}
//! ```
//!
//! Authentication uses `Authorization: Splunk <token>`.  The token is resolved
//! at runtime from the environment variable named by `Config::token_env`.
//!
//! # Usage
//!
//! ```no_run
//! use caver_sink_search_peer::{Config, Client};
//! use serde_json::json;
//!
//! let cfg = Config {
//!     url: "http://caver:8088".into(),
//!     token_env: "CAVER_HEC_TOKEN".into(),
//!     batch_size: 100,
//!     timeout_ms: 5_000,
//! };
//! let client = Client::from_config(&cfg).unwrap();
//! let events = vec![json!({"class_uid": 4002, "time": 1_700_000_000u64})];
//! client.push_batch(&events).unwrap();
//! ```

pub mod client;
pub mod error;
pub mod format;

pub use client::Client;
pub use error::PushError;

/// Sink configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of RES-splunk-caver, e.g. `http://caver:8088`.
    /// The sink appends `/services/collector` automatically.
    pub url: String,

    /// Name of the environment variable holding the HEC token.
    /// Resolved at `Client::from_config` time so that the value is never
    /// stored in the `Config` struct.
    pub token_env: String,

    /// Maximum number of events to include in a single POST.
    pub batch_size: usize,

    /// HTTP request timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: "http://localhost:8088".into(),
            token_env: "CAVER_HEC_TOKEN".into(),
            batch_size: 500,
            timeout_ms: 10_000,
        }
    }
}
