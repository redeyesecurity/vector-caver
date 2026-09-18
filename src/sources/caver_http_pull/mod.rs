//! `caver_http_pull` source: a stateful HTTP pull that stock `http_client`
//! cannot be, backed by the `caver-source-http-pull` crate
//! (`caver/crates/caver-source-http-pull`).
//!
//! Adds three things over the scheduled `http_client` scrape: OAuth2
//! client-credentials auth with refresh-before-expiry, a cursor/`nextLink`
//! checkpoint carried across polls, and response-array extraction via a JSON
//! pointer. Mirrors the `caver_parquet` sink's crate+wrapper split.

mod config;

pub use config::CaverHttpPullConfig;
