//! OTTL extension functions for caver-collector (caver-collector#86).
//!
//! Modules:
//!   `hmac`   — HMAC-SHA256 (pure Rust, no external crypto crates)
//!   `enrich` — enrichment table lookup (JSON sidecar → field expansion)
//!   `ocsf`   — OCSF field validation + required-field checks per class_uid

pub mod enrich;
pub mod hmac;
pub mod ocsf;
