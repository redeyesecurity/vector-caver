//! Operational helpers for caver-collector deployments.
//!
//! Tracked: caver-collector#74
//!
//! # Modules
//!
//! - `tls`: mTLS enforcement — rejects plaintext sink/source URLs when policy
//!   requires encrypted transport.
//! - `reload`: config-reload monitoring — validates a Vector config file and
//!   emits a structured reload event (pass/fail) for the caller to log or alert.
//! - `opamp`: OPAMP agent-registration stub — carries agent identity and labels
//!   for eventual wire-up to the RES fleet UI.

pub mod tls;
pub mod reload;
pub mod opamp;
