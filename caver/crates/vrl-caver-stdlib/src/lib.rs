//! VRL stdlib extensions for caver-collector.
//!
//! - caver-collector#63: OCSF normalization + classification functions
//! - caver-collector#64: ATT\&CK + CVE + threat-intel functions
//! - caver-collector#65: security parser functions

pub mod ocsf;
pub mod parsers;
pub mod threat_intel;
pub mod vrl_fns;

/// Re-export the VRL function registry at the crate root so downstream crates
/// (e.g. `vector-vrl-functions` under its `caver` feature) can call
/// `vrl_caver_stdlib::vrl_functions()`.
pub use vrl_fns::vrl_functions;
