//! Central location for all VRL functions used in Vector.
//!
//! This crate provides a single source of truth for the complete set of VRL functions
//! available throughout Vector, combining:
//! - Standard VRL library functions (`vrl::stdlib::all`)
//! - Vector-specific functions (`vector_vrl::secret_functions`)
//! - Enrichment table functions (`enrichment::vrl_functions`)
//! - Caver OCSF/parser/threat-intel functions (`vector_vrl_caver_stdlib::all`)
//! - DNS tap parsing functions (optional, with `dnstap` feature)

#![deny(warnings)]

use vrl::{compiler::Function, path::OwnedTargetPath};

pub mod get_secret;
pub mod remove_secret;
pub mod set_secret;
pub mod set_semantic_meaning;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum MetadataKey {
    Legacy(String),
    Query(OwnedTargetPath),
}

pub const LEGACY_METADATA_KEYS: [&str; 2] = ["datadog_api_key", "splunk_hec_token"];

/// Returns Vector-specific secret functions.
pub fn secret_functions() -> Vec<Box<dyn Function>> {
    vec![
        Box::new(set_semantic_meaning::SetSemanticMeaning) as _,
        Box::new(get_secret::GetSecret) as _,
        Box::new(remove_secret::RemoveSecret) as _,
        Box::new(set_secret::SetSecret) as _,
    ]
}

/// Returns all VRL functions available in Vector.
#[allow(clippy::disallowed_methods)]
pub fn all() -> Vec<Box<dyn Function>> {
    let functions = iter_all_without_vrl_stdlib().chain(vrl::stdlib::all());
    functions.collect()
}

/// Returns all VRL functions available only in Vector.
pub fn all_without_vrl_stdlib() -> Vec<Box<dyn Function>> {
    let functions = iter_all_without_vrl_stdlib();
    functions.collect()
}

fn iter_all_without_vrl_stdlib() -> impl Iterator<Item = Box<dyn Function>> {
    let functions = secret_functions()
        .into_iter()
        .chain(enrichment::vrl_functions())
        // Caver OCSF/parser/threat-intel functions (caver-collector#904) —
        // default-on: the OCSF VRL framework ships in the lean default
        // binary (caver-collector#890), vendor normalizer apps do not.
        .chain(vector_vrl_caver_stdlib::all());

    #[cfg(feature = "dnstap")]
    let functions = functions.chain(dnstap_parser::vrl_functions());

    #[cfg(feature = "vrl-metrics")]
    let functions = functions.chain(vector_vrl_metrics::all());

    functions
}

#[cfg(test)]
mod tests {
    /// The Caver OCSF VRL framework must be reachable from every consumer of
    /// `all()` — remap, conditions, `vector vrl` (caver-collector#904).
    #[test]
    fn caver_functions_are_registered() {
        let functions = super::all();
        for identifier in ["ocsf_classify", "ocsf_normalize", "parse_suricata_eve"] {
            assert!(
                functions.iter().any(|f| f.identifier() == identifier),
                "{identifier} missing from vector_vrl_functions::all()"
            );
        }
    }

    /// Registering two functions under one identifier would make resolution
    /// ambiguous; catch it at the aggregation point, where every source of
    /// functions is visible.
    #[test]
    fn no_duplicate_identifiers() {
        let functions = super::all();
        let mut identifiers: Vec<&str> = functions.iter().map(|f| f.identifier()).collect();
        identifiers.sort_unstable();
        let before = identifiers.len();
        identifiers.dedup();
        assert_eq!(
            before,
            identifiers.len(),
            "duplicate VRL function identifiers"
        );
    }
}
