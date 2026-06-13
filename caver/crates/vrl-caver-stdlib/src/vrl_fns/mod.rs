//! VRL `Function` bindings for the plain-Rust caver stdlib helpers
//! (caver-collector#906).
//!
//! The helpers in `crate::ocsf`, `crate::parsers`, `crate::threat_intel` are
//! pure Rust over `serde_json::Value`. VRL hands functions a
//! `vrl::value::Value`, so every binding follows the same three-step shape:
//!
//!   1. resolve the VRL argument and convert it: `vrl_to_json(value)`
//!   2. call the existing plain-Rust helper over `serde_json::Value`
//!   3. convert the result back: `json_to_vrl(result)`
//!
//! These conversion helpers are the single shared contract every binding in
//! this module relies on. Do not reimplement them per-function.

use vrl::compiler::Function;
use vrl::value::Value;

mod normalize;

/// All VRL functions exported by `vrl-caver-stdlib`.
///
/// The Integrate phase appends one `Box::new(...)` per binding. Keep this list
/// the single registration point.
pub fn vrl_functions() -> Vec<Box<dyn Function>> {
    vec![Box::new(normalize::OcsfNormalize) as _]
}

// ---------------------------------------------------------------------------
// Conversion helpers (vrl::value::Value <-> serde_json::Value)
//
// vrl provides `From<serde_json::Value> for Value` (infallible) and
// `TryInto<serde_json::Value> for Value` (fallible: a non-UTF-8 Bytes value
// cannot become a JSON string). We wrap both so every binding has one stable,
// named entry point and uniform error handling.
// ---------------------------------------------------------------------------

/// Convert a VRL `Value` into a `serde_json::Value`.
///
/// Infallible in practice for the inputs these helpers see, but the underlying
/// `TryInto` is fallible (non-UTF-8 byte strings), so we surface a clean error
/// string suitable for returning from `FunctionExpression::resolve`.
pub(crate) fn vrl_to_json(value: Value) -> std::result::Result<serde_json::Value, String> {
    value
        .try_into()
        .map_err(|e| format!("cannot convert VRL value to JSON: {e}"))
}

/// Convert a `serde_json::Value` back into a VRL `Value`. Infallible.
pub(crate) fn json_to_vrl(value: serde_json::Value) -> Value {
    Value::from(value)
}
