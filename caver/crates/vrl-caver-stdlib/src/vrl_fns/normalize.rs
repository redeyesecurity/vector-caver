//! `ocsf_normalize(event)` — VRL binding for `crate::ocsf::normalize`
//! (caver-collector#906).
//!
//! This is the CANONICAL reference binding. Every other `vrl-caver-stdlib`
//! VRL function copies this structure verbatim:
//!
//!   * a unit `struct` implementing `vrl::compiler::Function` (metadata +
//!     `compile`)
//!   * a `*Fn` struct holding the resolved argument `Box<dyn Expression>`s,
//!     implementing `FunctionExpression` (`resolve` + `type_def`)
//!   * `resolve` does: resolve arg -> `vrl_to_json` -> call plain-Rust helper
//!     -> `json_to_vrl`
//!
//! Conversions go through the shared `super::{vrl_to_json, json_to_vrl}`
//! helpers — never reimplement them here.

use std::sync::LazyLock;

use vrl::prelude::*;

use super::{json_to_vrl, vrl_to_json};

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "event",
        kind::OBJECT,
        "The raw vendor event object to normalize to OCSF.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct OcsfNormalize;

impl Function for OcsfNormalize {
    fn identifier(&self) -> &'static str {
        "ocsf_normalize"
    }

    fn usage(&self) -> &'static str {
        "Normalize a raw vendor `event` object into a fully-formed OCSF object."
    }

    fn category(&self) -> &'static str {
        Category::Convert.as_ref()
    }

    fn return_kind(&self) -> u16 {
        kind::OBJECT
    }

    fn parameters(&self) -> &'static [Parameter] {
        &PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let event = arguments.required("event");
        Ok(OcsfNormalizeFn { event }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct OcsfNormalizeFn {
    event: Box<dyn Expression>,
}

impl FunctionExpression for OcsfNormalizeFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let event = self.event.resolve(ctx)?;
        let json = vrl_to_json(event)?;
        let normalized = crate::ocsf::normalize(&json);
        Ok(json_to_vrl(normalized))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        // The shape varies by vendor/class (and may be an `{ "error": ... }`
        // object), so we only promise "an object". Conversion can fail on
        // non-UTF-8 bytes, hence `.fallible()`.
        TypeDef::object(Collection::any()).fallible()
    }
}
