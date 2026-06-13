//! OCSF classification + normalization (`vrl_caver_stdlib::ocsf`).

use crate::conv::{json_to_vrl, vrl_to_json};
use vrl::prelude::*;

// ---------------------------------------------------------------------------
// ocsf_classify
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct OcsfClassify;

impl Function for OcsfClassify {
    fn identifier(&self) -> &'static str {
        "ocsf_classify"
    }

    fn usage(&self) -> &'static str {
        "Returns the OCSF class_uid for a vendor event (routes on `_vendor`), or 0 if unrecognised."
    }

    fn category(&self) -> &'static str {
        "Enrichment"
    }

    fn return_kind(&self) -> u16 {
        kind::INTEGER
    }

    fn parameters(&self) -> &'static [Parameter] {
        const PARAMETERS: &[Parameter] = &[Parameter::required(
            "value",
            kind::OBJECT,
            "The event object to classify. Routing reads `_vendor` (set by the parse_* functions) plus vendor-specific fields.",
        )];
        PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[
            example! {
                title: "Classify an nginx access event",
                source: r#"ocsf_classify({"_vendor": "nginx"})"#,
                result: Ok("4002"),
            },
            example! {
                title: "Unknown vendors classify to 0",
                source: r#"ocsf_classify({"message": "hello"})"#,
                result: Ok("0"),
            },
        ]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        Ok(OcsfClassifyFn { value }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct OcsfClassifyFn {
    value: Box<dyn Expression>,
}

impl FunctionExpression for OcsfClassifyFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        let class_uid = vrl_caver_stdlib::ocsf::classify(&vrl_to_json(&value));
        Ok(Value::from(i64::from(class_uid)))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::integer().infallible()
    }
}

// ---------------------------------------------------------------------------
// ocsf_normalize
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct OcsfNormalize;

impl Function for OcsfNormalize {
    fn identifier(&self) -> &'static str {
        "ocsf_normalize"
    }

    fn usage(&self) -> &'static str {
        "Normalises a vendor event to the OCSF-flat shape the Python collector transforms emit. Unclassifiable events return an `{\"error\": ...}` object."
    }

    fn category(&self) -> &'static str {
        "Enrichment"
    }

    fn return_kind(&self) -> u16 {
        kind::OBJECT
    }

    fn parameters(&self) -> &'static [Parameter] {
        const PARAMETERS: &[Parameter] = &[Parameter::required(
            "value",
            kind::OBJECT,
            "The event object to normalise. Routing reads `_vendor` (set by the parse_* functions).",
        )];
        PARAMETERS
    }

    fn examples(&self) -> &'static [Example] {
        &[
            example! {
                title: "Events with no vendor match return an error object",
                source: r#"ocsf_normalize({"message": "hello"})"#,
                result: Ok(r#"{"error": "unclassified event — no _vendor match"}"#),
            },
            example! {
                title: "Normalise an nginx access event",
                source: r#"ocsf_normalize({"_vendor": "nginx", "request": "GET / HTTP/1.1", "status": "200"})"#,
                result: Ok(r#"{"class_uid": 4002}"#),
                deterministic: false,
            },
        ]
    }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        Ok(OcsfNormalizeFn { value }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct OcsfNormalizeFn {
    value: Box<dyn Expression>,
}

impl FunctionExpression for OcsfNormalizeFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        let normalized = vrl_caver_stdlib::ocsf::normalize(&vrl_to_json(&value));
        Ok(json_to_vrl(normalized))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).infallible()
    }
}
