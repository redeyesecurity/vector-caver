// caver/crates/vrl-caver-stdlib/src/vrl_fns/redact_pii.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::{json_to_vrl, vrl_to_json};

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![
        Parameter::required(
            "event",
            kind::OBJECT,
            "The event object to redact PII from (recursively).",
        ),
        Parameter::required(
            "profile",
            kind::BYTES,
            "The redaction profile: \"email\", \"ssn\", \"phone\", or \"all\".",
        ),
    ]
});

#[derive(Clone, Copy, Debug)]
pub struct RedactPii;

impl Function for RedactPii {
    fn identifier(&self) -> &'static str { "redact_pii" }
    fn usage(&self) -> &'static str {
        "Redact PII (email, SSN, phone) from all string values in an `event` object per `profile`."
    }
    fn category(&self) -> &'static str { Category::Convert.as_ref() }
    fn return_kind(&self) -> u16 { kind::OBJECT }
    fn parameters(&self) -> &'static [Parameter] { &PARAMETERS }
    fn examples(&self) -> &'static [Example] { &[] }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let event = arguments.required("event");
        let profile = arguments.required("profile");
        Ok(RedactPiiFn { event, profile }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct RedactPiiFn {
    event: Box<dyn Expression>,
    profile: Box<dyn Expression>,
}

impl FunctionExpression for RedactPiiFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let event = self.event.resolve(ctx)?;
        let json = vrl_to_json(event)?;

        let profile = self.profile.resolve(ctx)?;
        let profile_bytes = profile.try_bytes()?;
        let profile_str = String::from_utf8_lossy(&profile_bytes);

        let redacted = crate::parsers::redact_pii(&json, &profile_str);
        Ok(json_to_vrl(redacted))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).fallible()
    }
}
