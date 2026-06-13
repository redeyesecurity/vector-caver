// caver/crates/vrl-caver-stdlib/src/vrl_fns/parse_sysmon.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::{json_to_vrl, vrl_to_json};

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "event",
        kind::OBJECT,
        "The raw Sysmon event object to parse into structured fields.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct ParseSysmon;

impl Function for ParseSysmon {
    fn identifier(&self) -> &'static str { "parse_sysmon" }
    fn usage(&self) -> &'static str {
        "Parse a Sysmon `event` object into a structured field object."
    }
    fn category(&self) -> &'static str { Category::Parse.as_ref() }
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
        Ok(ParseSysmonFn { event }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct ParseSysmonFn {
    event: Box<dyn Expression>,
}

impl FunctionExpression for ParseSysmonFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let event = self.event.resolve(ctx)?;
        let json = vrl_to_json(event)?;
        let parsed = crate::parsers::parse_sysmon(&json);
        Ok(json_to_vrl(parsed))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).fallible()
    }
}
