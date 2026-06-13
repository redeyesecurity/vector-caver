// caver/crates/vrl-caver-stdlib/src/vrl_fns/parse_winevent.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::json_to_vrl;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "raw",
        kind::BYTES,
        "The raw Windows Event Log XML string to parse.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct ParseWinevent;

impl Function for ParseWinevent {
    fn identifier(&self) -> &'static str { "parse_winevent" }
    fn usage(&self) -> &'static str {
        "Parse a raw Windows Event Log XML `raw` string into a structured object."
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
        let raw = arguments.required("raw");
        Ok(ParseWineventFn { raw }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct ParseWineventFn {
    raw: Box<dyn Expression>,
}

impl FunctionExpression for ParseWineventFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let raw = self.raw.resolve(ctx)?;
        let raw = raw.try_bytes_utf8_lossy()?;
        let parsed = crate::parsers::parse_winevent(&raw);
        Ok(json_to_vrl(parsed))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).fallible()
    }
}
