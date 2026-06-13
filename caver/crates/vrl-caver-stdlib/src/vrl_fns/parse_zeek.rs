// caver/crates/vrl-caver-stdlib/src/vrl_fns/parse_zeek.rs

use std::sync::LazyLock;

use vrl::prelude::*;

use super::json_to_vrl;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![
        Parameter::required(
            "line",
            kind::BYTES,
            "A single raw Zeek log line (JSON or TSV) to parse.",
        ),
        Parameter::required(
            "log_type",
            kind::BYTES,
            "The Zeek log type (e.g. \"conn\", \"dns\", \"http\", \"ssl\").",
        ),
    ]
});

#[derive(Clone, Copy, Debug)]
pub struct ParseZeek;

impl Function for ParseZeek {
    fn identifier(&self) -> &'static str { "parse_zeek" }
    fn usage(&self) -> &'static str {
        "Parse a raw Zeek log `line` of the given `log_type` into a structured object."
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
        let line = arguments.required("line");
        let log_type = arguments.required("log_type");
        Ok(ParseZeekFn { line, log_type }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct ParseZeekFn {
    line: Box<dyn Expression>,
    log_type: Box<dyn Expression>,
}

impl FunctionExpression for ParseZeekFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let line = self.line.resolve(ctx)?;
        let line = line.try_bytes_utf8_lossy()?;
        let log_type = self.log_type.resolve(ctx)?;
        let log_type = log_type.try_bytes_utf8_lossy()?;
        let parsed = crate::parsers::parse_zeek(&line, &log_type);
        Ok(json_to_vrl(parsed))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).fallible()
    }
}
