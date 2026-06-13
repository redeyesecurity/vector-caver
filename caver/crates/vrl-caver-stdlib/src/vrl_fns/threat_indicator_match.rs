// caver/crates/vrl-caver-stdlib/src/vrl_fns/threat_indicator_match.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::json_to_vrl;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![
        Parameter::required(
            "value",
            kind::BYTES,
            "The indicator value to match (e.g. an IP, domain, hash, or URL).",
        ),
        Parameter::required(
            "indicator_type",
            kind::BYTES,
            "The indicator type (e.g. \"ip\", \"domain\", \"hash\", \"url\").",
        ),
    ]
});

#[derive(Clone, Copy, Debug)]
pub struct ThreatIndicatorMatch;

impl Function for ThreatIndicatorMatch {
    fn identifier(&self) -> &'static str { "threat_indicator_match" }
    fn usage(&self) -> &'static str {
        "Match `value` of `indicator_type` against SLAM-fed threat indicators, \
         returning an object describing any match."
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
        let value = arguments.required("value");
        let indicator_type = arguments.required("indicator_type");
        Ok(ThreatIndicatorMatchFn { value, indicator_type }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct ThreatIndicatorMatchFn {
    value: Box<dyn Expression>,
    indicator_type: Box<dyn Expression>,
}

impl FunctionExpression for ThreatIndicatorMatchFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let value = self.value.resolve(ctx)?;
        let value = value.try_bytes_utf8_lossy()?.into_owned();
        let indicator_type = self.indicator_type.resolve(ctx)?;
        let indicator_type = indicator_type.try_bytes_utf8_lossy()?.into_owned();
        let result = crate::threat_intel::threat_indicator_match(&value, &indicator_type);
        Ok(json_to_vrl(result))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).fallible()
    }
}
