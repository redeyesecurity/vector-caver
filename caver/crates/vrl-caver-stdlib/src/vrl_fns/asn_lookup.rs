// caver/crates/vrl-caver-stdlib/src/vrl_fns/asn_lookup.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::json_to_vrl;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "ip",
        kind::BYTES,
        "The IP address to look up the Autonomous System for.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct AsnLookup;

impl Function for AsnLookup {
    fn identifier(&self) -> &'static str { "asn_lookup" }
    fn usage(&self) -> &'static str {
        "Look up the Autonomous System (ASN) for an IP address. Stub: returns null until an ASN database is wired in."
    }
    fn category(&self) -> &'static str { Category::Convert.as_ref() }
    fn return_kind(&self) -> u16 { kind::OBJECT | kind::NULL }
    fn parameters(&self) -> &'static [Parameter] { &PARAMETERS }
    fn examples(&self) -> &'static [Example] { &[] }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let ip = arguments.required("ip");
        Ok(AsnLookupFn { ip }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct AsnLookupFn {
    ip: Box<dyn Expression>,
}

impl FunctionExpression for AsnLookupFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let ip = self.ip.resolve(ctx)?;
        let ip = ip.try_bytes_utf8_lossy()?.into_owned();
        let result = crate::threat_intel::asn_lookup(&ip);
        Ok(json_to_vrl(result))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any()).add_null().infallible()
    }
}
