// caver/crates/vrl-caver-stdlib/src/vrl_fns/is_internal_ip.rs
use std::sync::LazyLock;

use vrl::prelude::*;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "ip",
        kind::BYTES,
        "The IP address string to test for membership in an internal/private range.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct IsInternalIp;

impl Function for IsInternalIp {
    fn identifier(&self) -> &'static str { "is_internal_ip" }
    fn usage(&self) -> &'static str {
        "Return true if `ip` is an RFC-1918 / RFC-6598 / link-local / loopback / documentation address."
    }
    fn category(&self) -> &'static str { Category::Convert.as_ref() }
    fn return_kind(&self) -> u16 { kind::BOOLEAN }
    fn parameters(&self) -> &'static [Parameter] { &PARAMETERS }
    fn examples(&self) -> &'static [Example] { &[] }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let ip = arguments.required("ip");
        Ok(IsInternalIpFn { ip }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct IsInternalIpFn {
    ip: Box<dyn Expression>,
}

impl FunctionExpression for IsInternalIpFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let ip = self.ip.resolve(ctx)?;
        let ip_bytes = ip.try_bytes()?;
        let ip_str = String::from_utf8_lossy(&ip_bytes);
        let result = crate::threat_intel::is_internal_ip(&ip_str);
        Ok(Value::Boolean(result))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::boolean().fallible()
    }
}
