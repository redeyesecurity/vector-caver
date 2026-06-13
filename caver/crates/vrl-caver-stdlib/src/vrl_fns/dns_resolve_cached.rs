// caver/crates/vrl-caver-stdlib/src/vrl_fns/dns_resolve_cached.rs
use std::sync::LazyLock;

use vrl::prelude::*;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "name",
        kind::BYTES,
        "The hostname to resolve via DNS with TTL-aware caching.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct DnsResolveCached;

impl Function for DnsResolveCached {
    fn identifier(&self) -> &'static str { "dns_resolve_cached" }
    fn usage(&self) -> &'static str {
        "Resolve a hostname `name` via DNS with TTL-aware caching, returning an array of resolved addresses."
    }
    fn category(&self) -> &'static str { Category::Convert.as_ref() }
    fn return_kind(&self) -> u16 { kind::ARRAY }
    fn parameters(&self) -> &'static [Parameter] { &PARAMETERS }
    fn examples(&self) -> &'static [Example] { &[] }

    fn compile(
        &self,
        _state: &TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let name = arguments.required("name");
        Ok(DnsResolveCachedFn { name }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct DnsResolveCachedFn {
    name: Box<dyn Expression>,
}

impl FunctionExpression for DnsResolveCachedFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let name = self.name.resolve(ctx)?;
        let name = name.try_bytes_utf8_lossy()?.into_owned();
        let resolved = crate::parsers::dns_resolve_cached(&name);
        let arr: Vec<Value> = resolved.into_iter().map(Value::from).collect();
        Ok(Value::from(arr))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::array(Collection::any()).fallible()
    }
}
