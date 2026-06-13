// caver/crates/vrl-caver-stdlib/src/vrl_fns/geoip_caver.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::json_to_vrl;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "ip",
        kind::BYTES,
        "The IP address string to geo-locate.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct GeoipCaver;

impl Function for GeoipCaver {
    fn identifier(&self) -> &'static str {
        "geoip_caver"
    }
    fn usage(&self) -> &'static str {
        "Geo-locate an IP address (stub: returns null until a GeoLite2/IPinfo feed is wired)."
    }
    fn category(&self) -> &'static str {
        Category::Convert.as_ref()
    }
    fn return_kind(&self) -> u16 {
        kind::OBJECT | kind::NULL
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
        let ip = arguments.required("ip");
        Ok(GeoipCaverFn { ip }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct GeoipCaverFn {
    ip: Box<dyn Expression>,
}

impl FunctionExpression for GeoipCaverFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let ip = self.ip.resolve(ctx)?;
        let ip = ip.try_bytes_utf8_lossy()?;
        let located = crate::threat_intel::geoip_caver(&ip);
        Ok(json_to_vrl(located))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::object(Collection::any())
            .add_null()
            .fallible()
    }
}
