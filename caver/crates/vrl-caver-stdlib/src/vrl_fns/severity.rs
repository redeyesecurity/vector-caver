// caver/crates/vrl-caver-stdlib/src/vrl_fns/severity.rs
use std::sync::LazyLock;

use vrl::prelude::*;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "severity",
        kind::BYTES,
        "The vendor severity string to map to an OCSF severity id/name.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct OcsfSeverity;

impl Function for OcsfSeverity {
    fn identifier(&self) -> &'static str { "ocsf_severity" }
    fn usage(&self) -> &'static str {
        "Map a vendor `severity` string to an OCSF `{id, name}` object."
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
        let severity = arguments.required("severity");
        Ok(OcsfSeverityFn { severity }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct OcsfSeverityFn {
    severity: Box<dyn Expression>,
}

impl FunctionExpression for OcsfSeverityFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let severity = self.severity.resolve(ctx)?;
        let s = severity.try_bytes_utf8_lossy()?;
        let (id, name) = crate::ocsf::severity_id_name(&s);

        let mut obj = ObjectMap::new();
        obj.insert("id".into(), Value::from(id as i64));
        obj.insert("name".into(), Value::from(name));
        Ok(Value::Object(obj))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        // fallible: resolve() uses `try_bytes_utf8_lossy()?`, which errors on non-bytes args.
        TypeDef::object(Collection::any()).fallible()
    }
}
