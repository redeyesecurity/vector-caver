// caver/crates/vrl-caver-stdlib/src/vrl_fns/classify.rs
use std::sync::LazyLock;

use vrl::prelude::*;

use super::vrl_to_json;

static PARAMETERS: LazyLock<Vec<Parameter>> = LazyLock::new(|| {
    vec![Parameter::required(
        "event",
        kind::OBJECT,
        "The raw vendor event object to classify.",
    )]
});

#[derive(Clone, Copy, Debug)]
pub struct OcsfClassify;

impl Function for OcsfClassify {
    fn identifier(&self) -> &'static str {
        "ocsf_classify"
    }
    fn usage(&self) -> &'static str {
        "Inspect a raw vendor `event` object and return its OCSF class_uid, or 0 if unknown."
    }
    fn category(&self) -> &'static str {
        Category::Convert.as_ref()
    }
    fn return_kind(&self) -> u16 {
        kind::INTEGER
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
        let event = arguments.required("event");
        Ok(OcsfClassifyFn { event }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct OcsfClassifyFn {
    event: Box<dyn Expression>,
}

impl FunctionExpression for OcsfClassifyFn {
    fn resolve(&self, ctx: &mut Context<'_>) -> Resolved {
        let event = self.event.resolve(ctx)?;
        let json = vrl_to_json(event)?;
        let class_uid = crate::ocsf::classify(&json);
        Ok(Value::from(class_uid))
    }

    fn type_def(&self, _state: &TypeState) -> TypeDef {
        TypeDef::integer().fallible()
    }
}
