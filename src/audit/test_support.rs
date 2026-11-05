//! Small authored graph shared by pure feature tests.
pub(super) fn value() -> serde_json::Value {
    serde_json::from_slice(include_bytes!("../../tests/fixtures/audit/graph.json"))
        .expect("authored graph")
}

pub(super) fn report(value: &serde_json::Value) -> crate::api::audit::Report {
    crate::api::audit::Report::from_bytes(&serde_json::to_vec(value).expect("fixture JSON"))
        .expect("authored report")
}
