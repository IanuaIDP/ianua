//! Costing a GraphQL request before the backend pays for it.
//!
//! A GraphQL request says what it wants in the body alone, so the stage
//! reads the prefix the pipeline asked for. Whatever cannot be costed is
//! refused: a body longer than the gateway reads, since padding a query
//! past the read is the first way round the limits anyone would try; a body
//! the analyzer cannot read, a batch among them; and a query past the
//! tenant's depth or cost.
//!
//! Refusals are `400`: the query is what a developer should look at, not
//! their credentials. The reason names the limit and never the schema.

use ianua_app::ports::proxy::GraphQlAnalyzer;
use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::request::graphql::GraphQlLimits;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::types::DenialStatus;

use super::{deny, pass};

/// The decision `limits` take on `body`, read by `analyzer`.
pub(super) fn verdict(
    limits: &GraphQlLimits,
    body: Option<CapturedBody<'_>>,
    analyzer: &dyn GraphQlAnalyzer,
) -> StageDecision {
    let Some(body) = body else {
        return refused("graphql: the body was not read");
    };
    if !body.is_whole() {
        return refused("graphql: the query is longer than the gateway reads");
    }
    let Ok(operation) = analyzer.analyze(body.bytes) else {
        return refused("graphql: the body is not a GraphQL request the gateway reads");
    };
    match limits.verdict_on(&operation).reason() {
        Some(reason) => refused(&format!("graphql: {reason}")),
        None => pass(&format!(
            "graphql: the query costs {}",
            operation.complexity
        )),
    }
}

fn refused(reason: &str) -> StageDecision {
    deny(DenialStatus::BAD_REQUEST, reason)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::request::body::BodyExtent;
    use ianua_domain::domains::proxy::request::graphql::GraphQlOperation;
    use ianua_domain::shared::errors::DomainError;
    use ianua_infra::reading::DocumentGraphQlAnalyzer;

    use super::*;

    fn body(query: &str) -> Vec<u8> {
        serde_json::json!({ "query": query })
            .to_string()
            .into_bytes()
    }

    fn whole(bytes: &[u8]) -> CapturedBody<'_> {
        CapturedBody::new(bytes, BodyExtent::Whole)
    }

    fn decide(limits: &GraphQlLimits, sent: &[u8]) -> StageDecision {
        verdict(limits, Some(whole(sent)), &DocumentGraphQlAnalyzer)
    }

    #[test]
    fn a_query_within_the_limits_passes() {
        let decision = decide(&GraphQlLimits::default(), &body("{ user { name } }"));

        assert!(!decision.is_terminal());
    }

    #[test]
    fn a_query_nesting_past_the_limit_is_refused() {
        let limits = GraphQlLimits::new(2, 1_000, 0).unwrap();

        let StageDecision::Deny { status, reason } = decide(
            &limits,
            &body("{ secretRoot { internalField { deeper } } }"),
        ) else {
            panic!("the query nests too deep");
        };

        assert_eq!(status, DenialStatus::BAD_REQUEST);
        assert!(!reason.contains("secretRoot"));
    }

    #[test]
    fn a_query_costing_more_than_allowed_is_refused() {
        let limits = GraphQlLimits::new(15, 3, 0).unwrap();

        assert!(decide(&limits, &body("{ a b c d e f }")).is_terminal());
    }

    /// A valid query marked as only a body prefix receives a terminal refusal.
    #[test]
    fn a_body_longer_than_the_read_is_refused() {
        let sent = body("{ user { name } }");

        let decision = verdict(
            &GraphQlLimits::default(),
            Some(CapturedBody::new(&sent, BodyExtent::Prefix)),
            &DocumentGraphQlAnalyzer,
        );

        assert!(decision.is_terminal());
    }

    #[test]
    fn a_batch_is_refused() {
        let batch = br#"[{"query": "{ a }"}, {"query": "{ b }"}]"#;

        assert!(decide(&GraphQlLimits::default(), batch).is_terminal());
    }

    #[test]
    fn a_body_not_read_is_refused() {
        let decision = verdict(&GraphQlLimits::default(), None, &DocumentGraphQlAnalyzer);

        assert!(decision.is_terminal());
    }

    #[test]
    fn an_analyzer_that_fails_refuses() {
        struct Failing;

        impl GraphQlAnalyzer for Failing {
            fn analyze(&self, _: &[u8]) -> Result<GraphQlOperation, DomainError> {
                Err(DomainError::infra_msg("the parser failed"))
            }
        }

        let sent = body("{ user { name } }");

        assert!(verdict(&GraphQlLimits::default(), Some(whole(&sent)), &Failing).is_terminal());
    }
}
