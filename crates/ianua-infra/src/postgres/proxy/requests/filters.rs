//! How a search's filter narrows a tenant's request records. Each
//! condition is a fixed piece of SQL with at most one value bound.

use ianua_app::ports::proxy::{
    DecidedByFilter, DecisionFilter, RecordSubject, RequestRecordFilter,
};

use crate::postgres::foundation::paging::PageQuery;

/// `query` narrowed to the records `filter` keeps.
pub(super) fn narrowed(
    query: PageQuery<'static>,
    filter: &RequestRecordFilter,
) -> PageQuery<'static> {
    let mut query = by_decision(query, filter.decision);
    query = by_decider(query, filter.decided_by);
    if let Some(rule) = &filter.rule {
        query = query.filter("rule = ?", rule.as_str().to_owned());
    }
    if let Some(text) = &filter.reason_contains {
        query = query.filter("strpos(lower(reason), lower(?)) > 0", text.clone());
    }
    if let Some(route) = filter.route {
        query = query.filter("route_id = ?", *route.as_uuid());
    }
    query = by_subject(query, filter.subject);
    if let Some(after) = filter.after {
        query = query.filter("occurred_at >= ?", after);
    }
    if let Some(before) = filter.before {
        query = query.filter("occurred_at < ?", before);
    }
    query
}

/// Requests let through, or refused: denied, or ended with no decision,
/// which the proxy refuses as well.
fn by_decision(query: PageQuery<'static>, decision: DecisionFilter) -> PageQuery<'static> {
    match decision {
        DecisionFilter::Any => query,
        DecisionFilter::Allowed => query.keep("outcome = 'allowed'"),
        DecisionFilter::Refused => query.keep("outcome <> 'allowed'"),
    }
}

/// Refusals by one gateway check, one stage, or any stage of one kind.
fn by_decider(query: PageQuery<'static>, decided_by: DecidedByFilter) -> PageQuery<'static> {
    match decided_by {
        DecidedByFilter::Any => query,
        DecidedByFilter::Gateway(check) => query
            .filter("decided_by = ?", check.as_str())
            .keep("decided_by_stage_id IS NULL"),
        DecidedByFilter::Stage(stage) => query.filter("decided_by_stage_id = ?", *stage.as_uuid()),
        DecidedByFilter::StageKind(kind) => query
            .filter("decided_by = ?", kind.as_str())
            .keep("decided_by_stage_id IS NOT NULL"),
    }
}

/// Requests of one person, directly or through an agent, of one agent, or
/// of one consumer.
fn by_subject(query: PageQuery<'static>, subject: Option<RecordSubject>) -> PageQuery<'static> {
    match subject {
        None => query,
        Some(RecordSubject::User(user)) => query.filter("person_id = ?", *user.as_uuid()),
        Some(RecordSubject::Agent(agent)) => query
            .keep("principal = 'agent'")
            .filter("principal_id = ?", *agent.as_uuid()),
        Some(RecordSubject::Consumer(consumer)) => query
            .keep("principal = 'consumer'")
            .filter("principal_id = ?", *consumer.as_uuid()),
    }
}
