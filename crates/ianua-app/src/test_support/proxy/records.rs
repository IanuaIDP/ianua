//! An in-memory request log, written as the proxy's sink and searched as
//! the tenant's request log.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::proxy::observation::{
    DecidingRule, DecidingStage, ObservedPrincipal, RequestObservation, RequestOutcome, RouteMatch,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Fact, PrincipalRef};

use crate::listing::Listing;
use crate::ports::TenantScoped;
use crate::ports::proxy::{
    DecidedByFilter, DecisionFilter, ProxyAccessLogSink, ProxyRequestLog, ProxyRequestRecord,
    RecordSubject, RequestRecordFilter, RequestRecordPage, RequestRecordSortField,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::{Fake, request_observation, test_ctx};

/// A record of a request to `/orders` in the test tenant, decided as
/// `outcome`.
///
/// # Panics
///
/// Never in practice: the request names the test tenant.
#[must_use]
pub fn test_request_record(outcome: RequestOutcome) -> ProxyRequestRecord {
    let observation = RequestObservation {
        tenant_id: Fact::Known(test_ctx().tenant_id()),
        ..request_observation(outcome)
    };
    ProxyRequestRecord::of(&observation).expect("the request names a tenant")
}

/// In-memory request log for tests. Every record is kept under the tenant
/// it names, and a search reads only the asking tenant's.
#[derive(Default)]
pub struct FakeRequestLog {
    records: Mutex<Vec<ProxyRequestRecord>>,
}

impl FakeRequestLog {
    /// A log holding `records`.
    #[must_use]
    pub fn holding(records: Vec<ProxyRequestRecord>) -> Self {
        Self {
            records: Mutex::new(records),
        }
    }
}

impl TenantScoped for FakeRequestLog {}

#[async_trait]
impl ProxyAccessLogSink for FakeRequestLog {
    async fn write_batch(&self, records: &[ProxyRequestRecord]) -> Result<(), DomainError> {
        self.records.lock().unwrap().extend_from_slice(records);
        Ok(())
    }
}

#[async_trait]
impl ProxyRequestLog for FakeRequestLog {
    async fn search(
        &self,
        tenant_id: &ScopedTenant,
        listing: Listing<'_, &RequestRecordFilter, RequestRecordSortField>,
    ) -> Result<RequestRecordPage, DomainError> {
        let found: Vec<ProxyRequestRecord> = self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|record| record.tenant_id == **tenant_id && meets(listing.filter, record))
            .cloned()
            .collect();
        page(found, listing.sort, listing.page)
    }
}

/// Whether `record` meets every condition `filter` sets.
fn meets(filter: &RequestRecordFilter, record: &ProxyRequestRecord) -> bool {
    decision_matches(filter.decision, record)
        && decided_by_matches(filter.decided_by, &record.outcome)
        && filter.rule.as_ref().is_none_or(|rule| {
            refused_under(&record.outcome) == Some(&DecidingRule::Named(rule.clone()))
        })
        && filter
            .reason_contains
            .as_deref()
            .is_none_or(|text| reason_contains(&record.outcome, text))
        && filter.route.is_none_or(|route| {
            matches!(record.route, RouteMatch::Matched { route_id, .. } if route_id == route)
        })
        && filter
            .subject
            .is_none_or(|subject| subject_matches(subject, &record.principal))
        && filter.after.is_none_or(|after| record.occurred_at >= after)
        && filter.before.is_none_or(|before| record.occurred_at < before)
}

/// Whether the record's decision is the one asked for.
fn decision_matches(decision: DecisionFilter, record: &ProxyRequestRecord) -> bool {
    match decision {
        DecisionFilter::Any => true,
        DecisionFilter::Allowed => record.is_allowed(),
        DecisionFilter::Refused => !record.is_allowed(),
    }
}

/// Whether the check that refused the request is the one asked for.
fn decided_by_matches(decided_by: DecidedByFilter, outcome: &RequestOutcome) -> bool {
    let refused_by = match outcome {
        RequestOutcome::Denied { decided_by, .. } => Some(decided_by),
        RequestOutcome::Allowed { .. } | RequestOutcome::Undecided => None,
    };
    match (decided_by, refused_by) {
        (DecidedByFilter::Any, _) => true,
        (DecidedByFilter::Gateway(check), Some(DecidingStage::Gateway(by))) => check == *by,
        (DecidedByFilter::Stage(stage), Some(DecidingStage::Stage { stage_id, .. })) => {
            stage == *stage_id
        }
        (DecidedByFilter::StageKind(wanted), Some(DecidingStage::Stage { kind, .. })) => {
            wanted == *kind
        }
        (
            DecidedByFilter::Gateway(_) | DecidedByFilter::Stage(_) | DecidedByFilter::StageKind(_),
            _,
        ) => false,
    }
}

/// The rule a refused request was refused under.
fn refused_under(outcome: &RequestOutcome) -> Option<&DecidingRule> {
    let RequestOutcome::Denied { rule, .. } = outcome else {
        return None;
    };
    Some(rule)
}

/// Whether the refusal's reason holds `text`, ignoring case.
fn reason_contains(outcome: &RequestOutcome, text: &str) -> bool {
    let RequestOutcome::Denied { reason, .. } = outcome else {
        return false;
    };
    reason.to_lowercase().contains(&text.to_lowercase())
}

/// Whether `principal` is the subject asked for. A user matches as the
/// person an agent acted for too.
fn subject_matches(subject: RecordSubject, principal: &ObservedPrincipal) -> bool {
    match (subject, principal) {
        (RecordSubject::User(user), ObservedPrincipal::User(asking)) => user == *asking,
        (
            RecordSubject::User(user),
            ObservedPrincipal::Agent {
                on_behalf_of: PrincipalRef::User(person),
                ..
            },
        ) => user == *person,
        (RecordSubject::Agent(agent), ObservedPrincipal::Agent { agent_id, .. }) => {
            agent == *agent_id
        }
        (RecordSubject::Consumer(consumer), ObservedPrincipal::Consumer { consumer_id, .. }) => {
            consumer == *consumer_id
        }
        _ => false,
    }
}

impl Fake for Arc<dyn ProxyRequestLog> {
    fn fake() -> Self {
        Arc::new(FakeRequestLog::default())
    }
}
