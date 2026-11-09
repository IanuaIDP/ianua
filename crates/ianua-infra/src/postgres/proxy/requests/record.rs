//! A request record as its row holds it: read back into the record the
//! proxy made, and written out from many of them in one statement. A row
//! keeps what the record holds and nothing more.

use std::collections::HashMap;
use std::net::IpAddr;

use ianua_app::ports::proxy::ProxyRequestRecord;
use ianua_domain::domains::authorization::policy::version::PolicyVersion;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::observation::{
    DecidingRule, DecidingStage, GatewayCheck, ObservedPrincipal, RequestOutcome, RouteMatch,
    RulingPolicy, TunnelClose,
};
use ianua_domain::domains::proxy::stages::stage::StageKindName;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    AgentId, ConsumerId, CorrelationId, DelegationId, Label, PrincipalRef, RouteId, ServiceId,
    StageId, TenantId, UntrustedText, UserId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const RECORD: Stored = Stored("request record");

/// A request record as it is read. The store's checked queries fill it.
pub(super) struct RequestRecord {
    pub(super) tenant_id: Uuid,
    pub(super) correlation_id: Uuid,
    pub(super) principal: String,
    pub(super) principal_id: Option<Uuid>,
    pub(super) delegation_id: Option<Uuid>,
    pub(super) on_behalf_kind: Option<String>,
    pub(super) on_behalf_id: Option<Uuid>,
    pub(super) consumer_credential: Option<String>,
    pub(super) route_id: Option<Uuid>,
    pub(super) service_id: Option<Uuid>,
    pub(super) ip_address: String,
    pub(super) method: String,
    pub(super) path: String,
    pub(super) outcome: String,
    pub(super) status: i16,
    pub(super) reason: Option<String>,
    pub(super) decided_by: Option<String>,
    pub(super) decided_by_stage_id: Option<Uuid>,
    pub(super) rule: Option<String>,
    pub(super) duration_ms: i32,
    pub(super) classification: Vec<String>,
    pub(super) occurred_at: OffsetDateTime,
    pub(super) policy_version: Option<i64>,
    pub(super) closed_reason: Option<String>,
    pub(super) closed_at: Option<OffsetDateTime>,
}

impl RequestRecord {
    /// The record the row holds, its words and values checked again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a word is unknown, a
    /// value no longer reads, or the row's parts do not fit together.
    pub(super) fn into_request(self) -> Result<ProxyRequestRecord, DomainError> {
        let principal = self.principal_of()?;
        let outcome = self.outcome_of()?;
        let route = self.route_of()?;
        let ip_address: IpAddr = self
            .ip_address
            .parse()
            .map_err(|_| DomainError::corrupt_row(RECORD.0, "an address that does not read"))?;
        Ok(ProxyRequestRecord {
            tenant_id: TenantId::from_uuid(self.tenant_id),
            correlation_id: CorrelationId::from_uuid(self.correlation_id),
            principal,
            route,
            ip_address,
            method: UntrustedText::record(&self.method),
            path: UntrustedText::record(&self.path),
            outcome,
            duration_ms: u32::try_from(self.duration_ms)
                .map_err(|_| DomainError::corrupt_row(RECORD.0, "a duration below zero"))?,
            occurred_at: self.occurred_at,
            classification: self
                .classification
                .iter()
                .map(|level| DataClassLevel::from_stored(level))
                .collect::<Result<_, _>>()?,
            policy: ruling_policy(self.policy_version)?,
            closed: close_of(self.closed_reason.as_deref(), self.closed_at)?,
        })
    }

    /// Rebuilds the route only when both related identifiers are present.
    fn route_of(&self) -> Result<RouteMatch, DomainError> {
        match (self.route_id, self.service_id) {
            (Some(route), Some(service)) => Ok(RouteMatch::Matched {
                route_id: RouteId::from_uuid(route),
                service_id: ServiceId::from_uuid(service),
            }),
            (None, None) => Ok(RouteMatch::NoRoute),
            _ => Err(DomainError::corrupt_row(RECORD.0, "half a route")),
        }
    }

    fn principal_of(&self) -> Result<ObservedPrincipal, DomainError> {
        let parts = (
            self.principal.as_str(),
            self.principal_id,
            self.delegation_id,
            self.on_behalf_kind.as_deref(),
            self.on_behalf_id,
            self.consumer_credential.as_deref(),
        );
        match parts {
            ("anonymous", None, None, None, None, None) => Ok(ObservedPrincipal::Anonymous),
            ("user", Some(id), None, None, None, None) => {
                Ok(ObservedPrincipal::User(UserId::from_uuid(id)))
            }
            ("agent", Some(agent), Some(delegation), Some(kind), Some(behalf), None) => {
                Ok(ObservedPrincipal::Agent {
                    agent_id: AgentId::from_uuid(agent),
                    delegation_id: DelegationId::from_uuid(delegation),
                    on_behalf_of: PrincipalRef::from_parts(kind, behalf)?,
                })
            }
            ("consumer", Some(id), None, None, None, Some(credential)) => {
                Ok(ObservedPrincipal::Consumer {
                    consumer_id: ConsumerId::from_uuid(id),
                    credential: RECORD.choice(credential)?,
                })
            }
            _ => Err(DomainError::corrupt_row(RECORD.0, "an unknown principal")),
        }
    }

    fn outcome_of(&self) -> Result<RequestOutcome, DomainError> {
        let status = u16::try_from(self.status)
            .map_err(|_| DomainError::corrupt_row(RECORD.0, "a status below zero"))?;
        match (self.outcome.as_str(), &self.reason, &self.decided_by) {
            ("allowed", None, None) => Ok(RequestOutcome::Allowed {
                upstream_status: status,
            }),
            ("undecided", None, None) => Ok(RequestOutcome::Undecided),
            ("denied", Some(reason), Some(decided_by)) => Ok(RequestOutcome::Denied {
                status,
                reason: reason.clone(),
                decided_by: deciding_stage(decided_by, self.decided_by_stage_id)?,
                rule: match &self.rule {
                    None => DecidingRule::Unnamed,
                    Some(rule) => DecidingRule::Named(
                        RECORD.value("rule", Label::new("name", rule.as_str()))?,
                    ),
                },
            }),
            _ => Err(DomainError::corrupt_row(RECORD.0, "an unknown outcome")),
        }
    }
}

/// The close the row records, when the gateway closed the connection.
fn close_of(
    reason: Option<&str>,
    at: Option<OffsetDateTime>,
) -> Result<Option<TunnelClose>, DomainError> {
    match (reason, at) {
        (None, None) => Ok(None),
        (Some(word), Some(at)) => Ok(Some(TunnelClose {
            reason: RECORD.choice(word)?,
            at,
        })),
        _ => Err(DomainError::corrupt_row(RECORD.0, "half a close")),
    }
}

/// The check `word` names: a stage of its kind when the row names the
/// stage, else a gateway check.
fn deciding_stage(word: &str, stage: Option<Uuid>) -> Result<DecidingStage, DomainError> {
    let unknown = || DomainError::corrupt_row(RECORD.0, "an unknown deciding check");
    let Some(stage) = stage else {
        return GatewayCheck::parse(word)
            .map(DecidingStage::Gateway)
            .ok_or_else(unknown);
    };
    let kind = StageKindName::parse(word).ok_or_else(unknown)?;
    Ok(DecidingStage::Stage {
        stage_id: StageId::from_uuid(stage),
        kind,
    })
}

/// The policy the stored version names: none when the column is empty.
fn ruling_policy(stored: Option<i64>) -> Result<RulingPolicy, DomainError> {
    let Some(number) = stored else {
        return Ok(RulingPolicy::NoTenantVersion);
    };
    let number = u32::try_from(number)
        .map_err(|_| DomainError::corrupt_row(RECORD.0, "a policy version out of range"))?;
    Ok(RulingPolicy::Tenant(PolicyVersion::from_stored(number)?))
}

/// The version column of `policy`.
fn policy_column(policy: RulingPolicy) -> Option<i64> {
    policy.version().map(|version| i64::from(version.number()))
}

/// Who asked, as the principal columns keep it, and the person behind.
struct Principal {
    word: &'static str,
    id: Option<Uuid>,
    delegation: Option<Uuid>,
    on_behalf_kind: Option<String>,
    on_behalf_id: Option<Uuid>,
    credential: Option<String>,
    person: Option<Uuid>,
}

impl Principal {
    /// Starts with empty principal columns while retaining the attributed person.
    fn anonymous(principal: &ObservedPrincipal) -> Self {
        Self {
            word: "anonymous",
            id: None,
            delegation: None,
            on_behalf_kind: None,
            on_behalf_id: None,
            credential: None,
            person: principal.person().map(|user| *user.as_uuid()),
        }
    }

    /// Selects the columns specific to the observed principal's kind.
    fn of(principal: &ObservedPrincipal) -> Self {
        let nobody = Self::anonymous(principal);
        match principal {
            ObservedPrincipal::Anonymous => nobody,
            ObservedPrincipal::User(user) => Self {
                word: "user",
                id: Some(*user.as_uuid()),
                ..nobody
            },
            ObservedPrincipal::Agent {
                agent_id,
                delegation_id,
                on_behalf_of,
            } => Self {
                word: "agent",
                id: Some(*agent_id.as_uuid()),
                delegation: Some(*delegation_id.as_uuid()),
                on_behalf_kind: Some(on_behalf_of.kind().to_owned()),
                on_behalf_id: Some(on_behalf_of.id()),
                ..nobody
            },
            ObservedPrincipal::Consumer {
                consumer_id,
                credential,
            } => Self {
                word: "consumer",
                id: Some(*consumer_id.as_uuid()),
                credential: Some(credential.word().to_owned()),
                ..nobody
            },
        }
    }
}

/// What was decided, as the outcome columns keep it.
struct Outcome {
    word: &'static str,
    reason: Option<String>,
    decided_by: Option<String>,
    stage: Option<Uuid>,
    rule: Option<String>,
}

impl Outcome {
    fn of(outcome: &RequestOutcome) -> Self {
        let plain = |word| Self {
            word,
            reason: None,
            decided_by: None,
            stage: None,
            rule: None,
        };
        match outcome {
            RequestOutcome::Allowed { .. } => plain("allowed"),
            RequestOutcome::Undecided => plain("undecided"),
            RequestOutcome::Denied {
                reason,
                decided_by,
                rule,
                ..
            } => Self {
                word: "denied",
                reason: Some(reason.clone()),
                decided_by: Some(decided_by.name().to_owned()),
                stage: match decided_by {
                    DecidingStage::Stage { stage_id, .. } => Some(*stage_id.as_uuid()),
                    DecidingStage::Gateway(_) => None,
                },
                rule: match rule {
                    DecidingRule::Unnamed => None,
                    DecidingRule::Named(name) => Some(name.as_str().to_owned()),
                },
            },
        }
    }
}

/// Many records' columns, one list per column and one place per record,
/// as one statement writes them.
#[derive(Default)]
pub(super) struct RequestBatch {
    pub(super) correlation_ids: Vec<Uuid>,
    pub(super) principals: Vec<String>,
    pub(super) principal_ids: Vec<Option<Uuid>>,
    pub(super) delegation_ids: Vec<Option<Uuid>>,
    pub(super) on_behalf_kinds: Vec<Option<String>>,
    pub(super) on_behalf_ids: Vec<Option<Uuid>>,
    pub(super) consumer_credentials: Vec<Option<String>>,
    pub(super) person_ids: Vec<Option<Uuid>>,
    pub(super) route_ids: Vec<Option<Uuid>>,
    pub(super) service_ids: Vec<Option<Uuid>>,
    pub(super) ip_addresses: Vec<String>,
    pub(super) methods: Vec<String>,
    pub(super) paths: Vec<String>,
    pub(super) outcomes: Vec<String>,
    pub(super) statuses: Vec<i16>,
    pub(super) reasons: Vec<Option<String>>,
    pub(super) decided_by: Vec<Option<String>>,
    pub(super) decided_by_stage_ids: Vec<Option<Uuid>>,
    pub(super) rules: Vec<Option<String>>,
    pub(super) durations: Vec<i32>,
    pub(super) classifications: Vec<String>,
    pub(super) occurred_at: Vec<OffsetDateTime>,
    pub(super) policy_versions: Vec<Option<i64>>,
    pub(super) closed_reasons: Vec<Option<String>>,
    pub(super) closed_ats: Vec<Option<OffsetDateTime>>,
    positions: HashMap<Uuid, usize>,
}

impl RequestBatch {
    /// The columns `records` are written to. The levels found on each are
    /// one comma-joined text, highest first, split again as they are
    /// written.
    pub(super) fn of<'a>(records: impl IntoIterator<Item = &'a ProxyRequestRecord>) -> Self {
        let mut batch = Self::default();
        for record in records {
            batch.push(record);
        }
        batch
    }

    /// Appends one record's columns at the same position in every batch
    /// vector. A record already in the batch only adds its close: one
    /// statement may touch a row once, so a request and its close, queued
    /// together, are written as one row.
    fn push(&mut self, record: &ProxyRequestRecord) {
        let id = *record.correlation_id.as_uuid();
        if let Some(position) = self.positions.get(&id).copied() {
            self.merge_close(position, record.closed);
            return;
        }
        self.positions.insert(id, self.correlation_ids.len());
        let principal = Principal::of(&record.principal);
        let outcome = Outcome::of(&record.outcome);
        self.correlation_ids.push(id);
        self.push_principal(principal);
        self.push_route(record.route);
        self.ip_addresses.push(record.ip_address.to_string());
        self.methods.push(record.method.as_str().to_owned());
        self.paths.push(record.path.as_str().to_owned());
        self.push_outcome(outcome, record.status());
        self.durations
            .push(i32::try_from(record.duration_ms).unwrap_or(i32::MAX));
        self.classifications.push(
            record
                .classification
                .iter()
                .map(|level| level.as_str())
                .collect::<Vec<_>>()
                .join(","),
        );
        self.occurred_at.push(record.occurred_at);
        self.policy_versions.push(policy_column(record.policy));
        self.closed_reasons
            .push(record.closed.map(|close| close.reason.word().to_owned()));
        self.closed_ats.push(record.closed.map(|close| close.at));
    }

    /// Adds `closed` to the row at `position`, the first close kept.
    fn merge_close(&mut self, position: usize, closed: Option<TunnelClose>) {
        let Some(closed) = closed else {
            return;
        };
        let (Some(reason), Some(at)) = (
            self.closed_reasons.get_mut(position),
            self.closed_ats.get_mut(position),
        ) else {
            return;
        };
        if reason.is_none() {
            *reason = Some(closed.reason.word().to_owned());
            *at = Some(closed.at);
        }
    }

    /// Appends the matched route and service together, or two empty columns.
    fn push_route(&mut self, matched: RouteMatch) {
        let (route, service) = match matched {
            RouteMatch::Matched {
                route_id,
                service_id,
            } => (Some(*route_id.as_uuid()), Some(*service_id.as_uuid())),
            RouteMatch::NoRoute => (None, None),
        };
        self.route_ids.push(route);
        self.service_ids.push(service);
    }

    /// Appends identity and attribution columns for one observed principal.
    fn push_principal(&mut self, principal: Principal) {
        self.principals.push(principal.word.to_owned());
        self.principal_ids.push(principal.id);
        self.delegation_ids.push(principal.delegation);
        self.on_behalf_kinds.push(principal.on_behalf_kind);
        self.on_behalf_ids.push(principal.on_behalf_id);
        self.consumer_credentials.push(principal.credential);
        self.person_ids.push(principal.person);
    }

    /// Appends the decision, its explanation, and the bounded wire status.
    fn push_outcome(&mut self, outcome: Outcome, status: u16) {
        self.outcomes.push(outcome.word.to_owned());
        self.statuses
            .push(i16::try_from(status).unwrap_or(i16::MAX));
        self.reasons.push(outcome.reason);
        self.decided_by.push(outcome.decided_by);
        self.decided_by_stage_ids.push(outcome.stage);
        self.rules.push(outcome.rule);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The columns the sink writes, as its statement names them.
    const WRITTEN: &str = include_str!("../../../../queries/proxy_request_records/write.sql");

    /// The request insert names exactly the expected metadata columns,
    /// with no columns for tokens, cookies, headers or bodies.
    #[test]
    fn a_row_keeps_the_records_facts_and_nothing_more() {
        let listed = WRITTEN
            .split_once("INSERT INTO proxy_request_records")
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(columns, _)| columns.replace(['(', '\n', ' '], ""))
            .unwrap();

        assert_eq!(
            listed,
            "tenant_id,correlation_id,principal,principal_id,delegation_id,on_behalf_kind,\
             on_behalf_id,consumer_credential,person_id,route_id,service_id,ip_address,method,\
             path,outcome,status,reason,decided_by,decided_by_stage_id,rule,duration_ms,\
             classification,occurred_at,policy_version,closed_reason,closed_at"
        );
    }

    /// Version 7 is written as 7 and reads back as version 7; no version is
    /// an empty column.
    #[test]
    fn the_ruling_policy_reads_back_as_written() {
        let seven = RulingPolicy::Tenant(PolicyVersion::parse(7).unwrap());

        assert_eq!(policy_column(seven), Some(7));
        assert_eq!(ruling_policy(Some(7)).unwrap(), seven);
        assert_eq!(policy_column(RulingPolicy::NoTenantVersion), None);
        assert_eq!(ruling_policy(None).unwrap(), RulingPolicy::NoTenantVersion);
    }

    /// A stored version 0 or one past what a version holds is a corrupt
    /// row, refused rather than read as some other version.
    #[test]
    fn a_stored_version_no_policy_has_is_refused() {
        for stored in [0, -1, i64::from(u32::MAX) + 1] {
            assert!(
                matches!(
                    ruling_policy(Some(stored)),
                    Err(DomainError::Infrastructure(_))
                ),
                "{stored}"
            );
        }
    }

    /// A refusal by a stage reads back as that stage, and one by a gateway
    /// check as the check.
    #[test]
    fn a_deciding_check_reads_back_as_what_it_was() {
        let stage = StageId::new();

        assert_eq!(
            deciding_stage("route", None).unwrap(),
            DecidingStage::Gateway(GatewayCheck::Route)
        );
        assert_eq!(
            deciding_stage("policy", Some(*stage.as_uuid())).unwrap(),
            DecidingStage::Stage {
                stage_id: stage,
                kind: StageKindName::Policy,
            }
        );
        assert!(deciding_stage("wizard", None).is_err());
    }
}
