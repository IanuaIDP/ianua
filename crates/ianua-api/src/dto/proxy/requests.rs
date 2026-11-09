//! Request record bodies: which of the requests the gateway decided to
//! find, and each one as the search answers it, with why it was refused.

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::proxy::{
    DecidedByFilter, DecisionFilter, ProxyRequestRecord, RecordSubject, RequestRecordFilter,
    RequestRecordSortField,
};
use ianua_app::use_cases::proxy::SearchRequestRecordsRequest;
use ianua_domain::domains::authorization::policy::version::PolicyVersion;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::observation::{
    DecidingRule, DecidingStage, GatewayCheck, ObservedPrincipal, RequestOutcome, RouteMatch,
    TunnelClose,
};
use ianua_domain::domains::proxy::request::context::ConsumerCredential;
use ianua_domain::domains::proxy::stages::stage::StageKindName;
use ianua_domain::message;
use ianua_domain::types::{AgentId, ConsumerId, Label, RouteId, StageId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;
use crate::extractors::time::parse_rfc3339;

/// Which request records to find.
///
/// At most one of `gateway_check`, `stage_id` and `stage_kind`, and at most
/// one of `user_id`, `agent_id` and `consumer_id`, may be given.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct RequestSearchParams {
    /// `allowed` or `refused`. A request that ended undecided counts as
    /// refused: the gateway refuses it too.
    pub decision: Option<String>,
    /// Only refusals by this gateway check, made before any stage ran:
    /// `tenant`, `route`, `app_sign_in`, `body_limit`, `pipeline_off`,
    /// `attack_mode` or `upstream`.
    pub gateway_check: Option<String>,
    /// Only refusals by this stage of a pipeline.
    pub stage_id: Option<Uuid>,
    /// Only refusals by any stage of this kind, such as `geo_fence`.
    pub stage_kind: Option<String>,
    /// Only refusals under the tenant policy rule of this name.
    pub rule: Option<String>,
    /// Only refusals whose reason contains this text, ignoring case.
    pub reason: Option<String>,
    /// Only requests that matched this route.
    pub route_id: Option<Uuid>,
    /// Only requests of this tenant user, directly or through an agent
    /// acting for them.
    pub user_id: Option<Uuid>,
    /// Only requests this agent made.
    pub agent_id: Option<Uuid>,
    /// Only requests this consumer made.
    pub consumer_id: Option<Uuid>,
    /// Only requests finished at or after this RFC 3339 timestamp. Named
    /// `since` because `after` is the page cursor.
    pub since: Option<String>,
    /// Only requests finished before this RFC 3339 timestamp.
    pub before: Option<String>,
}

impl RequestSearchParams {
    /// The search these parameters ask for, in `sort` order.
    ///
    /// # Errors
    ///
    /// A validation error for an unknown decision, check or stage kind, a
    /// rule name that is not one, a timestamp that is not RFC 3339, or two
    /// parameters that each name what refused, or who asked.
    pub(crate) fn search(
        &self,
        sort: SortOrder<RequestRecordSortField>,
        page: PageRequest,
    ) -> Result<SearchRequestRecordsRequest, ApiError> {
        Ok(SearchRequestRecordsRequest {
            filter: self.filter()?,
            sort,
            page,
        })
    }

    /// Every condition the query sets.
    fn filter(&self) -> Result<RequestRecordFilter, ApiError> {
        Ok(RequestRecordFilter {
            decision: decision(self.decision.as_deref())?,
            decided_by: self.decided_by()?,
            rule: self
                .rule
                .clone()
                .map(|rule| Label::new("rule", rule))
                .transpose()
                .map_err(ApiError::validation)?,
            reason_contains: self.reason.clone(),
            route: self.route_id.map(RouteId::from_uuid),
            subject: self.subject()?,
            after: self.since.as_deref().map(parse_rfc3339).transpose()?,
            before: self.before.as_deref().map(parse_rfc3339).transpose()?,
        })
    }

    /// The check the refusals are to have been made by.
    fn decided_by(&self) -> Result<DecidedByFilter, ApiError> {
        match (
            self.gateway_check.as_deref(),
            self.stage_id,
            self.stage_kind.as_deref(),
        ) {
            (None, None, None) => Ok(DecidedByFilter::Any),
            (Some(check), None, None) => GatewayCheck::parse(check)
                .map(DecidedByFilter::Gateway)
                .ok_or_else(|| {
                    ApiError::validation(message!(
                        "api-no-gateway-check-is",
                        format!("no gateway check is `{check}`")
                    ))
                }),
            (None, Some(stage), None) => Ok(DecidedByFilter::Stage(StageId::from_uuid(stage))),
            (None, None, Some(kind)) => StageKindName::parse(kind)
                .map(DecidedByFilter::StageKind)
                .ok_or_else(|| {
                    ApiError::validation(message!(
                        "api-no-stage-kind-is",
                        format!("no stage kind is `{kind}`")
                    ))
                }),
            _ => Err(ApiError::validation(message!(
                "api-give-one-of-gateway-check-stage",
                "give one of gateway_check, stage_id and stage_kind"
            ))),
        }
    }

    /// Who the records are to say was asking.
    fn subject(&self) -> Result<Option<RecordSubject>, ApiError> {
        match (self.user_id, self.agent_id, self.consumer_id) {
            (None, None, None) => Ok(None),
            (Some(user), None, None) => Ok(Some(RecordSubject::User(UserId::from_uuid(user)))),
            (None, Some(agent), None) => Ok(Some(RecordSubject::Agent(AgentId::from_uuid(agent)))),
            (None, None, Some(consumer)) => Ok(Some(RecordSubject::Consumer(
                ConsumerId::from_uuid(consumer),
            ))),
            _ => Err(ApiError::validation(message!(
                "api-give-one-of-user-id-agent",
                "give one of user_id, agent_id and consumer_id"
            ))),
        }
    }
}

/// The decision a search narrows to.
fn decision(raw: Option<&str>) -> Result<DecisionFilter, ApiError> {
    match raw {
        None => Ok(DecisionFilter::Any),
        Some("allowed") => Ok(DecisionFilter::Allowed),
        Some("refused") => Ok(DecisionFilter::Refused),
        Some(other) => Err(ApiError::validation(message!(
            "api-decision-is-allowed-or-refused-not",
            format!("decision is `allowed` or `refused`, not `{other}`")
        ))),
    }
}

/// One request the gateway decided.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RequestRecordResponse {
    /// Ties the request to its logs, traces and audit rows.
    pub correlation_id: Uuid,
    /// Who the gateway decided was asking.
    pub subject: RecordSubjectResponse,
    /// The route the request matched, `null` when none did.
    pub route_id: Option<Uuid>,
    /// The service behind that route, `null` when no route matched.
    pub service_id: Option<Uuid>,
    /// The client's address.
    pub ip_address: String,
    /// The method as it arrived.
    pub method: String,
    /// The path as it arrived.
    pub path: String,
    /// `allowed`, `refused`, or `undecided` for a request that ended
    /// without a recorded decision, which the gateway refuses too.
    pub decision: &'static str,
    /// The status returned to the client.
    pub status: u16,
    /// Why it was refused, `null` when it was not.
    pub reason: Option<String>,
    /// What refused it, `null` when nothing did.
    pub decided_by: Option<DecidedByResponse>,
    /// The tenant policy rule it was refused under, `null` when no named
    /// rule refused it.
    pub rule: Option<String>,
    /// The version of the tenant's policy that ruled on it; with the route
    /// it names the policy that decided. `null` when no version ruled: the
    /// request was settled before the policy was read, or the tenant has no
    /// live one.
    pub policy_version: Option<u32>,
    /// How long the request took, in milliseconds.
    pub duration_ms: u32,
    /// When it finished.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// The data classification levels found on it, highest first.
    #[schema(schema_with = crate::dto::schemas::data_class_level_list)]
    pub classification: Vec<DataClassLevel>,
    /// How the gateway closed the connection this request upgraded, when
    /// it closed it because the caller's access ended, a check of it failed
    /// or the credential ran out. Absent for any other connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<ConnectionCloseResponse>,
}

/// How the gateway closed a connection a request upgraded.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConnectionCloseResponse {
    /// `access_ended`, `check_failed` or `credential_expired`.
    pub reason: &'static str,
    /// When it closed.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
}

/// The body naming how a connection was closed.
fn connection_close(closed: TunnelClose) -> ConnectionCloseResponse {
    ConnectionCloseResponse {
        reason: closed.reason.as_str(),
        at: closed.at,
    }
}

/// Who a request record says was asking.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RecordSubjectResponse {
    /// `anonymous`, `user`, `agent` or `consumer`.
    pub kind: &'static str,
    /// Their id, `null` when anonymous.
    pub id: Option<Uuid>,
    /// For an agent, whom it acted for, as `<kind>:<uuid>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// For a consumer, which of its credentials it presented: `api_key`,
    /// `certificate` or `token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<&'static str>,
}

/// What refused a request.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DecidedByResponse {
    /// `gateway` for one of the gateway's own checks, `stage` for a stage
    /// of the route's pipeline.
    pub kind: &'static str,
    /// The check's or the stage kind's name, such as `pipeline_off` or
    /// `geo_fence`.
    pub name: &'static str,
    /// The stage, `null` for a gateway check.
    pub stage_id: Option<Uuid>,
}

impl From<ProxyRequestRecord> for RequestRecordResponse {
    fn from(record: ProxyRequestRecord) -> Self {
        let status = record.status();
        let (route_id, service_id) = route_ids(record.route);
        Self {
            correlation_id: *record.correlation_id.as_uuid(),
            subject: RecordSubjectResponse::from(&record.principal),
            route_id,
            service_id,
            ip_address: record.ip_address.to_string(),
            method: record.method.as_str().to_owned(),
            path: record.path.as_str().to_owned(),
            decision: decision_name(&record.outcome),
            status,
            reason: refusal_reason(&record.outcome),
            decided_by: decided_by(&record.outcome),
            rule: rule_name(&record.outcome),
            policy_version: record.policy.version().map(PolicyVersion::number),
            duration_ms: record.duration_ms,
            occurred_at: record.occurred_at,
            classification: record.classification,
            closed: record.closed.map(connection_close),
        }
    }
}

/// The route and service a request matched, if any.
fn route_ids(route: RouteMatch) -> (Option<Uuid>, Option<Uuid>) {
    match route {
        RouteMatch::NoRoute => (None, None),
        RouteMatch::Matched {
            route_id,
            service_id,
        } => (Some(*route_id.as_uuid()), Some(*service_id.as_uuid())),
    }
}

/// What a record says was decided.
fn decision_name(outcome: &RequestOutcome) -> &'static str {
    match outcome {
        RequestOutcome::Allowed { .. } => "allowed",
        RequestOutcome::Denied { .. } => "refused",
        RequestOutcome::Undecided => "undecided",
    }
}

/// Why a request was refused, if it was.
fn refusal_reason(outcome: &RequestOutcome) -> Option<String> {
    let RequestOutcome::Denied { reason, .. } = outcome else {
        return None;
    };
    Some(reason.clone())
}

/// What refused a request, if anything did.
fn decided_by(outcome: &RequestOutcome) -> Option<DecidedByResponse> {
    let RequestOutcome::Denied { decided_by, .. } = outcome else {
        return None;
    };
    Some(DecidedByResponse::from(decided_by))
}

/// The named rule a request was refused under, if any.
fn rule_name(outcome: &RequestOutcome) -> Option<String> {
    let RequestOutcome::Denied {
        rule: DecidingRule::Named(rule),
        ..
    } = outcome
    else {
        return None;
    };
    Some(rule.as_str().to_owned())
}

impl From<&DecidingStage> for DecidedByResponse {
    fn from(stage: &DecidingStage) -> Self {
        match stage {
            DecidingStage::Gateway(check) => Self {
                kind: "gateway",
                name: check.as_str(),
                stage_id: None,
            },
            DecidingStage::Stage { stage_id, kind } => Self {
                kind: "stage",
                name: kind.as_str(),
                stage_id: Some(*stage_id.as_uuid()),
            },
        }
    }
}

impl From<&ObservedPrincipal> for RecordSubjectResponse {
    fn from(principal: &ObservedPrincipal) -> Self {
        match principal {
            ObservedPrincipal::Anonymous => Self::named("anonymous", None),
            ObservedPrincipal::User(user) => Self::named("user", Some(*user.as_uuid())),
            ObservedPrincipal::Agent {
                agent_id,
                on_behalf_of,
                ..
            } => Self {
                on_behalf_of: Some(on_behalf_of.label()),
                ..Self::named("agent", Some(*agent_id.as_uuid()))
            },
            ObservedPrincipal::Consumer {
                consumer_id,
                credential,
            } => Self {
                credential: Some(credential_name(*credential)),
                ..Self::named("consumer", Some(*consumer_id.as_uuid()))
            },
        }
    }
}

impl RecordSubjectResponse {
    /// A subject of `kind` with `id` and nothing more.
    fn named(kind: &'static str, id: Option<Uuid>) -> Self {
        Self {
            kind,
            id,
            on_behalf_of: None,
            credential: None,
        }
    }
}

/// The name of the credential a consumer presented.
fn credential_name(credential: ConsumerCredential) -> &'static str {
    match credential {
        ConsumerCredential::ApiKey => "api_key",
        ConsumerCredential::Certificate => "certificate",
        ConsumerCredential::Token => "token",
    }
}
