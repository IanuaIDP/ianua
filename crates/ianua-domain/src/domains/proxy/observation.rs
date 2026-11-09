//! What the proxy observed about one finished request.
//!
//! Every proxied request produces exactly one of these. Every destination
//! that reports on traffic reads the same value: structured logs, the
//! dashboard, the access log, a metrics scrape, a trace exporter or a log
//! shipper. Adding a destination means adding an observer, not another field
//! here.
//!
//! Only what may be reported belongs here. Never a token, a header or a
//! body. Decisions are observable and credentials are not, and this type
//! keeps that rule.

mod deciding;
mod path;

use std::net::IpAddr;

pub use deciding::{DecidingRule, DecidingStage, GatewayCheck};
pub use path::ObservedPath;
use time::{Duration, OffsetDateTime};

use crate::domains::authorization::policy::version::PolicyVersion;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::proxy::access::decision::TenantRuling;
use crate::domains::proxy::request::context::ConsumerCredential;
use crate::domains::proxy::request::trace::TraceContext;
use crate::types::{
    AgentId, ConsumerId, CorrelationId, DelegationId, Fact, PrincipalRef, RouteId, ServiceId,
    TenantId, UntrustedText, UserId,
};

/// One finished proxied request, reduced to what may be reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestObservation {
    /// Ties this request to its logs, traces and audit rows.
    pub correlation_id: CorrelationId,
    /// The tenant the request resolved to. Unknown when it never did.
    pub tenant_id: Fact<TenantId>,
    /// The route that matched and the service behind it, or that none did.
    pub route: RouteMatch,
    /// The method as it arrived.
    ///
    /// The token as sent, not an [`HttpMethod`](crate::types::HttpMethod). A
    /// client may send anything, and an observation records what happened,
    /// not the nearest thing the proxy has a name for. A destination that
    /// needs a bounded set, such as a metrics label, narrows it itself. It is
    /// recorded as [`UntrustedText`], so whatever a client sent is safe to
    /// store.
    pub method: UntrustedText,
    /// The path as it arrived, before rewriting, without its query string
    /// or fragment.
    pub path: ObservedPath,
    /// The client's address as the proxy determined it.
    pub client: IpAddr,
    /// Who the proxy decided was asking.
    pub principal: ObservedPrincipal,
    /// What the proxy decided to do about it.
    pub outcome: RequestOutcome,
    /// Where this request sat in the caller's trace, when it was in one.
    ///
    /// It lets a log line, a scrape and a trace be read together. They share
    /// the identifiers a customer's own tracing uses, not a correlation id
    /// only this platform knows.
    pub trace: Traced,
    /// How long the whole request took.
    pub latency: Duration,
    /// Data classification levels found on the request, highest first.
    pub classification: Vec<DataClassLevel>,
    /// The version of the tenant's policy that ruled on it, if one did.
    pub policy: RulingPolicy,
    /// When the request finished.
    pub occurred_at: OffsetDateTime,
}

/// Which policy ruled on a request, so its record names what decided it.
///
/// A tenant has one policy, kept in numbered versions, so the tenant the
/// record belongs to and a version name it exactly: the record of a
/// request refused under version 7 still says so after version 8 goes
/// live. A route's own policy is named by the route the record names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RulingPolicy {
    /// No version of the tenant's policy ruled: the request was settled
    /// before the policy was read, the policy could not be read, or the
    /// tenant has no live one.
    #[default]
    NoTenantVersion,
    /// This version of the tenant's policy ruled.
    Tenant(PolicyVersion),
}

impl RulingPolicy {
    /// The version that ruled, when one did.
    #[must_use]
    pub fn version(self) -> Option<PolicyVersion> {
        match self {
            Self::Tenant(version) => Some(version),
            Self::NoTenantVersion => None,
        }
    }
}

impl From<&TenantRuling> for RulingPolicy {
    fn from(ruling: &TenantRuling) -> Self {
        match ruling {
            TenantRuling::Decided { version, .. } => Self::Tenant(*version),
            TenantRuling::NotReached | TenantRuling::Unreadable | TenantRuling::NoPolicy => {
                Self::NoTenantVersion
            }
        }
    }
}

/// The route a request matched, with the service behind it, or that none did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteMatch {
    /// No route matched.
    #[default]
    NoRoute,
    /// This route matched, in front of this service.
    Matched {
        /// The matching forwarding rule selected for this request.
        route_id: RouteId,
        /// The upstream service behind it.
        service_id: ServiceId,
    },
}

/// Whether a request was part of a caller's trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Traced {
    /// It carried no trace context.
    #[default]
    NotTraced,
    /// It sat here in the caller's trace.
    In(TraceContext),
}

/// Who the proxy decided was asking.
///
/// One value instead of four optional fields, because not every combination
/// is real. An agent request has a delegation and a person's does not. "An
/// agent id with no delegation" is not a state the proxy can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ObservedPrincipal {
    /// Nobody proved who they are.
    #[default]
    Anonymous,
    /// A tenant user, directly.
    User(UserId),
    /// An agent, under one delegation, acting for someone.
    Agent {
        /// The executing identity, separate from the principal it acts for.
        agent_id: AgentId,
        /// The delegation its authority came from.
        delegation_id: DelegationId,
        /// Whom it acted for. One hop down a chain this is another agent,
        /// never widened into a person.
        on_behalf_of: PrincipalRef,
    },
    /// A tenant's machine identity, with the credential it presented.
    Consumer {
        /// The external machine identity authenticated for this request.
        consumer_id: ConsumerId,
        /// Which of its credentials it presented.
        credential: ConsumerCredential,
    },
}

impl ObservedPrincipal {
    /// Whether an agent made this request.
    #[must_use]
    pub fn is_agent(&self) -> bool {
        matches!(self, Self::Agent { .. })
    }

    /// Whether a tenant's machine identity made this request.
    #[must_use]
    pub fn is_consumer(&self) -> bool {
        matches!(self, Self::Consumer { .. })
    }

    /// The person directly behind the request: the user, or the person an
    /// agent acted for when a person is its immediate delegator.
    #[must_use]
    pub fn person(&self) -> Option<&UserId> {
        match self {
            Self::User(user_id)
            | Self::Agent {
                on_behalf_of: PrincipalRef::User(user_id),
                ..
            } => Some(user_id),
            Self::Anonymous | Self::Agent { .. } | Self::Consumer { .. } => None,
        }
    }
}

/// Why the gateway closed a connection it had upgraded, as the request's
/// record keeps it. A connection either side ended, or that sat idle, has
/// no close to record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelCloseReason {
    /// The person's access ended: a check found them suspended, out of the
    /// route's group or permission, or their session ended.
    AccessEnded,
    /// A check could not be made in time or failed, so the connection
    /// closed rather than stay open undecided.
    CheckFailed,
    /// The credential the connection opened with ran out.
    CredentialExpired,
}

impl TunnelCloseReason {
    /// The stable word a request record keeps.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessEnded => "access_ended",
            Self::CheckFailed => "check_failed",
            Self::CredentialExpired => "credential_expired",
        }
    }
}

/// How the gateway closed a connection it had upgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelClose {
    /// Why it closed.
    pub reason: TunnelCloseReason,
    /// When it closed.
    pub at: OffsetDateTime,
}

/// The rule of a request no named rule refused.
static NO_RULE: DecidingRule = DecidingRule::Unnamed;

/// What the proxy decided about a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestOutcome {
    /// Forwarded, and the upstream answered with this status.
    Allowed {
        /// The status the upstream returned.
        upstream_status: u16,
    },
    /// Refused by the pipeline, with the status and the reason given.
    Denied {
        /// The status returned to the client.
        status: u16,
        /// Why the request was refused. A stage's own words, never a
        /// credential or anything derived from one.
        reason: String,
        /// Which check refused it: a gateway check or a pipeline stage.
        decided_by: DecidingStage,
        /// The named rule it was refused under, when there is one.
        rule: DecidingRule,
    },
    /// The request ended without the proxy recording a decision.
    ///
    /// The proxy denies by default, so a client gains nothing here. But it is
    /// worth reporting loudly. It means a code path returned without saying
    /// what it decided.
    Undecided,
}

impl RequestOutcome {
    /// The status the client saw.
    ///
    /// An undecided request reports `500`. Nothing was served, and any other
    /// status would hide a proxy bug inside the success rate.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::Allowed { upstream_status } => *upstream_status,
            Self::Denied { status, .. } => *status,
            Self::Undecided => 500,
        }
    }
}

impl RequestObservation {
    /// The status the client saw, as [`RequestOutcome::status`] reads it.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.outcome.status()
    }

    /// Whether the pipeline let the request through.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self.outcome, RequestOutcome::Allowed { .. })
    }

    /// Why the request was refused, when it was.
    #[must_use]
    pub fn denial_reason(&self) -> Option<&str> {
        let RequestOutcome::Denied { reason, .. } = &self.outcome else {
            return None;
        };
        Some(reason.as_str())
    }

    /// Which check refused the request, when it was refused.
    #[must_use]
    pub fn decided_by(&self) -> Option<&DecidingStage> {
        let RequestOutcome::Denied { decided_by, .. } = &self.outcome else {
            return None;
        };
        Some(decided_by)
    }

    /// The named rule the request was refused under. Unnamed when it was
    /// refused by no named rule, or not refused at all.
    #[must_use]
    pub fn deciding_rule(&self) -> &DecidingRule {
        let RequestOutcome::Denied { rule, .. } = &self.outcome else {
            return &NO_RULE;
        };
        rule
    }

    /// The status class, such as `2xx` or `4xx`, as a metrics label.
    ///
    /// One label of five values, not one of hundreds. A scrape wants to know
    /// how much traffic failed. A series per distinct status lets a client
    /// that probes many statuses overwhelm the metrics store.
    #[must_use]
    pub fn status_class(&self) -> &'static str {
        status_class(self.status())
    }
}

/// The class of `status`, such as `2xx` or `4xx`, as a metrics label.
///
/// Five values for any status at all. A status outside `100..=499`, real
/// or not, is `5xx`: a reply nobody can read as success is counted as a
/// failure.
#[must_use]
pub fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::policy::simulator::AuditMark;
    use crate::domains::proxy::access::decision::SettledBy;
    use crate::domains::proxy::stages::stage::StageKindName;

    /// Each way a connection is closed keeps the word its record stores.
    #[test]
    fn close_reasons_keep_their_words() {
        assert_eq!(TunnelCloseReason::AccessEnded.as_str(), "access_ended");
        assert_eq!(TunnelCloseReason::CheckFailed.as_str(), "check_failed");
        assert_eq!(
            TunnelCloseReason::CredentialExpired.as_str(),
            "credential_expired"
        );
    }

    fn observation(outcome: RequestOutcome) -> RequestObservation {
        RequestObservation {
            correlation_id: CorrelationId::new(),
            tenant_id: Fact::Known(TenantId::new()),
            route: RouteMatch::Matched {
                route_id: RouteId::new(),
                service_id: ServiceId::new(),
            },
            method: UntrustedText::record("GET"),
            path: ObservedPath::record("/reports"),
            client: IpAddr::from([203, 0, 113, 1]),
            principal: ObservedPrincipal::default(),
            outcome,
            trace: Traced::NotTraced,
            latency: Duration::milliseconds(12),
            classification: Vec::new(),
            policy: RulingPolicy::NoTenantVersion,
            occurred_at: crate::shared::clock::now(),
        }
    }

    /// The tenant's policy at version 7 decides. The observation names
    /// version 7; a request refused before the policy was read names none.
    #[test]
    fn the_ruling_policy_is_the_version_that_decided() {
        let seven = PolicyVersion::parse(7).unwrap();
        let decided = TenantRuling::Decided {
            version: seven,
            settled_by: SettledBy::Default,
            audit: AuditMark::default(),
        };

        assert_eq!(RulingPolicy::from(&decided).version(), Some(seven));
        assert_eq!(
            RulingPolicy::from(&TenantRuling::NotReached),
            RulingPolicy::NoTenantVersion
        );
    }

    /// A billing service calls with an API key. Its request is recorded as
    /// that consumer, not as anonymous, and names no person.
    #[test]
    fn a_consumer_request_is_not_anonymous() {
        let principal = ObservedPrincipal::Consumer {
            consumer_id: ConsumerId::new(),
            credential: ConsumerCredential::ApiKey,
        };

        assert!(principal.is_consumer());
        assert_ne!(principal, ObservedPrincipal::Anonymous);
        assert_eq!(principal.person(), None);
    }

    /// A forwarded request whose upstream answered 201 reports 201, counts as
    /// allowed and has no denial reason.
    #[test]
    fn an_allowed_request_reports_the_upstreams_status() {
        let observed = observation(RequestOutcome::Allowed {
            upstream_status: 201,
        });

        assert_eq!(observed.status(), 201);
        assert!(observed.is_allowed());
        assert_eq!(observed.denial_reason(), None);
    }

    /// A request the policy denied with 403 reports 403, counts as not
    /// allowed and keeps the reason "policy denied".
    #[test]
    fn a_denied_request_reports_the_status_it_returned() {
        let observed = observation(RequestOutcome::Denied {
            status: 403,
            reason: "policy denied".to_owned(),
            decided_by: DecidingStage::Gateway(GatewayCheck::Route),
            rule: DecidingRule::Unnamed,
        });

        assert_eq!(observed.status(), 403);
        assert!(!observed.is_allowed());
        assert_eq!(observed.denial_reason(), Some("policy denied"));
    }

    /// The Policy stage refuses Sam under the tenant rule "contractors off
    /// hours". The record names the stage and the rule, so an admin
    /// searching the log sees why.
    #[test]
    fn a_denied_request_records_the_stage_and_rule_that_decided() {
        let stage_id = crate::types::StageId::new();
        let rule =
            DecidingRule::Named(crate::types::Label::new("name", "contractors off hours").unwrap());
        let observed = observation(RequestOutcome::Denied {
            status: 403,
            reason: "policy denied".to_owned(),
            decided_by: DecidingStage::Stage {
                stage_id,
                kind: StageKindName::Policy,
            },
            rule: rule.clone(),
        });

        assert_eq!(
            observed.decided_by(),
            Some(&DecidingStage::Stage {
                stage_id,
                kind: StageKindName::Policy
            })
        );
        assert_eq!(observed.deciding_rule(), &rule);
    }

    /// A request let through names no deciding stage and no rule.
    #[test]
    fn an_allowed_request_names_no_deciding_stage() {
        let observed = observation(RequestOutcome::Allowed {
            upstream_status: 200,
        });

        assert_eq!(observed.decided_by(), None);
        assert_eq!(observed.deciding_rule(), &DecidingRule::Unnamed);
    }

    /// A request that ended with no recorded decision reports 500 and
    /// `5xx`. It is a proxy bug, so it shows in the error rate, not the
    /// success rate.
    #[test]
    fn an_undecided_request_counts_as_a_server_error() {
        let observed = observation(RequestOutcome::Undecided);

        assert_eq!(observed.status(), 500);
        assert_eq!(observed.status_class(), "5xx");
        assert!(!observed.is_allowed());
    }

    /// 100, 204, 301, 404 and 503 fall into `1xx` through `5xx`, one class
    /// each.
    #[test]
    fn status_classes_cover_every_status() {
        for (status, expected) in [
            (100, "1xx"),
            (204, "2xx"),
            (301, "3xx"),
            (404, "4xx"),
            (503, "5xx"),
        ] {
            let observed = observation(RequestOutcome::Allowed {
                upstream_status: status,
            });
            assert_eq!(observed.status_class(), expected, "status {status}");
        }
    }

    /// Out-of-range statuses 42 and 999 map to `5xx`, while the valid
    /// success status 201 maps to `2xx`.
    #[test]
    fn a_status_outside_the_classes_counts_as_a_server_error() {
        assert_eq!(status_class(42), "5xx");
        assert_eq!(status_class(999), "5xx");
        assert_eq!(status_class(201), "2xx");
    }

    /// An agent acting for Ann is reported as an agent, and Ann is the
    /// person behind it. An anonymous request is not an agent.
    #[test]
    fn a_request_with_an_agent_is_reported_as_one() {
        let person = UserId::new();
        let principal = ObservedPrincipal::Agent {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            on_behalf_of: PrincipalRef::User(person),
        };

        assert!(principal.is_agent());
        assert_eq!(principal.person(), Some(&person));
        assert!(!ObservedPrincipal::default().is_agent());
    }
}
