//! What happened to one request, collected while it is in flight and
//! reported once when it ends.
//!
//! Only collects. Where the report goes (the request records, the live
//! dashboard, the logs, the metrics, a trace collector, a tenant's log
//! store) is the observer's business, and this type does not know how many
//! there are.
//!
//! Nothing secret can get in. The path is cut at its query string as it
//! arrives, a refusal's reason is a fixed word from the code or the words
//! of the stage that refused, and there is no setter for a header, a
//! cookie, a token or a body.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use ianua_app::ports::runtime::RequestObserver;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::access::decision::TenantRuling;
use ianua_domain::domains::proxy::observation::{
    DecidingRule, DecidingStage, ObservedPath, ObservedPrincipal, RequestObservation,
    RequestOutcome, RouteMatch, RulingPolicy, Traced, TunnelClose, TunnelCloseReason,
};
use ianua_domain::domains::proxy::request::trace::TraceContext;
use ianua_domain::shared::clock;
use ianua_domain::types::{
    CorrelationId, DenialStatus, Fact, RouteId, ServiceId, TenantId, UntrustedText,
};
use time::Duration;

/// How a request arrived, before anything about it was decided.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Arrival<'a> {
    /// The id tying the request to its logs, traces and records.
    pub correlation_id: CorrelationId,
    /// The client's address, as the listener determined it.
    pub client: IpAddr,
    /// The method as it arrived.
    pub method: &'a str,
    /// The request target as it arrived; everything from its first `?` or
    /// `#` is cut before it is kept.
    pub target: &'a str,
}

/// Why a request was refused, as its record keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    status: DenialStatus,
    reason: Cow<'static, str>,
    decided_by: DecidingStage,
    rule: DecidingRule,
}

impl Refusal {
    /// A refusal answered with `status`, recorded with `reason`: a fixed
    /// word from the code, never anything the request carried.
    #[must_use]
    pub(crate) fn new(
        status: DenialStatus,
        reason: &'static str,
        decided_by: DecidingStage,
    ) -> Self {
        Self {
            status,
            reason: Cow::Borrowed(reason),
            decided_by,
            rule: DecidingRule::Unnamed,
        }
    }

    /// A refusal a pipeline stage made, answered with `status` and recorded
    /// with the reason the stage gave: the stage's own words, which name
    /// what it checked and never what the request carried.
    #[must_use]
    pub(crate) fn by_stage(status: DenialStatus, reason: &str, decided_by: DecidingStage) -> Self {
        Self {
            status,
            reason: Cow::Owned(reason.to_owned()),
            decided_by,
            rule: DecidingRule::Unnamed,
        }
    }

    /// The same refusal, made under the tenant policy rule `rule`.
    #[must_use]
    pub(crate) fn under(self, rule: DecidingRule) -> Self {
        Self { rule, ..self }
    }

    /// Lets handler tests compare the recorded refusal with the client's status.
    #[cfg(test)]
    pub(crate) fn status(&self) -> DenialStatus {
        self.status
    }

    /// The outcome a record keeps.
    fn into_outcome(self) -> RequestOutcome {
        RequestOutcome::Denied {
            status: self.status.code(),
            reason: self.reason.into_owned(),
            decided_by: self.decided_by,
            rule: self.rule,
        }
    }
}

/// The status a request's record keeps for a protocol switch.
const SWITCHED_PROTOCOLS: u16 = 101;

/// What a tunnel keeps to report, later, why the gateway closed it: the
/// record of the request that opened it, ready for the close.
///
/// It holds nothing the record does not: a tunnel outliving its handshake
/// carries no header or token through this.
#[derive(Clone)]
pub(crate) struct TunnelCloseRecord {
    observation: RequestObservation,
    started: Instant,
    observer: Arc<dyn RequestObserver>,
}

impl TunnelCloseRecord {
    /// Reports that the gateway closed the tunnel for `reason`, on the
    /// record of the request that opened it.
    pub(crate) fn report(&self, reason: TunnelCloseReason) {
        let closed = TunnelClose {
            reason,
            at: clock::now(),
        };
        let observation = RequestObservation {
            occurred_at: closed.at,
            latency: Duration::try_from(self.started.elapsed()).unwrap_or(Duration::MAX),
            ..self.observation.clone()
        };
        self.observer.observe_tunnel_close(&observation, closed);
    }

    /// A record nobody hears, for a test that forwards without a request's
    /// report.
    #[cfg(test)]
    pub(crate) fn unobserved() -> Self {
        let arrival = Arrival {
            correlation_id: CorrelationId::new(),
            client: IpAddr::from([198, 51, 100, 7]),
            method: "GET",
            target: "/",
        };
        RequestAudit::start(
            arrival,
            Arc::new(ianua_app::ports::runtime::RequestObservers::none()),
        )
        .tunnel_close_record()
    }
}

/// Whether the request was already reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reported {
    /// Not yet: dropping it reports it as undecided.
    Pending,
    /// Once, with its decision.
    Done,
}

/// Collects what is known about one request and reports it once.
///
/// A request that ends with [`report_allowed`](Self::report_allowed) or
/// [`report_refused`](Self::report_refused) is reported with that decision. One dropped
/// without either is still reported, as undecided: the gateway refuses it
/// by default, and a record that never arrives would hide the bug that
/// left it undecided.
pub(crate) struct RequestAudit {
    correlation_id: CorrelationId,
    client: IpAddr,
    method: UntrustedText,
    path: ObservedPath,
    tenant: Fact<TenantId>,
    route: RouteMatch,
    principal: ObservedPrincipal,
    trace: Traced,
    classification: Vec<DataClassLevel>,
    policy: RulingPolicy,
    started: Instant,
    observer: Arc<dyn RequestObserver>,
    reported: Reported,
}

impl RequestAudit {
    /// Starts the record of a request as it arrived, to be reported to
    /// `observer`.
    #[must_use]
    pub(crate) fn start(arrival: Arrival<'_>, observer: Arc<dyn RequestObserver>) -> Self {
        Self {
            correlation_id: arrival.correlation_id,
            client: arrival.client,
            method: UntrustedText::record(arrival.method),
            path: ObservedPath::record(arrival.target),
            tenant: Fact::Unknown,
            route: RouteMatch::NoRoute,
            principal: ObservedPrincipal::Anonymous,
            trace: Traced::NotTraced,
            classification: Vec::new(),
            policy: RulingPolicy::NoTenantVersion,
            started: Instant::now(),
            observer,
            reported: Reported::Pending,
        }
    }

    /// The tenant the request's host resolved to.
    pub(crate) fn record_tenant(&mut self, tenant: TenantId) {
        self.tenant = Fact::Known(tenant);
    }

    /// The route that matched, in front of `service`.
    pub(crate) fn record_route(&mut self, route: RouteId, service: ServiceId) {
        self.route = RouteMatch::Matched {
            route_id: route,
            service_id: service,
        };
    }

    /// Who the gateway decided was asking.
    pub(crate) fn record_principal(&mut self, principal: ObservedPrincipal) {
        self.principal = principal;
    }

    /// The trace context the gateway passed upstream, naming its own span.
    pub(crate) fn record_trace(&mut self, trace: TraceContext) {
        self.trace = Traced::In(trace);
    }

    /// The data classification levels found on the request, highest first.
    pub(crate) fn record_classification(&mut self, levels: Vec<DataClassLevel>) {
        self.classification = levels;
    }

    /// What the tenant's policy had to do with the access decision, so the
    /// record names the version that ruled.
    pub(crate) fn record_ruling(&mut self, ruling: &TenantRuling) {
        self.policy = RulingPolicy::from(ruling);
    }

    /// What the tunnel this request may open keeps to report its close,
    /// as far as the request is known now. A request that opens no tunnel
    /// never reports it.
    #[must_use]
    pub(crate) fn tunnel_close_record(&self) -> TunnelCloseRecord {
        TunnelCloseRecord {
            observation: self.observation(RequestOutcome::Allowed {
                upstream_status: SWITCHED_PROTOCOLS,
            }),
            started: self.started,
            observer: Arc::clone(&self.observer),
        }
    }

    /// Reports the request as forwarded, the upstream answering
    /// `upstream_status`.
    pub(crate) fn report_allowed(mut self, upstream_status: u16) {
        self.report(RequestOutcome::Allowed { upstream_status });
    }

    /// Reports the request as refused for `refusal`.
    pub(crate) fn report_refused(mut self, refusal: Refusal) {
        self.report(refusal.into_outcome());
    }

    /// Reports the request with `outcome`, once.
    fn report(&mut self, outcome: RequestOutcome) {
        self.reported = Reported::Done;
        let observation = self.observation(outcome);
        self.observer.observe(&observation);
    }

    /// What is known about the request, ended with `outcome`.
    fn observation(&self, outcome: RequestOutcome) -> RequestObservation {
        RequestObservation {
            correlation_id: self.correlation_id,
            tenant_id: self.tenant,
            route: self.route,
            method: self.method.clone(),
            path: self.path.clone(),
            client: self.client,
            principal: self.principal,
            outcome,
            trace: self.trace,
            latency: Duration::try_from(self.started.elapsed()).unwrap_or(Duration::MAX),
            classification: self.classification.clone(),
            policy: self.policy,
            occurred_at: clock::now(),
        }
    }
}

/// Reports a request no path decided, as undecided.
impl Drop for RequestAudit {
    fn drop(&mut self) {
        if self.reported == Reported::Done {
            return;
        }
        self.report(RequestOutcome::Undecided);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ianua_domain::domains::proxy::access::decision::DenyCode;
    use ianua_domain::domains::proxy::observation::GatewayCheck;
    use ianua_domain::types::{AgentId, DelegationId, PrincipalRef, UserId};

    use super::*;

    /// Keeps what it heard, so a test reads what the gateway reported.
    #[derive(Default)]
    struct Heard(Mutex<Vec<RequestObservation>>);

    impl RequestObserver for Heard {
        fn observe(&self, observation: &RequestObservation) {
            self.0.lock().unwrap().push(observation.clone());
        }
    }

    impl Heard {
        fn reports(&self) -> Vec<RequestObservation> {
            self.0.lock().unwrap().clone()
        }
    }

    fn audit(heard: &Arc<Heard>, target: &str) -> RequestAudit {
        RequestAudit::start(
            Arrival {
                correlation_id: CorrelationId::new(),
                client: IpAddr::from([203, 0, 113, 9]),
                method: "GET",
                target,
            },
            Arc::clone(heard) as Arc<dyn RequestObserver>,
        )
    }

    /// Ann's request is forwarded and the upstream answers 201. It is
    /// reported once, allowed, with her as the subject and the route.
    #[test]
    fn a_forwarded_request_is_reported_once_with_its_subject() {
        let heard = Arc::new(Heard::default());
        let ann = UserId::new();
        let route = RouteId::new();
        let mut audit = audit(&heard, "/reports");
        audit.record_tenant(TenantId::new());
        audit.record_route(route, ServiceId::new());
        audit.record_principal(ObservedPrincipal::User(ann));

        audit.report_allowed(201);

        let reports = heard.reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].status(), 201);
        assert_eq!(reports[0].principal, ObservedPrincipal::User(ann));
        assert!(matches!(
            reports[0].route,
            RouteMatch::Matched { route_id, .. } if route_id == route
        ));
    }

    /// The policy refuses Sam for a missing permission. The record keeps
    /// the domain's deny code and the status the code gives.
    #[test]
    fn a_refusal_keeps_the_domains_deny_code() {
        let heard = Arc::new(Heard::default());
        let audit = audit(&heard, "/admin");

        audit.report_refused(Refusal::new(
            DenyCode::PermissionMissing.status(),
            DenyCode::PermissionMissing.as_str(),
            DecidingStage::Gateway(GatewayCheck::Route),
        ));

        let reports = heard.reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].status(), 403);
        assert_eq!(reports[0].denial_reason(), Some("permission_missing"));
    }

    /// Version 3 of Acme's policy refuses Sam. The report names version 3,
    /// so the record says which policy decided.
    #[test]
    fn a_report_names_the_policy_version_that_ruled() {
        use ianua_domain::domains::authorization::policy::simulator::AuditMark;
        use ianua_domain::domains::authorization::policy::version::PolicyVersion;
        use ianua_domain::domains::proxy::access::decision::SettledBy;

        let heard = Arc::new(Heard::default());
        let mut audit = audit(&heard, "/admin");
        let three = PolicyVersion::parse(3).unwrap();
        audit.record_ruling(&TenantRuling::Decided {
            version: three,
            settled_by: SettledBy::Default,
            audit: AuditMark::default(),
        });

        audit.report_refused(Refusal::new(
            DenyCode::PermissionMissing.status(),
            DenyCode::PermissionMissing.as_str(),
            DecidingStage::Gateway(GatewayCheck::Route),
        ));

        assert_eq!(heard.reports()[0].policy, RulingPolicy::Tenant(three));
    }

    /// Dropping an audit without a decision emits one report with an
    /// undecided outcome.
    #[test]
    fn a_request_nothing_decided_is_still_reported() {
        let heard = Arc::new(Heard::default());

        drop(audit(&heard, "/reports"));

        let reports = heard.reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].outcome, RequestOutcome::Undecided);
    }

    /// Reporting a callback request preserves its path in debug output
    /// while excluding the code and access-token values from its query.
    #[test]
    fn a_query_string_never_reaches_the_report() {
        let heard = Arc::new(Heard::default());
        let audit = audit(
            &heard,
            "/callback?code=s3cr3t-code&access_token=eyJabc#frag",
        );

        audit.report_allowed(302);

        let printed = format!("{:?}", heard.reports());
        assert!(printed.contains("/callback"));
        assert!(!printed.contains("s3cr3t"), "{printed}");
        assert!(!printed.contains("eyJ"), "{printed}");
    }

    /// An agent acting for Ann is reported as the agent, under its
    /// delegation, on her behalf.
    #[test]
    fn an_agent_is_reported_with_whom_it_acted_for() {
        let heard = Arc::new(Heard::default());
        let ann = UserId::new();
        let mut audit = audit(&heard, "/orders");
        audit.record_principal(ObservedPrincipal::Agent {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            on_behalf_of: PrincipalRef::User(ann),
        });

        audit.report_allowed(200);

        assert_eq!(heard.reports()[0].principal.person(), Some(&ann));
    }
}
