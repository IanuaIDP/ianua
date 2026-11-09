//! Admit an agent's request past the controls the gateway applies only to
//! agents, after policy has allowed it and before it is forwarded.
//!
//! Policy decides whether a principal may make a request. These decide
//! whether an agent may make it now: what its parameters name, how
//! sensitive the data its task may reach is, where the data it has touched
//! may go, and whether a person approved it. Any answer other than a clear
//! yes refuses, no answer included.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::ActionApproval;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::matching::parameter::{
    BodyFields, ParameterRule, ParameterViolation, RawQuery, RequestParameters, RouteReach, check,
    needs_approval_for_agents,
};
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{AgentId, ApprovalId, DeclaredAction, DelegationId, HttpMethod};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentExposureGate, GatedAction};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::approvals::{ApprovalGate, GateActionUseCase};

/// What the agent's task token confines it to, as far as these controls
/// read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskLimits {
    /// The most sensitive data the task may reach, from the `dcl` claim.
    pub max_data_class: Restriction<DataClassLevel>,
    /// Whether a person approves each action, from the `apr` claim.
    pub approval: ActionApproval,
}

/// The route the request matched, as far as these controls read it.
#[derive(Debug, Clone)]
pub struct AgentRoute {
    /// The class of the data the route serves.
    pub data_class: DataClassLevel,
    /// Whether the route's service goes where it is told.
    pub reach: RouteReach,
    /// Which hosts the route's URL parameters may name.
    pub parameter_rules: Vec<ParameterRule>,
    /// The kind of action the route declares, if it declares one.
    pub declared: DeclaredAction,
}

/// What the request carries, as the gateway read it, for the route's
/// parameter rules.
#[derive(Debug, Clone)]
pub struct CarriedValues {
    /// The raw query string, without its `?`, or `None` when the URL had
    /// none.
    pub query: Option<String>,
    /// The body's top-level fields, read from the prefix the gateway
    /// peeked. A body that is not a whole JSON object is
    /// [`BodyFields::Unreadable`], never empty.
    pub body: BodyFields,
    /// What the route's pattern captured from the path, by name.
    pub captured: Vec<(String, String)>,
    /// The request's headers, as sent.
    pub headers: Vec<(String, String)>,
}

/// One agent request policy allowed, to be admitted.
#[derive(Debug, Clone)]
pub struct AdmitActionRequest {
    /// The agent making it.
    pub agent_id: AgentId,
    /// The delegation its task token was minted from.
    pub delegation_id: DelegationId,
    /// What its task token confines it to.
    pub limits: TaskLimits,
    /// The route it matched.
    pub route: AgentRoute,
    /// The method of the request.
    pub method: HttpMethod,
    /// The normalized path policy decided on.
    pub path: String,
    /// What it carries.
    pub carried: CarriedValues,
}

impl AdmitActionRequest {
    /// The exact action a person approves: the method and the normalized
    /// path with its query. The body is not part of it: the gateway decides
    /// on metadata and streams the body, so an approval binds what is
    /// addressed, not what is sent.
    fn gated(&self) -> GatedAction {
        let target = match &self.carried.query {
            Some(query) => format!("{}?{query}", self.path),
            None => self.path.clone(),
        };
        GatedAction {
            agent_id: self.agent_id,
            delegation_id: self.delegation_id,
            method: self.method,
            target,
            declared: self.route.declared,
        }
    }

    /// Whether a person must approve this request: because its delegation
    /// asks for that, or because the route goes where it is told and has
    /// no parameter rules to hold it.
    fn needs_approval(&self) -> bool {
        self.limits.approval == ActionApproval::PerAction
            || needs_approval_for_agents(self.route.reach, &self.route.parameter_rules)
    }
}

/// Why an agent's request was refused. The reasons are the gateway's own
/// and never repeat a value the agent sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRefusal {
    /// Its parameters name a host the route's rules do not allow, are
    /// oddly encoded, or carry an address no rule covers.
    Parameters(ParameterViolation),
    /// The route serves data more sensitive than the agent's task allows.
    AboveTask,
    /// The agent has touched data this route is not cleared for.
    AboveExposure,
    /// Too many of its actions already await a person's approval.
    TooManyAwaiting,
}

impl AgentRefusal {
    /// A short reason for the refusal's record.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Parameters(violation) => violation.reason(),
            Self::AboveTask => {
                "the route serves data more sensitive than the agent's task allows".to_owned()
            }
            Self::AboveExposure => {
                "the agent has touched data this route is not cleared for".to_owned()
            }
            Self::TooManyAwaiting => "too many actions are already awaiting approval".to_owned(),
        }
    }
}

/// What came of admitting an agent's request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Every control let it through: forward it.
    Admitted,
    /// It waits on a person's decision on the named request: refuse it
    /// for now, naming the request.
    AwaitingApproval(ApprovalId),
    /// The action is denied for the attached policy reason.
    Refused(AgentRefusal),
}

/// The ports [`AdmitActionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AdmitActionPorts {
    /// Holds each agent's data-class high-water mark.
    pub exposure: Arc<dyn AgentExposureGate>,
}

/// Applies every agent-only control to a request policy allowed.
pub struct AdmitActionUseCase {
    ports: AdmitActionPorts,
    gate: Arc<GateActionUseCase>,
}

impl AdmitActionUseCase {
    /// Admits through `ports`, asking `gate` about the actions a person
    /// must approve.
    #[must_use]
    pub fn new(ports: AdmitActionPorts, gate: Arc<GateActionUseCase>) -> Self {
        Self { ports, gate }
    }
}

impl Command for AdmitActionUseCase {
    type Caller = ScopedTenant;
    type Input = AdmitActionRequest;
    type Output = Result<Admission, AppError>;

    /// Applies the controls in order: what the request's parameters name,
    /// how sensitive the data its task may reach is, where the agent's data
    /// may go, then whether a person approved it. Exposure is checked, and
    /// the agent's mark raised to the route's class, before approval, so an
    /// action a person approves is never one the agent could not have made
    /// anyway.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the exposure mark cannot be read or
    ///   raised, or the approval gate cannot be asked.
    /// - Anything [`GateActionUseCase`] reports.
    ///
    /// The gateway refuses the request on any error: a control that gave no
    /// answer is a closed one.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: AdmitActionRequest,
    ) -> Result<Admission, AppError> {
        if let Some(refusal) = refusal_before_exposure(&req) {
            return Ok(Admission::Refused(refusal));
        }
        let cleared = self
            .ports
            .exposure
            .admit(tenant, &req.agent_id, req.route.data_class)
            .await
            .or_internal()?;
        if !cleared {
            return Ok(Admission::Refused(AgentRefusal::AboveExposure));
        }
        if !req.needs_approval() {
            return Ok(Admission::Admitted);
        }
        let gate = self.gate.execute(tenant, auditor, req.gated()).await?;
        Ok(admission_of(gate))
    }
}

/// What refuses the request before its exposure is asked: its parameters,
/// then its task's data class. `None` when neither does.
fn refusal_before_exposure(req: &AdmitActionRequest) -> Option<AgentRefusal> {
    if let Err(violation) = screen(req) {
        return Some(AgentRefusal::Parameters(violation));
    }
    let above_task = req
        .limits
        .max_data_class
        .limit()
        .is_some_and(|cap| req.route.data_class > *cap);
    above_task.then_some(AgentRefusal::AboveTask)
}

/// Screens what the request carries against the route's parameter rules.
fn screen(req: &AdmitActionRequest) -> Result<(), ParameterViolation> {
    let carried = &req.carried;
    let query = match &carried.query {
        Some(query) => RawQuery::Present(query),
        None => RawQuery::Absent,
    };
    check(
        &req.route.parameter_rules,
        &RequestParameters {
            query,
            body: &carried.body,
            captured: &carried.captured,
            headers: &carried.headers,
        },
    )
}

/// What the gate's answer comes to for the request.
fn admission_of(gate: ApprovalGate) -> Admission {
    match gate {
        ApprovalGate::Admitted => Admission::Admitted,
        ApprovalGate::AwaitingDecision { approval_id, .. } => {
            Admission::AwaitingApproval(approval_id)
        }
        ApprovalGate::TooManyOpen => Admission::Refused(AgentRefusal::TooManyAwaiting),
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::agents::identity::exposure_reset::ExposureReset;
    use ianua_domain::domains::routing::matching::parameter::{BodyValue, ParameterLocation};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::DomainName;

    use super::*;
    use crate::ports::TenantScoped;
    use crate::test_support::agents::{FakeApprovalBroker, FakeExposureGate};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::agents::approvals::GateActionPorts;

    /// The gateway's agent controls, over an exposure gate and an API that
    /// answers approval questions.
    struct Controls {
        use_case: AdmitActionUseCase,
        exposure: Arc<FakeExposureGate>,
        broker: Arc<FakeApprovalBroker>,
    }

    fn controls() -> Controls {
        controls_with(Arc::new(FakeApprovalBroker::answering()))
    }

    fn controls_with(broker: Arc<FakeApprovalBroker>) -> Controls {
        let exposure = Arc::new(FakeExposureGate::default());
        let gate = GateActionUseCase::new(GateActionPorts {
            broker: broker.clone(),
        });
        Controls {
            use_case: AdmitActionUseCase::new(
                AdmitActionPorts {
                    exposure: exposure.clone(),
                },
                Arc::new(gate),
            ),
            exposure,
            broker,
        }
    }

    impl Controls {
        fn admit(&self, req: AdmitActionRequest) -> Result<Admission, AppError> {
            block_on(self.use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(Arc::new(FakeEventDispatcher::new())),
                req,
            ))
        }
    }

    /// A fetcher whose `url` parameter may name `api.partner.test` only.
    fn fetcher_rules() -> Vec<ParameterRule> {
        vec![
            ParameterRule::new(
                "url",
                ParameterLocation::Query,
                vec![DomainName::new("api.partner.test").unwrap()],
            )
            .unwrap(),
        ]
    }

    /// An agent's `GET /orders` to a fixed, internal route, under a task
    /// with no limits these controls read.
    fn request() -> AdmitActionRequest {
        AdmitActionRequest {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            limits: TaskLimits {
                max_data_class: Restriction::Unrestricted,
                approval: ActionApproval::NotRequired,
            },
            route: AgentRoute {
                data_class: DataClassLevel::Internal,
                reach: RouteReach::Fixed,
                parameter_rules: Vec::new(),
                declared: DeclaredAction::Undeclared,
            },
            method: HttpMethod::Get,
            path: "/orders".to_owned(),
            carried: CarriedValues {
                query: None,
                body: BodyFields::None,
                captured: Vec::new(),
                headers: Vec::new(),
            },
        }
    }

    fn fetch(query: &str) -> AdmitActionRequest {
        let mut req = request();
        req.route.reach = RouteReach::OpenEnded;
        req.route.parameter_rules = fetcher_rules();
        req.path = "/fetch".to_owned();
        req.carried.query = Some(query.to_owned());
        req
    }

    /// The agent reads orders on a route its task and its exposure allow.
    /// It is admitted, and its mark rises to the route's class.
    #[test]
    fn a_request_every_control_allows_is_admitted() {
        let c = controls();
        let req = request();
        let agent = req.agent_id;

        let admission = c.admit(req).unwrap();

        assert_eq!(admission, Admission::Admitted);
        assert_eq!(
            c.exposure.of(&test_ctx().tenant(), &agent),
            DataClassLevel::Internal
        );
    }

    /// The agent asks the fetcher for the partner's API, the one host its
    /// rule allows. It is admitted without a person.
    #[test]
    fn a_parameter_naming_an_allowed_host_is_admitted() {
        let c = controls();

        let admission = c.admit(fetch("url=https://api.partner.test/x")).unwrap();

        assert_eq!(admission, Admission::Admitted);
    }

    /// A fetch parameter naming an unlisted host is refused while the
    /// agent's exposure remains public.
    #[test]
    fn a_parameter_naming_another_host_is_refused() {
        let c = controls();
        let req = fetch("url=https://evil.example/x");
        let agent = req.agent_id;

        let admission = c.admit(req).unwrap();

        assert!(matches!(
            admission,
            Admission::Refused(AgentRefusal::Parameters(
                ParameterViolation::HostNotAllowed(_)
            ))
        ));
        assert_eq!(
            c.exposure.of(&test_ctx().tenant(), &agent),
            DataClassLevel::Public
        );
    }

    /// An unreadable body fails parameter screening even when the query
    /// names an allowed host.
    #[test]
    fn an_unreadable_body_under_rules_is_refused() {
        let c = controls();
        let mut req = fetch("url=https://api.partner.test/x");
        req.carried.body = BodyFields::Unreadable;

        let admission = c.admit(req).unwrap();

        assert_eq!(
            admission,
            Admission::Refused(AgentRefusal::Parameters(ParameterViolation::BodyUnreadable))
        );
    }

    /// An address in an uncovered body field is refused as an undeclared
    /// parameter.
    #[test]
    fn an_address_in_an_undeclared_field_is_refused() {
        let c = controls();
        let mut req = fetch("url=https://api.partner.test/x");
        req.carried.body = BodyFields::Fields(vec![(
            "callback".to_owned(),
            BodyValue::Text("https://evil.example/hook".to_owned()),
        )]);

        let admission = c.admit(req).unwrap();

        assert!(matches!(
            admission,
            Admission::Refused(AgentRefusal::Parameters(ParameterViolation::Undeclared(_)))
        ));
    }

    /// A task limited to internal data is refused on a restricted-data route.
    #[test]
    fn a_route_above_the_tasks_class_is_refused() {
        let c = controls();
        let mut req = request();
        req.limits.max_data_class = Restriction::To(DataClassLevel::Internal);
        req.route.data_class = DataClassLevel::Restricted;

        let admission = c.admit(req).unwrap();

        assert_eq!(admission, Admission::Refused(AgentRefusal::AboveTask));
    }

    /// An agent marked with restricted exposure is refused on a public route.
    #[test]
    fn a_route_below_the_agents_exposure_is_refused() {
        let c = controls();
        let mut req = request();
        c.exposure.set(
            &test_ctx().tenant(),
            req.agent_id,
            DataClassLevel::Restricted,
        );
        req.route.data_class = DataClassLevel::Public;

        let admission = c.admit(req).unwrap();

        assert_eq!(admission, Admission::Refused(AgentRefusal::AboveExposure));
    }

    /// The agent's delegation asks a person to approve each action. Its
    /// first attempt waits on a person and is not forwarded.
    #[test]
    fn an_action_its_delegation_gates_awaits_approval() {
        let c = controls();
        let mut req = request();
        req.limits.approval = ActionApproval::PerAction;

        let admission = c.admit(req).unwrap();

        assert!(matches!(admission, Admission::AwaitingApproval(_)));
    }

    /// Carol approved exactly this action. The agent's attempt is admitted.
    #[test]
    fn an_approved_action_is_admitted() {
        let c = controls();
        let mut req = request();
        req.limits.approval = ActionApproval::PerAction;
        c.broker.grant(&req.gated());

        let admission = c.admit(req).unwrap();

        assert_eq!(admission, Admission::Admitted);
    }

    /// An open-ended route without parameter rules waits for approval even
    /// when the task delegation does not require it.
    #[test]
    fn an_open_ended_route_without_rules_awaits_approval() {
        let c = controls();
        let mut req = request();
        req.route.reach = RouteReach::OpenEnded;

        let admission = c.admit(req).unwrap();

        assert!(matches!(admission, Admission::AwaitingApproval(_)));
    }

    /// An unreachable approval broker makes admission fail for a gated action.
    #[test]
    fn an_unanswered_approval_admits_nothing() {
        let c = controls_with(Arc::new(FakeApprovalBroker::unreachable()));
        let mut req = request();
        req.limits.approval = ActionApproval::PerAction;

        let admission = c.admit(req);

        assert!(admission.is_err());
    }

    /// A full approval broker refuses admission because too many actions
    /// already await approval.
    #[test]
    fn too_many_awaiting_is_refused() {
        let c = controls_with(Arc::new(FakeApprovalBroker::full()));
        let mut req = request();
        req.limits.approval = ActionApproval::PerAction;

        let admission = c.admit(req).unwrap();

        assert_eq!(admission, Admission::Refused(AgentRefusal::TooManyAwaiting));
    }

    /// An unreadable exposure mark makes admission return an internal error.
    #[test]
    fn an_unreadable_exposure_admits_nothing() {
        let use_case = AdmitActionUseCase::new(
            AdmitActionPorts {
                exposure: Arc::new(UnreadableExposure),
            },
            Arc::new(GateActionUseCase::new(GateActionPorts::fakes())),
        );

        let admission = block_on(use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request(),
        ));

        assert!(matches!(admission, Err(AppError::Internal(_))));
    }

    /// The approved action is the method and the path with its query, so
    /// approving a payment of 10 never approves one of 10000.
    #[test]
    fn the_gated_action_carries_the_query() {
        let req = fetch("amount=10");

        assert_eq!(req.gated().target, "/fetch?amount=10");
    }

    /// An exposure gate whose store is down.
    struct UnreadableExposure;

    impl TenantScoped for UnreadableExposure {}

    #[async_trait]
    impl AgentExposureGate for UnreadableExposure {
        async fn admit(
            &self,
            _tenant_id: &ScopedTenant,
            _agent_id: &AgentId,
            _class: DataClassLevel,
        ) -> Result<bool, DomainError> {
            Err(DomainError::infra_msg("the mark cannot be read"))
        }

        async fn current(
            &self,
            _tenant_id: &ScopedTenant,
            _agent_id: &AgentId,
        ) -> Result<DataClassLevel, DomainError> {
            Err(DomainError::infra_msg("the mark cannot be read"))
        }

        async fn reset(
            &self,
            _tenant_id: &ScopedTenant,
            _reset: &ExposureReset<ResolvedTenant>,
        ) -> Result<bool, DomainError> {
            Err(DomainError::infra_msg("the mark cannot be read"))
        }
    }
}
