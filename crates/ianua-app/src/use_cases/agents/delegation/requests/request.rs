//! Request delegation: an agent asks a person for a delegation.
//!
//! An agent working for Ann finds it needs more than it holds. It asks her,
//! signed in as itself, naming what it needs and why. The request grants
//! nothing: Ann sees it, and grants it or refuses it. An agent may keep
//! only a few requests open at once, and make only so many an hour, so it
//! cannot bury the people it asks in requests until one is approved
//! without being read.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
use ianua_domain::domains::agents::authority::delegation_request::{
    AskDelegationParams, DelegationReason, DelegationRequest,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentId, Audience, Human, PrincipalRef};
use time::{Duration, OffsetDateTime};

use crate::acting::AgentActors;
use crate::auditor::RequestAuditor;
use crate::context::AgentAssertion;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::DelegationRequestStore;
use crate::ports::identity::UserStore;
use crate::ports::notifications::AlertThrottle;
use crate::ports::organization::OrgUserStore;
use crate::services::agents::sign_in::{AgentDoor, signed_in_at};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::people::{PeopleSources, person_behind};

/// The most requests an agent may have waiting for an answer at once.
pub(crate) const MAX_OPEN_REQUESTS: usize = 3;

/// The most requests an agent may make in an hour, answered or not.
pub(crate) const MAX_REQUESTS_PER_HOUR: usize = 10;

/// The agent asking, signed in as itself.
pub struct AskingAgent {
    /// The tenant the request was addressed to.
    pub tenant: ScopedTenant,
    /// The assertion its own key signed.
    pub assertion: AgentAssertion,
}

/// What the agent asks for, and of whom.
pub struct RequestRequest {
    /// The person asked, by their account.
    pub asked_of: PrincipalRef,
    /// The capabilities it asks for.
    pub granted: CapabilitySet,
    /// The limits it asks for.
    pub constraints: DelegationConstraints,
    /// Why it asks, in its own words.
    pub reason: DelegationReason,
}

/// The ports [`RequestUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestPorts {
    /// How the agent signs in as itself.
    pub agent_actors: Arc<dyn AgentActors>,
    /// Holds back records of a refused sign-in that looks like an attack
    /// to one a window per agent and kind of attack.
    pub alert_throttle: Arc<dyn AlertThrottle>,
    /// Keeps the request, and the agent's earlier ones.
    pub request_store: Arc<dyn DelegationRequestStore>,
    /// The person asked, when they are a tenant user.
    pub user_store: Arc<dyn UserStore>,
    /// The person asked, when they are an organization member.
    pub org_user_store: Arc<dyn OrgUserStore>,
}

/// Records the delegations agents ask people for.
pub struct RequestUseCase {
    ports: RequestPorts,
    audience: Audience,
}

impl RequestUseCase {
    /// A use case working through `ports`, taking agent assertions made for
    /// `audience`.
    #[must_use]
    pub fn new(ports: RequestPorts, audience: Audience) -> Self {
        Self { ports, audience }
    }

    /// Refuses an agent that has as many requests open, or made in the last
    /// hour, as an agent may.
    async fn ensure_may_ask_again(
        &self,
        tenant: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<(), AppError> {
        let asked = self
            .ports
            .request_store
            .list_for_agent(tenant, agent)
            .await
            .or_internal()?;
        ensure_under_limits(&asked, clock::now())
    }

    /// The person of `tenant` that `asked_of` names.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when `asked_of` is not a person of the tenant.
    /// - `AppError::Internal` when an account cannot be read.
    async fn person_asked(
        &self,
        tenant: &ScopedTenant,
        asked_of: &PrincipalRef,
    ) -> Result<Human, AppError> {
        let sources = PeopleSources {
            users: self.ports.user_store.as_ref(),
            members: self.ports.org_user_store.as_ref(),
        };
        person_behind(sources, tenant, asked_of)
            .await?
            .or_not_found(message!("agents-no-such-person", "no such person"))
    }
}

impl Command for RequestUseCase {
    type Caller = AskingAgent;
    type Input = RequestRequest;
    type Output = Result<DelegationRequest<ResolvedTenant>, AppError>;

    /// Records the agent's request of the person `request.asked_of` names,
    /// and `agents.delegation_requested`, so they hear of it.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the assertion does not sign the agent
    ///   in, or the agent may not act now.
    /// - `AppError::TooManyRequests` when the agent has as many requests
    ///   open, or made in the last hour, as it may.
    /// - `AppError::NotFound` when the person asked is not a person of the
    ///   tenant.
    /// - `AppError::Internal` on persistence or audit failure, an attack on
    ///   the agent's sign-in that cannot be recorded included.
    ///
    /// A sign-in refused as a replayed or forged assertion, or one naming
    /// another agent, records `agents.token_attack_refused` once a window
    /// per agent and kind of attack.
    async fn execute(
        &self,
        caller: &AskingAgent,
        auditor: &RequestAuditor,
        request: RequestRequest,
    ) -> Result<DelegationRequest<ResolvedTenant>, AppError> {
        let tenant = &caller.tenant;
        let door = AgentDoor {
            actors: self.ports.agent_actors.as_ref(),
            attacks: self.ports.alert_throttle.as_ref(),
            tenant,
            audience: &self.audience,
        };
        let signed = signed_in_at(door, auditor, &caller.assertion).await?;
        self.ensure_may_ask_again(tenant, signed.agent.id()).await?;
        let asked_of = self.person_asked(tenant, &request.asked_of).await?;
        let params = AskDelegationParams {
            asked_of,
            granted: request.granted,
            constraints: request.constraints,
            reason: request.reason,
        };
        let mut asked = DelegationRequest::ask(&signed.acting, &signed.agent, params)
            .map_err(AppError::from_domain)?;
        self.ports
            .request_store
            .save(tenant, &asked)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&signed.actor(), asked.take_events(tenant))
            .await
            .or_internal()?;
        Ok(asked)
    }
}

/// Refuses another request when `asked`, the agent's requests so far, hold
/// as many open at `now`, or made in the hour before it, as an agent may.
fn ensure_under_limits(
    asked: &[DelegationRequest<ResolvedTenant>],
    now: OffsetDateTime,
) -> Result<(), AppError> {
    let open = asked
        .iter()
        .filter(|request| request.is_open_at(now))
        .count();
    if open >= MAX_OPEN_REQUESTS {
        return Err(AppError::TooManyRequests(message!(
            "agents-an-agent-may-have-at-most",
            format!("an agent may have at most {MAX_OPEN_REQUESTS} requests waiting for an answer")
        )));
    }
    let since = now.saturating_sub(Duration::hours(1));
    let recent = asked
        .iter()
        .filter(|request| request.created_at() > since)
        .count();
    if recent >= MAX_REQUESTS_PER_HOUR {
        return Err(AppError::TooManyRequests(message!(
            "agents-an-agent-may-make-at-most",
            format!("an agent may make at most {MAX_REQUESTS_PER_HOUR} requests an hour")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::agents::identity::control::AgentControl;
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::types::{Human, HumanAccount, PersonKey, Seconds, UserId};

    use super::*;
    use crate::acting::agent::{AgentActing, AgentActingPorts};
    use crate::ports::agents::AgentStore;
    use crate::test_support::acting::RefusingAgentActors;
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationRequestStore, ReplayedGuard, agent_manager, asked_request,
        callers_agent, signing_in, someone_else,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn audience() -> Audience {
        Audience::new("ianua:agents").unwrap()
    }

    fn reports() -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![])
    }

    /// Ann, a user of the tenant; her agent, signed in as itself; and the
    /// requests it made so far.
    struct Scene {
        ann: UserId,
        agent: AgentId,
        agents: Arc<FakeAgentStore>,
        requests: Arc<FakeDelegationRequestStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Scene {
        fn new() -> Self {
            let agent = AgentId::new();
            Self {
                ann: UserId::new(),
                agent,
                agents: Arc::new(callers_agent(agent)),
                requests: Arc::new(FakeDelegationRequestStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> (RequestPorts, AskingAgent) {
            let (sign_in, assertion) = signing_in(self.agents.clone(), self.agent);
            let ports = RequestPorts {
                agent_actors: Arc::new(AgentActing::new(sign_in)),
                request_store: self.requests.clone(),
                user_store: Arc::new(FakeUserStore::with_user(self.ann, "ann@acme.test")),
                ..RequestPorts::fakes()
            };
            let caller = AskingAgent {
                tenant: test_ctx().tenant(),
                assertion,
            };
            (ports, caller)
        }

        fn ask_with(
            &self,
            ports: RequestPorts,
            caller: &AskingAgent,
            asked_of: PrincipalRef,
        ) -> Result<DelegationRequest<ResolvedTenant>, AppError> {
            let use_case = RequestUseCase::new(ports, audience());
            block_on(use_case.execute(
                caller,
                &test_auditor(self.sink.clone()),
                RequestRequest {
                    asked_of,
                    granted: reports(),
                    constraints: DelegationConstraints::new(Seconds::new(600), 1).unwrap(),
                    reason: DelegationReason::new("I need the monthly reports").unwrap(),
                },
            ))
        }

        fn ask(&self) -> Result<DelegationRequest<ResolvedTenant>, AppError> {
            let (ports, caller) = self.ports();
            self.ask_with(ports, &caller, PrincipalRef::User(self.ann))
        }

        /// The agent as kept.
        fn stored_agent(&self) -> AgentIdentity<ResolvedTenant> {
            block_on(self.agents.find_by_id(&test_ctx().tenant(), &self.agent))
                .unwrap()
                .unwrap()
        }

        /// Keeps `count` requests the agent already made of Ann, still
        /// waiting for her.
        fn already_asked(&self, count: usize) {
            let agent = self.stored_agent();
            for _ in 0..count {
                let earlier = asked_request(&agent, ann_as_person(self.ann), reports());
                block_on(self.requests.save(&test_ctx().tenant(), &earlier)).unwrap();
            }
        }

        /// Keeps `count` requests the agent already made of Ann, each
        /// refused by an agent manager.
        fn already_asked_and_refused(&self, count: usize) {
            let agent = self.stored_agent();
            let manager = agent_manager(someone_else());
            for _ in 0..count {
                let mut earlier = asked_request(&agent, ann_as_person(self.ann), reports());
                earlier.deny(&AgentControl::new(&manager), &agent).unwrap();
                block_on(self.requests.save(&test_ctx().tenant(), &earlier)).unwrap();
            }
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann as the person her account belongs to.
    fn ann_as_person(ann: UserId) -> Human {
        Human::new(
            HumanAccount::User(ann),
            PersonKey::new("ann@acme.test").unwrap(),
        )
    }

    /// Ann's agent asks her to let it read the reports. The request is kept,
    /// waiting for her, and she is told of it.
    #[test]
    fn an_agent_asks_a_person_for_a_delegation() {
        let scene = Scene::new();

        let asked = scene.ask().unwrap();

        assert!(asked.is_open_at(clock::now()));
        assert_eq!(asked.asked_of().principal(), PrincipalRef::User(scene.ann));
        assert_eq!(scene.requests.count(), 1);
        assert_eq!(scene.records(), ["agents.delegation_requested"]);
    }

    /// Reaching the open-request limit rate-limits another request without
    /// saving or recording it.
    #[test]
    fn an_agent_with_too_many_open_requests_is_held_back() {
        let scene = Scene::new();
        scene.already_asked(MAX_OPEN_REQUESTS);

        let result = scene.ask();

        assert!(
            matches!(result, Err(AppError::TooManyRequests(_))),
            "{result:?}"
        );
        assert_eq!(scene.requests.count(), MAX_OPEN_REQUESTS);
        assert!(scene.records().is_empty());
    }

    /// Asking an unknown person reports them as missing and saves no request.
    #[test]
    fn a_request_of_nobody_is_not_found() {
        let scene = Scene::new();
        let (ports, caller) = scene.ports();

        let result = scene.ask_with(ports, &caller, PrincipalRef::User(UserId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(scene.requests.count(), 0);
    }

    /// An agent refused at sign-in cannot save a delegation request.
    #[test]
    fn an_agent_that_is_not_signed_in_is_refused() {
        let scene = Scene::new();
        let (ports, caller) = scene.ports();
        let ports = RequestPorts {
            agent_actors: Arc::new(RefusingAgentActors),
            ..ports
        };

        let result = scene.ask_with(ports, &caller, PrincipalRef::User(scene.ann));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(scene.requests.count(), 0);
    }

    /// A replayed assertion refuses the delegation request without saving
    /// it and records a token attack.
    #[test]
    fn a_replayed_assertion_is_recorded_as_an_attack() {
        let scene = Scene::new();
        let (sign_in, assertion) = signing_in(scene.agents.clone(), scene.agent);
        let (ports, _) = scene.ports();
        let ports = RequestPorts {
            agent_actors: Arc::new(AgentActing::new(AgentActingPorts {
                replay_guard: Arc::new(ReplayedGuard),
                ..sign_in
            })),
            ..ports
        };
        let caller = AskingAgent {
            tenant: test_ctx().tenant(),
            assertion,
        };

        let result = scene.ask_with(ports, &caller, PrincipalRef::User(scene.ann));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(scene.requests.count(), 0);
        assert!(
            scene
                .records()
                .contains(&"agents.token_attack_refused".to_owned())
        );
    }

    /// Denied requests count toward the hourly limit; reaching it
    /// rate-limits another request without increasing the stored count.
    #[test]
    fn an_agent_past_the_hourly_limit_is_held_back() {
        let scene = Scene::new();
        scene.already_asked_and_refused(MAX_REQUESTS_PER_HOUR);

        let result = scene.ask();

        assert!(
            matches!(result, Err(AppError::TooManyRequests(_))),
            "{result:?}"
        );
        assert_eq!(scene.requests.count(), MAX_REQUESTS_PER_HOUR);
    }
}
