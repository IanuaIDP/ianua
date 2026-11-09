//! Offer agent: an agent's owner offers it to a named person, who may
//! accept it.
//!
//! Ann moves teams and wants Bob to look after her agent. She names him,
//! and the agent waits for him to accept. Bob is not the one signed in, so
//! whether he may own an agent is worked out from what the tenant's records
//! say he holds, never from what Ann says. Nothing moves until Bob accepts.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::{AgentIdentity, AgentRecipient};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, AgentVersion};
use crate::ports::authorization::{AccessRecordStore, Holder};
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// Which agent is offered, and to whom.
pub struct OfferAgentRequest {
    /// The identity whose ownership is offered to the recipient.
    pub agent_id: AgentId,
    /// The tenant user it is offered to.
    pub recipient: UserId,
}

/// The ports [`OfferAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OfferAgentPorts {
    /// Loads and saves agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// The person the agent is offered to.
    pub user_store: Arc<dyn UserStore>,
    /// What the recipient holds, for whether they may own an agent.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Offers agents to the people who would take them over.
pub struct OfferAgentUseCase {
    ports: OfferAgentPorts,
}

impl OfferAgentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OfferAgentPorts) -> Self {
        Self { ports }
    }
}

impl Command for OfferAgentUseCase {
    type Caller = CallerContext;
    type Input = OfferAgentRequest;
    type Output = Result<AgentIdentity<ResolvedTenant>, AppError>;

    /// Offers `request.agent_id` to `request.recipient`, records
    /// `agents.agent_ownership_offered` naming them, and returns the agent
    /// as it stands, still the caller's.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent or user, or
    ///   the caller neither owns the agent nor may manage agents, so that an
    ///   agent of someone else's answers as one that does not exist.
    /// - `AppError::Forbidden` when the recipient may not sign in or may not
    ///   create agents.
    /// - `AppError::Conflict` when the recipient owns the agent already, or
    ///   the agent changed since it was read.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: OfferAgentRequest,
    ) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Manage);
        let mut agent = owned_agent(store, &tenant, &request.agent_id, &control, reach).await?;
        let read = AgentVersion::of(&agent);
        let recipient = recipient_of(&self.ports, &tenant, &request.recipient).await?;
        agent
            .offer_ownership(&control, &recipient)
            .map_err(AppError::from_domain)?;
        self.ports
            .agent_store
            .save_unchanged_since(&tenant, &agent, read)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), agent.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(agent)
    }
}

/// The tenant user `user_id`, as one an agent may be offered to, from what
/// the tenant's records say they hold.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such user.
/// - `AppError::Forbidden` when they may not sign in or may not create
///   agents.
/// - `AppError::Internal` when the user or the records cannot be read.
async fn recipient_of(
    ports: &OfferAgentPorts,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<AgentRecipient, AppError> {
    let account = existing_user(ports.user_store.as_ref(), tenant, user_id).await?;
    let records = ports
        .access_records
        .load_held_by(tenant, Holder::user(*user_id))
        .await
        .or_internal()?;
    AgentRecipient::worked_out(&records.access(**tenant), &account).map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::OwnershipOffer;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{HumanAccount, PrincipalRef};

    use super::*;
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, callers_agent, someone};
    use crate::test_support::authorization::{
        FakeAccessRecordStore, stored_assignment, stored_role,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The caller's agent, Bob's account, and the stores keeping them.
    struct Scene {
        agents: Arc<FakeAgentStore>,
        agent: AgentId,
        bob: UserId,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Scene {
        fn new() -> Self {
            let agent = AgentId::new();
            Self {
                agents: Arc::new(callers_agent(agent)),
                agent,
                bob: UserId::new(),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The ports, with Bob's roles holding `system`.
        fn ports(&self, system: &[SystemPermission]) -> OfferAgentPorts {
            self.ports_reading(Arc::new(records_giving(self.bob, system)))
        }

        /// The ports, reading who holds what from `records`.
        fn ports_reading(&self, records: Arc<FakeAccessRecordStore>) -> OfferAgentPorts {
            OfferAgentPorts {
                agent_store: self.agents.clone(),
                user_store: Arc::new(FakeUserStore::with_user(self.bob, "bob@example.test")),
                access_records: records,
                ..OfferAgentPorts::fakes()
            }
        }

        fn offer(&self, ports: OfferAgentPorts) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
            block_on(OfferAgentUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                OfferAgentRequest {
                    agent_id: self.agent,
                    recipient: self.bob,
                },
            ))
        }

        fn offer_now(&self) -> OwnershipOffer {
            self.agents
                .find_by_id_direct(&self.agent)
                .unwrap()
                .offer()
                .clone()
        }
    }

    /// Records giving `user` one role holding `system`.
    fn records_giving(user: UserId, system: &[SystemPermission]) -> FakeAccessRecordStore {
        let role = stored_role("team", system.to_vec(), Vec::new());
        let assignment = stored_assignment(PrincipalRef::User(user), *role.id());
        FakeAccessRecordStore::holding(
            *test_ctx().tenant(),
            AccessRecords {
                roles: vec![role],
                assignments: vec![assignment],
                ..AccessRecords::default()
            },
        )
    }

    const CREATES_AGENTS: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::Create)];

    /// Ann offers her agent to Bob, whose roles let him create agents. It
    /// waits for him, is still hers, and the offer is recorded.
    #[test]
    fn an_owner_offers_her_agent_to_someone_who_may_own_one() {
        let scene = Scene::new();

        let agent = scene.offer(scene.ports(&CREATES_AGENTS)).unwrap();

        let offered = scene.offer_now();
        let recipient = offered.open_to(clock::now()).unwrap();
        assert_eq!(recipient.account(), HumanAccount::User(scene.bob));
        assert_ne!(agent.owner().account(), HumanAccount::User(scene.bob));
        assert_eq!(
            scene.sink.records.lock().unwrap().as_slice(),
            ["agents.agent_ownership_offered"]
        );
    }

    /// Ann offers her agent to Bob. Whether he may own one is worked out
    /// from his own records alone; the rest of the tenant's are not read.
    #[test]
    fn an_offer_reads_only_the_recipients_records() {
        let scene = Scene::new();
        let records = Arc::new(records_giving(scene.bob, &CREATES_AGENTS));

        scene.offer(scene.ports_reading(records.clone())).unwrap();

        assert_eq!(records.whole_reads(), 0);
    }

    /// A recipient whose roles grant only viewing cannot receive an
    /// ownership offer; the agent stays unoffered and no offer is recorded.
    #[test]
    fn an_agent_is_not_offered_to_someone_whose_records_cannot_own_one() {
        let scene = Scene::new();
        let ports = scene.ports(&[SystemPermission::Agents(AgentAction::View)]);

        let result = scene.offer(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(scene.offer_now(), OwnershipOffer::Unoffered);
        assert!(scene.sink.records.lock().unwrap().is_empty());
    }

    /// A viewer cannot offer another person's agent; the agent appears
    /// missing and no ownership offer is recorded.
    #[test]
    fn a_caller_with_no_say_over_the_agent_offers_nothing() {
        let scene = Scene::new();
        let agents = Arc::new(FakeAgentStore::empty());
        agents.add_owned_by(scene.agent, someone("ann@example.test"));
        let ports = OfferAgentPorts {
            agent_store: agents,
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..scene.ports(&CREATES_AGENTS)
        };

        let result = scene.offer(ports);

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert!(scene.sink.records.lock().unwrap().is_empty());
    }

    /// Ann offers her agent to someone the tenant has no account for. It is
    /// not found.
    #[test]
    fn an_unknown_recipient_is_not_found() {
        let scene = Scene::new();
        let ports = OfferAgentPorts {
            user_store: Arc::new(FakeUserStore::empty()),
            ..scene.ports(&CREATES_AGENTS)
        };

        let result = scene.offer(ports);

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
    }

    /// A signed-out owner cannot offer their agent, which stays unoffered.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = Scene::new();
        let ports = OfferAgentPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..scene.ports(&CREATES_AGENTS)
        };

        let result = scene.offer(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(scene.offer_now(), OwnershipOffer::Unoffered);
    }
}
