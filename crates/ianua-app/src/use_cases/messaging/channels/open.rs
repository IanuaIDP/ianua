//! Open channel: a person lets two agents exchange messages or share an object.

use std::sync::Arc;

use ianua_domain::domains::agents::channels::channel::{
    AgentChannel, ChannelScope, OpenChannelParams,
};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, Seconds};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentStore;
use crate::ports::messaging::AgentChannelStore;
use crate::services::agents::standing::ensure_active;
use crate::services::lookup::existing_agent;
use crate::use_case::Command;
use crate::use_cases::messaging::lookup::owned_sender;

/// What a person asks for when opening a channel.
pub struct OpenRequest {
    /// The agent whose area the messages come from.
    pub sender: AgentId,
    /// The agent that may read them.
    pub receiver: AgentId,
    /// What may travel: topics in the sender's area, or one shared resource.
    pub scope: ChannelScope,
    /// The most sensitive data that may travel.
    pub max_class: DataClassLevel,
    /// How long the channel stays open.
    pub lifetime_seconds: Seconds,
}

/// Ports the open channel use case needs.
#[derive(ianua_macros::Fakes)]
pub struct OpenPorts {
    /// Where channels are kept.
    pub channel_store: Arc<dyn AgentChannelStore>,
    /// Confirms both agents exist in the tenant and are active.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Opens a channel between two agents.
pub struct OpenUseCase {
    ports: OpenPorts,
}

impl OpenUseCase {
    /// Creates the use case.
    #[must_use]
    pub fn new(ports: OpenPorts) -> Self {
        Self { ports }
    }

    /// The channel `req` asks for, opened by the caller from the sending
    /// agent, once both agents are active. A sending agent the caller has
    /// no say over reads as missing.
    async fn new_channel(
        &self,
        ctx: &CallerContext,
        req: OpenRequest,
    ) -> Result<AgentChannel<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let agents = self.ports.agent_store.as_ref();
        let sender = owned_sender(agents, &ctx.tenant(), &req.sender, &control).await?;
        ensure_active(&sender)?;
        ensure_active(&existing_agent(agents, &ctx.tenant(), &req.receiver).await?)?;
        let params = OpenChannelParams {
            sender: req.sender,
            receiver: req.receiver,
            scope: req.scope,
            max_class: req.max_class,
            lifetime_seconds: req.lifetime_seconds,
        };
        AgentChannel::open(&control, sender.owner(), params).map_err(AppError::from_domain)
    }
}

impl Command for OpenUseCase {
    type Caller = CallerContext;
    type Input = OpenRequest;
    type Output = Result<AgentChannel<ResolvedTenant>, AppError>;

    /// Opens the channel and records who opened it as
    /// `messaging.channel_opened`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when either agent is not in the tenant, or the
    ///   caller neither owns the sending agent nor may change agents, so an
    ///   id cannot be used to find out which agents exist.
    /// - `AppError::Conflict` when either agent is not active.
    /// - `AppError::Domain(Validation)` when the request breaks a channel rule.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: OpenRequest,
    ) -> Result<AgentChannel<ResolvedTenant>, AppError> {
        let mut channel = self.new_channel(ctx, req).await?;

        self.ports
            .channel_store
            .save(&ctx.tenant(), &channel)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), channel.take_events(&ctx.tenant()))
            .await
            .or_internal()?;
        Ok(channel)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::TopicPattern;
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::PrincipalRef;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::FakeAgentStore;
    use crate::test_support::messaging::FakeAgentChannelStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Bench {
        use_case: OpenUseCase,
        channels: Arc<FakeAgentChannelStore>,
        agents: Arc<FakeAgentStore>,
        sender: AgentId,
        receiver: AgentId,
    }

    fn bench(people: FakeTenantAuthorities) -> Bench {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        let agents = Arc::new(FakeAgentStore::with_active(sender));
        agents.add_active(receiver);
        let channels = Arc::new(FakeAgentChannelStore::default());
        Bench {
            use_case: OpenUseCase::new(OpenPorts {
                channel_store: channels.clone(),
                agent_store: agents.clone(),
                tenant_authorities: Arc::new(people),
            }),
            channels,
            agents,
            sender,
            receiver,
        }
    }

    fn request(sender: AgentId, receiver: AgentId) -> OpenRequest {
        OpenRequest {
            sender,
            receiver,
            scope: ChannelScope::Topics(
                TopicPattern::new(format!("agents.{}.>", sender.as_uuid().as_simple())).unwrap(),
            ),
            max_class: DataClassLevel::Internal,
            lifetime_seconds: Seconds::new(3600),
        }
    }

    fn run(
        bench: &Bench,
        req: OpenRequest,
    ) -> (
        Result<AgentChannel<ResolvedTenant>, AppError>,
        Arc<FakeEventDispatcher>,
    ) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(bench.use_case.execute(
            &test_ctx(),
            &test_auditor(audit.clone()),
            req,
        ));
        (result, audit)
    }

    /// Ann may change agents. She opens a channel from one agent to another.
    /// It is kept, names her as its opener, and is on record.
    #[test]
    fn a_person_opens_a_channel_and_it_is_on_record() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, audit) = run(&bench, request(bench.sender, bench.receiver));

        let channel = result.unwrap();
        assert_eq!(bench.channels.count(), 1);
        assert!(matches!(channel.opened_by(), PrincipalRef::User(_)));
        assert_eq!(audit.records.lock().unwrap()[0], "messaging.channel_opened");
    }

    /// A channel to an agent the tenant does not have is not found.
    #[test]
    fn a_channel_to_an_unknown_agent_is_not_found() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, _) = run(&bench, request(bench.sender, AgentId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.channels.count(), 0);
    }

    /// Opening a channel to a suspended receiver returns a conflict and
    /// saves no channel.
    #[test]
    fn a_channel_to_an_inactive_agent_is_refused() {
        let bench = bench(FakeTenantAuthorities::holding_everything());
        let suspended = AgentId::new();
        bench
            .agents
            .add_with_status(suspended, AgentStatus::Suspended);

        let (result, _) = run(&bench, request(bench.sender, suspended));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(bench.channels.count(), 0);
    }

    /// A channel covering topics outside the sender's area fails validation;
    /// no channel is saved and no event is recorded.
    #[test]
    fn a_channel_reaching_outside_the_senders_area_is_refused() {
        let bench = bench(FakeTenantAuthorities::holding_everything());
        let req = OpenRequest {
            scope: ChannelScope::Topics(TopicPattern::new("agents.>").unwrap()),
            ..request(bench.sender, bench.receiver)
        };

        let (result, audit) = run(&bench, req);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(bench.channels.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A viewer who does not own the sender receives the same not-found
    /// error for its real ID and an unknown ID, and no channel is saved.
    #[test]
    fn a_caller_who_may_not_change_the_sender_is_answered_as_for_a_missing_one() {
        let viewer = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);
        let bench = bench(viewer);

        let (real, _) = run(&bench, request(bench.sender, bench.receiver));
        let (made_up, _) = run(&bench, request(AgentId::new(), bench.receiver));

        assert!(matches!(real, Err(AppError::NotFound(_))));
        assert!(matches!(made_up, Err(AppError::NotFound(_))));
        assert_eq!(bench.channels.count(), 0);
    }

    /// A signed-out caller receives an unauthenticated error when opening
    /// a channel.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bench = bench(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = run(&bench, request(bench.sender, bench.receiver));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
