//! Close channel: a person stops one agent reading another's area.

use std::sync::Arc;

use ianua_domain::domains::agents::channels::channel::AgentChannel;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentChannelId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentStore;
use crate::ports::messaging::AgentChannelStore;
use crate::use_case::Command;
use crate::use_cases::messaging::lookup::{ChannelStores, ClosableChannel, owned_channel};

/// Ports the close channel use case needs.
#[derive(ianua_macros::Fakes)]
pub struct ClosePorts {
    /// Where channels are kept.
    pub channel_store: Arc<dyn AgentChannelStore>,
    /// The sending agent, whose owner may close the channel.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Closes a channel between two agents.
pub struct CloseUseCase {
    ports: ClosePorts,
}

impl CloseUseCase {
    /// Creates the use case.
    #[must_use]
    pub fn new(ports: ClosePorts) -> Self {
        Self { ports }
    }

    /// The channel `channel_id`, closed for the caller, who opened it, owns
    /// the sending agent, or may change agents. A channel they have no say
    /// over reads as missing.
    async fn closed(
        &self,
        ctx: &CallerContext,
        channel_id: &AgentChannelId,
    ) -> Result<AgentChannel<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let stores = ChannelStores {
            channels: self.ports.channel_store.as_ref(),
            agents: self.ports.agent_store.as_ref(),
        };
        let ClosableChannel {
            mut channel,
            sender,
        } = owned_channel(stores, &ctx.tenant(), channel_id, &control).await?;
        channel
            .close(&control, sender.owner())
            .map_err(AppError::from_domain)?;
        Ok(channel)
    }
}

impl Command for CloseUseCase {
    type Caller = CallerContext;
    type Input = AgentChannelId;
    type Output = Result<(), AppError>;

    /// Closes the channel. The next read through it is refused. Saves the
    /// closed channel, then records `messaging.channel_closed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the channel or its sending agent is not
    ///   in the tenant, or the caller neither opened the channel nor has a
    ///   say over the sending agent, so an id cannot be used to find out
    ///   which channels exist.
    /// - `AppError::Domain(InvalidTransition)` when it is already closed.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        channel_id: AgentChannelId,
    ) -> Result<(), AppError> {
        let mut channel = self.closed(ctx, &channel_id).await?;

        self.ports
            .channel_store
            .save(&ctx.tenant(), &channel)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), channel.take_events(&ctx.tenant()))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::AgentId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::FakeAgentStore;
    use crate::test_support::messaging::{FakeAgentChannelStore, open_channel};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Bench {
        use_case: CloseUseCase,
        channels: Arc<FakeAgentChannelStore>,
        id: AgentChannelId,
    }

    fn bench(people: FakeTenantAuthorities) -> Bench {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        let agents = Arc::new(FakeAgentStore::with_active(sender));
        let owner = agents.find_by_id_direct(&sender).unwrap().owner().clone();
        let channel = open_channel(sender, receiver, &owner);
        let id = *channel.id();
        let channels = Arc::new(FakeAgentChannelStore::default());
        block_on(channels.save(&test_ctx().tenant(), &channel)).unwrap();
        Bench {
            use_case: CloseUseCase::new(ClosePorts {
                channel_store: channels.clone(),
                agent_store: agents,
                tenant_authorities: Arc::new(people),
            }),
            channels,
            id,
        }
    }

    fn close(
        bench: &Bench,
        id: AgentChannelId,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(bench.use_case.execute(
            &test_ctx(),
            &test_auditor(audit.clone()),
            id,
        ));
        (result, audit)
    }

    fn closed(bench: &Bench) -> bool {
        block_on(bench.channels.find_by_id(&test_ctx().tenant(), &bench.id))
            .unwrap()
            .unwrap()
            .closed_at()
            .is_some()
    }

    /// Ann may change agents. She closes a channel. Nothing travels through
    /// it afterwards, and the closing is on record.
    #[test]
    fn closing_a_channel_stops_it_and_is_on_record() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, audit) = close(&bench, bench.id);

        result.unwrap();
        assert!(closed(&bench));
        assert_eq!(audit.records.lock().unwrap()[0], "messaging.channel_closed");
    }

    /// A channel closed once is not closed again.
    #[test]
    fn closing_twice_is_refused() {
        let bench = bench(FakeTenantAuthorities::holding_everything());
        close(&bench, bench.id).0.unwrap();

        let (again, _) = close(&bench, bench.id);

        assert!(matches!(
            again,
            Err(AppError::Domain(DomainError::InvalidTransition(_)))
        ));
    }

    /// A viewer who neither opened the channel nor owns its sender gets
    /// the same not-found error for its real ID and an unknown ID; the
    /// channel stays open.
    #[test]
    fn a_caller_with_no_say_over_the_channel_is_answered_as_for_a_missing_one() {
        let viewer = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);
        let bench = bench(viewer);

        let (real, _) = close(&bench, bench.id);
        let (made_up, _) = close(&bench, AgentChannelId::new());

        assert!(matches!(real, Err(AppError::NotFound(_))));
        assert!(matches!(made_up, Err(AppError::NotFound(_))));
        assert!(!closed(&bench));
    }

    /// A signed-out caller receives an unauthenticated error when closing
    /// a channel.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bench = bench(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = close(&bench, bench.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A channel the tenant does not have is not found.
    #[test]
    fn an_unknown_channel_is_not_found() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, _) = close(&bench, AgentChannelId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
