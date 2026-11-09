//! Fake for the channels people open between agents, and the channels
//! their tests share.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::TopicPattern;
use ianua_domain::domains::agents::channels::channel::{
    AgentChannel, AgentChannelRow, ChannelScope, OpenChannelParams,
};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::authority::anyone_holding;
use ianua_domain::types::{AgentChannelId, AgentId, Ending, Human, Seconds, TenantId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::messaging::{AgentChannelSortField, AgentChannelStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::listing::page;

/// A channel open for an hour carrying every topic in `sender`'s area to
/// `receiver`, up to internal data, opened by someone who manages agents
/// for the sender's owner `sender_owner`.
#[must_use]
pub fn open_channel(
    sender: AgentId,
    receiver: AgentId,
    sender_owner: &Human,
) -> AgentChannel<ResolvedTenant> {
    let admin = AgentControl::new(anyone_holding(&[SystemPermission::ManageAgents]));
    let area = format!("agents.{}.>", sender.as_uuid().as_simple());
    AgentChannel::open(
        &admin,
        sender_owner,
        OpenChannelParams {
            sender,
            receiver,
            scope: ChannelScope::Topics(TopicPattern::new(area).unwrap()),
            max_class: DataClassLevel::Internal,
            lifetime_seconds: Seconds::new(3600),
        },
    )
    .unwrap()
}

/// In-memory channel store, each channel kept under its tenant in the order
/// it was first saved.
#[derive(Default)]
pub struct FakeAgentChannelStore {
    channels: Mutex<Vec<(TenantId, AgentChannel<ResolvedTenant>)>>,
}

impl TenantScoped for FakeAgentChannelStore {}

impl FakeAgentChannelStore {
    /// A store holding no channel.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many channels are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.channels.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant_id: &ScopedTenant,
        keeps: impl Fn(&AgentChannel<ResolvedTenant>) -> bool,
    ) -> Result<Vec<AgentChannel<ResolvedTenant>>, DomainError> {
        self.channels
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, channel)| tenant == &**tenant_id && keeps(channel))
            .map(|(_, channel)| copy_channel(channel))
            .collect()
    }
}

#[async_trait]
impl AgentChannelStore for FakeAgentChannelStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AgentChannel<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_channel(channel)?;
        let mut channels = self.channels.lock().unwrap();
        let kept = channels
            .iter_mut()
            .find(|(tenant, kept)| tenant == &**tenant_id && kept.id() == channel.id());
        match kept {
            Some((_, kept)) => *kept = copy,
            None => channels.push((**tenant_id, copy)),
        }
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentChannelId,
    ) -> Result<Option<AgentChannel<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |channel| channel.id() == id)?;
        Ok(found.into_iter().next())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        request: &PageRequest,
    ) -> Result<Page<AgentChannel<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |_| true)?;
        page(
            found,
            &SortOrder::<AgentChannelSortField>::default(),
            request,
        )
    }

    async fn unclosed_between(
        &self,
        tenant_id: &ScopedTenant,
        sender: &AgentId,
        receiver: &AgentId,
    ) -> Result<Vec<AgentChannel<ResolvedTenant>>, DomainError> {
        self.matching(tenant_id, |channel| {
            channel.sender() == sender
                && channel.receiver() == receiver
                && channel.closed_at().is_none()
        })
    }

    async fn unclosed_into(
        &self,
        tenant_id: &ScopedTenant,
        receiver: &AgentId,
    ) -> Result<Vec<AgentChannel<ResolvedTenant>>, DomainError> {
        self.matching(tenant_id, |channel| {
            channel.receiver() == receiver && channel.closed_at().is_none()
        })
    }
}

impl Fake for Arc<dyn AgentChannelStore> {
    fn fake() -> Self {
        Arc::new(FakeAgentChannelStore::empty())
    }
}

/// `channel` written out and read back, as storage would return it.
fn copy_channel(
    channel: &AgentChannel<ResolvedTenant>,
) -> Result<AgentChannel<ResolvedTenant>, DomainError> {
    AgentChannel::reconstitute(AgentChannelRow {
        id: *channel.id(),
        sender: *channel.sender(),
        receiver: *channel.receiver(),
        scope: channel.scope().clone(),
        max_class: channel.max_class(),
        opened_by: *channel.opened_by(),
        opened_at: channel.opened_at(),
        expires_at: channel.expires_at(),
        ending: Ending::from_stored(channel.closed_at()),
    })
}
