//! A channel between two agents as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::agents::channels::channel::{
    AgentChannel, AgentChannelRow, ChannelScope,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentChannelId, AgentId, Ending};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{kind_word, principal_from};
use crate::postgres::foundation::stored::Stored;

const CHANNEL: Stored = Stored("agent channel");

/// A channel as it is read. The store's checked queries fill it.
pub(super) struct ChannelRecord {
    pub(super) id: Uuid,
    pub(super) sender_id: Uuid,
    pub(super) receiver_id: Uuid,
    pub(super) scope_kind: String,
    pub(super) scope_value: String,
    pub(super) max_class: String,
    pub(super) opened_by_kind: String,
    pub(super) opened_by_id: Uuid,
    pub(super) opened_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) closed_at: Option<OffsetDateTime>,
}

impl ChannelRecord {
    /// The channel the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the scope or a word does
    /// not read, or the row breaks a rule the channel keeps, such as one
    /// opened by an agent.
    pub(super) fn into_channel(self) -> Result<AgentChannel<ResolvedTenant>, DomainError> {
        AgentChannel::reconstitute(AgentChannelRow {
            id: AgentChannelId::from_uuid(self.id),
            sender: AgentId::from_uuid(self.sender_id),
            receiver: AgentId::from_uuid(self.receiver_id),
            scope: ChannelScope::from_stored(&self.scope_kind, &self.scope_value)?,
            max_class: DataClassLevel::from_stored(&self.max_class)?,
            opened_by: principal_from(CHANNEL, &self.opened_by_kind, self.opened_by_id)?,
            opened_at: self.opened_at,
            expires_at: self.expires_at,
            ending: Ending::from_stored(self.closed_at),
        })
    }
}

/// A channel's columns, as they are written.
pub(super) struct ChannelColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) sender_id: &'a Uuid,
    pub(super) receiver_id: &'a Uuid,
    pub(super) scope_kind: &'static str,
    pub(super) scope_value: &'a str,
    pub(super) max_class: &'static str,
    pub(super) opened_by_kind: &'static str,
    pub(super) opened_by_id: Uuid,
    pub(super) opened_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) closed_at: Option<OffsetDateTime>,
}

impl<'a> ChannelColumns<'a> {
    /// The columns `channel` is written to.
    pub(super) fn of(channel: &'a AgentChannel<ResolvedTenant>) -> Self {
        Self {
            id: channel.id().as_uuid(),
            sender_id: channel.sender().as_uuid(),
            receiver_id: channel.receiver().as_uuid(),
            scope_kind: channel.scope().kind(),
            scope_value: channel.scope().as_str(),
            max_class: channel.max_class().as_str(),
            opened_by_kind: kind_word(channel.opened_by()),
            opened_by_id: channel.opened_by().id(),
            opened_at: channel.opened_at(),
            expires_at: channel.expires_at(),
            closed_at: channel.closed_at(),
        }
    }
}
