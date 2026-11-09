//! The records of an account's one address for a service's events: ready,
//! lapsed, closed, and its token shown. None carries a secret, a key or a
//! token.

use time::OffsetDateTime;

use crate::domains::workflows::integration::IntegrationKey;
use crate::domains::workflows::triggers::subscription::LapseReason;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{AccountChannelId, IntegrationAccountId};

/// Which channel an event is about.
#[derive(Debug, Clone)]
pub(crate) struct ChannelRef {
    /// The channel, named by the address the service sends to.
    pub(crate) channel_id: AccountChannelId,
    /// The account whose events it takes.
    pub(crate) account_id: IntegrationAccountId,
    /// The integration whose service sends them.
    pub(crate) integration: IntegrationKey,
}

impl ChannelRef {
    fn payload(&self) -> EventData {
        EventData::new()
            .field("channel_id", self.channel_id.to_string())
            .field("account_id", self.account_id.to_string())
            .field("integration", self.integration.as_str().to_owned())
    }
}

/// An account's channel began taking a service's events.
#[derive(Debug)]
pub(crate) struct AccountChannelReady {
    /// Which channel went live, with the account whose events it takes.
    pub(crate) channel: ChannelRef,
    /// When it became ready.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccountChannelReady => WorkflowsEvent::ChannelReady,
    fn payload(&self) -> EventData {
        self.channel.payload()
    }
}

/// An account's channel lapsed. The service's events no longer start the
/// workflows waiting on it.
#[derive(Debug)]
pub(crate) struct AccountChannelLapsed {
    /// Which channel stopped, with the account whose workflows it starts.
    pub(crate) channel: ChannelRef,
    /// Why, in the platform's own words.
    pub(crate) reason: LapseReason,
    /// When it lapsed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccountChannelLapsed => WorkflowsEvent::ChannelLapsed,
    fn payload(&self) -> EventData {
        self.channel
            .payload()
            .field("reason", self.reason.as_str().to_owned())
    }
}

/// An account's channel no workflow used any more was closed.
#[derive(Debug)]
pub(crate) struct AccountChannelClosed {
    /// Which channel was taken off the service and forgotten.
    pub(crate) channel: ChannelRef,
    /// When it was closed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccountChannelClosed => WorkflowsEvent::ChannelClosed,
    fn payload(&self) -> EventData {
        self.channel.payload()
    }
}

/// The token a service sent an account's channel was shown to its owner.
#[derive(Debug)]
pub(crate) struct AccountChannelTokenShown {
    /// Which channel held the token its owner read.
    pub(crate) channel: ChannelRef,
    /// When it was shown.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccountChannelTokenShown => WorkflowsEvent::ChannelTokenShown,
    fn payload(&self) -> EventData {
        self.channel.payload()
    }
}
