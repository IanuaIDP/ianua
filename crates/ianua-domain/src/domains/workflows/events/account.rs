//! The records of what happens to an integration account: connected,
//! changed, disabled, enabled again, and its credential renewed by its
//! service.

use time::OffsetDateTime;

use crate::domains::workflows::events::ACCOUNT;
use crate::domains::workflows::integration::IntegrationKey;
use crate::shared::events::data::{EventData, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{EventLabel, IntegrationAccountId};

/// Which integration account an event is about.
#[derive(Debug, Clone)]
pub(crate) struct AccountRef {
    /// The connected credential affected by the recorded lifecycle change.
    pub(crate) account_id: IntegrationAccountId,
    /// The catalogue entry that defines the referenced credential's operations.
    pub(crate) integration: IntegrationKey,
    /// Its name when the event fired.
    pub(crate) label: EventLabel,
}

macro_rules! account_event {
    ($(#[$meta:meta])* $name:ident => $kind:ident) => {
        $(#[$meta])*
        #[derive(Debug)]
        pub struct $name {
            /// The account.
            pub(crate) account: AccountRef,
            /// When it happened.
            pub(crate) occurred_at: OffsetDateTime,
        }

        tenant_event! {
            $name => WorkflowsEvent::$kind,
            fn payload(&self) -> EventData {
                EventData::new()
                    .reference(
                        "account",
                        Reference::new(
                            ACCOUNT,
                            self.account.account_id.to_string(),
                            self.account.label.as_str(),
                        ),
                    )
                    .field("integration", self.account.integration.as_str().to_owned())
            }
        }
    };
}

account_event! {
    /// An integration account was connected.
    IntegrationAccountConnected => AccountConnected
}

account_event! {
    /// An integration account's sharing, scope, name or credential changed.
    IntegrationAccountChanged => AccountChanged
}

account_event! {
    /// An integration account was disabled.
    IntegrationAccountDisabled => AccountDisabled
}

account_event! {
    /// An integration account was enabled again.
    IntegrationAccountEnabled => AccountEnabled
}

account_event! {
    /// The service renewed an integration account's credential as it was
    /// used, and the renewed one was kept in its place.
    IntegrationAccountCredentialRenewed => AccountCredentialRenewed
}
