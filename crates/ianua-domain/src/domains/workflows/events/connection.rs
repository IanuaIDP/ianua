//! The records of a person beginning to connect an account by signing in at
//! an integration's service, and of a refused attempt to finish someone
//! else's. Neither carries a code, a state or a credential.

use time::OffsetDateTime;

use crate::domains::workflows::integration::IntegrationKey;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{PendingConnectionId, PrincipalRef};

/// Which connection an event is about.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionRef {
    /// The pending account setup tied to the external authorization callback.
    pub(crate) connection_id: PendingConnectionId,
    /// The integration it connects.
    pub(crate) integration: IntegrationKey,
    /// The person who began it.
    pub(crate) by: PrincipalRef,
}

impl ConnectionRef {
    fn payload(&self) -> EventData {
        EventData::new()
            .field("connection_id", self.connection_id.to_string())
            .field("integration", self.integration.as_str().to_owned())
            .field("started_by", self.by.label())
    }
}

/// A person began connecting an account by signing in at the integration's
/// service.
#[derive(Debug)]
pub struct AccountConnectionStarted {
    /// The account setup whose external sign-in was initiated.
    pub(crate) connection: ConnectionRef,
    /// When it began.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccountConnectionStarted => WorkflowsEvent::AccountConnectionStarted,
    fn payload(&self) -> EventData {
        self.connection.payload()
    }
}

/// Someone other than the person who began a connection tried to finish
/// it. The connection is spent, so the credential the service issued is
/// kept by nobody.
#[derive(Debug)]
pub struct AccountConnectionRefused {
    /// The account setup spent after a different person tried to finish it.
    pub(crate) connection: ConnectionRef,
    /// The person who tried to finish it.
    pub(crate) tried_by: PrincipalRef,
    /// When it was refused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccountConnectionRefused => WorkflowsEvent::AccountConnectionRefused,
    fn payload(&self) -> EventData {
        self.connection
            .payload()
            .field("tried_by", self.tried_by.label())
    }
}
