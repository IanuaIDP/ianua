//! Events about requests for a copy of a person's data.
//!
//! Each names the person by account id only, as the erasure events do: a
//! name or an address written into a permanent record would outlive an
//! erasure the person asks for later.

use time::OffsetDateTime;

use crate::domains::identity::events::user_reference;
use crate::domains::identity::privacy::export::ExportScope;
use crate::shared::events::data::{EventData, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::UserId;

/// The person an export is for, named by account id.
fn person(user_id: &UserId) -> Reference {
    user_reference(user_id, &user_id.to_string())
}

/// A copy of a person's data was asked for, by them or by staff for them.
#[derive(Debug)]
pub struct DataExportRequested {
    /// The person whose data it copies.
    pub(crate) user_id: UserId,
    /// What was asked for.
    pub(crate) scope: ExportScope,
    /// When it was asked for.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DataExportRequested => crate::types::event_type::IdentityEvent::DataExportRequested,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("user", person(&self.user_id))
            .field("scope", self.scope.as_str())
    }
}

/// A person's export was gathered and may be downloaded until a time.
#[derive(Debug)]
pub struct DataExportReady {
    /// The person whose data it copies.
    pub(crate) user_id: UserId,
    /// Until when it may be downloaded.
    pub(crate) available_until: OffsetDateTime,
    /// When it was ready.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DataExportReady => crate::types::event_type::IdentityEvent::DataExportReady,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("user", person(&self.user_id))
            .field("expires_at", self.available_until.to_string())
    }
}

/// A person downloaded their export.
#[derive(Debug)]
pub struct DataExportDownloaded {
    /// The person who downloaded it.
    pub(crate) user_id: UserId,
    /// When they did.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DataExportDownloaded => crate::types::event_type::IdentityEvent::DataExportDownloaded,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", person(&self.user_id))
    }
}

/// A person's export reached the end of its download window and was
/// deleted.
#[derive(Debug)]
pub struct DataExportExpired {
    /// The person whose data it copied.
    pub(crate) user_id: UserId,
    /// When it expired.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DataExportExpired => crate::types::event_type::IdentityEvent::DataExportExpired,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", person(&self.user_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    /// Ann asks for everything kept about her. The record names her by
    /// account id only, and the scope she asked for.
    #[test]
    fn an_export_request_names_the_person_by_id_and_its_scope() {
        let ann = UserId::new();
        let event = DataExportRequested {
            user_id: ann,
            scope: ExportScope::Access,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(payload.get("scope"), Some("access"));
        let Some(FieldValue::Reference(reference)) = payload.value("user") else {
            panic!("the record names no person");
        };
        assert_eq!(reference.label(), ann.to_string());
    }

    /// A ready export records until when it may be downloaded.
    #[test]
    fn a_ready_export_records_its_window() {
        let until = crate::shared::clock::now();
        let event = DataExportReady {
            user_id: UserId::new(),
            available_until: until,
            occurred_at: until,
        };

        assert_eq!(
            event.payload().get("expires_at"),
            Some(until.to_string().as_str())
        );
    }
}
