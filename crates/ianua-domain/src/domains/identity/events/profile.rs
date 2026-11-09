//! Events about what an account records about its holder, and accounts
//! brought over from another system.

use time::OffsetDateTime;

use crate::domains::identity::account::import::state::ImportStatus;
use crate::domains::identity::account::user_profile::ChangedProfileField;
use crate::domains::identity::events::user_reference;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::{Email, UserId, UserImportId};

/// Fields of a user's profile changed: their own details, or what the
/// company's directory records about them.
///
/// The record names which fields changed and never what they now say. A
/// phone number or a manager written into a permanent audit line would
/// outlive the person's erasure, and the account itself holds the values.
#[derive(Debug)]
pub struct UserProfileUpdated {
    /// The user whose profile changed.
    pub(crate) user_id: UserId,
    /// Which fields changed, in the order the profile declares them.
    pub(crate) fields: Vec<ChangedProfileField>,
    /// When the profile changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserProfileUpdated => crate::types::event_type::IdentityEvent::UserProfileUpdated,
    fn payload(&self) -> EventData {
        let fields: Vec<&str> = self.fields.iter().map(|field| field.as_str()).collect();
        EventData::new()
            .reference("user", user_reference(&self.user_id, &self.user_id.to_string()))
            .field("fields", fields.join(","))
    }
}

/// An account was opened from another system's records, such as an export
/// from the identity provider a tenant is leaving.
///
/// The address stays unverified until its holder follows the link mailed
/// to it, whatever the other system said about it.
#[derive(Debug)]
pub struct UserImported {
    /// The address the account was opened with.
    pub(crate) email: Email,
    /// When it was opened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserImported => crate::types::event_type::IdentityEvent::UserImported,
    fn payload(&self) -> EventData {
        EventData::new().field("email", self.email.as_str())
    }
}

/// An admin sent accounts to import from another system. They are opened
/// later, by the worker.
#[derive(Debug)]
pub struct UserImportStarted {
    /// The queued batch whose records will be opened by the worker.
    pub(crate) import_id: UserImportId,
    /// How many records it holds.
    pub(crate) records: u32,
    /// When it was kept.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserImportStarted => crate::types::event_type::IdentityEvent::UserImportStarted,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("import_id", self.import_id.to_string())
            .field("records", self.records.to_string())
    }
}

/// An import of accounts from another system came to its end, finished or
/// given up on.
///
/// Raised once per import, so colleagues hear of ten thousand accounts in
/// one line, not ten thousand. Each account still has its own
/// `identity.user_imported` record in the audit trail.
#[derive(Debug)]
pub struct UsersImported {
    /// The batch whose final counters summarize all account-opening attempts.
    pub(crate) import_id: UserImportId,
    /// How it ended.
    pub(crate) status: ImportStatus,
    /// The accounts it opened.
    pub(crate) imported: u32,
    /// The records it could not open an account from.
    pub(crate) refused: u32,
    /// When it ended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UsersImported => crate::types::event_type::IdentityEvent::UsersImported,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("import_id", self.import_id.to_string())
            .field("status", self.status.as_str())
            .field("imported", self.imported.to_string())
            .field("refused", self.refused.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::event::DomainEventCore;

    /// Ann adds her phone number and her department changes. The record
    /// names both fields and holds neither value.
    #[test]
    fn a_profile_change_names_its_fields_and_never_their_values() {
        let ann = UserId::new();
        let event = UserProfileUpdated {
            user_id: ann,
            fields: vec![
                ChangedProfileField::PhoneNumber,
                ChangedProfileField::Department,
            ],
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(payload.get("fields"), Some("phone_number,department"));
        assert_eq!(payload.len(), 2);
    }

    /// An account brought over from another system records the address it
    /// was opened with.
    #[test]
    fn an_imported_account_records_its_address() {
        let event = UserImported {
            email: Email::new("ann@acme.com").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(event.payload().get("email"), Some("ann@acme.com"));
    }

    /// Ann's import of 9,998 accounts ends with two records refused. The one
    /// summary says how it ended and both counts, and names no address.
    #[test]
    fn a_finished_import_records_its_counts_once() {
        let event = UsersImported {
            import_id: UserImportId::new(),
            status: ImportStatus::Finished,
            imported: 9_998,
            refused: 2,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(payload.get("status"), Some("finished"));
        assert_eq!(payload.get("imported"), Some("9998"));
        assert_eq!(payload.get("refused"), Some("2"));
        assert_eq!(payload.len(), 4);
    }
}
