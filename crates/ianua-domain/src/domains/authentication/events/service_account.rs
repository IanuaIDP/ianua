//! Directory service account events: the accounts applications bind to
//! the LDAP directory as, how they change and go, each bind, and each
//! search made through one.

use time::OffsetDateTime;

use crate::domains::authentication::directory_service::account::ServiceAccountStatus;
use crate::domains::authentication::directory_service::scope::DirectoryAccess;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{DirectoryServiceAccountId, EventLabel};

/// What a directory service account is called in a record.
const SERVICE_ACCOUNT: RefKind = RefKind::new("service_account");

/// The service account a record is about, by id and name.
fn account_reference(id: DirectoryServiceAccountId, name: &EventLabel) -> Reference {
    Reference::new(SERVICE_ACCOUNT, id.to_string(), name.as_str())
}

/// An admin made a service account for an application to bind to the
/// directory as.
#[derive(Debug)]
pub struct DirectoryServiceAccountCreated {
    /// The account made.
    pub(crate) account_id: DirectoryServiceAccountId,
    /// The bind label copied at creation so the audit entry survives later changes.
    pub(crate) name: EventLabel,
    /// What it may do.
    pub(crate) access: DirectoryAccess,
    /// When it was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectoryServiceAccountCreated => crate::types::event_type::AuthenticationEvent::DirectoryServiceAccountCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("service_account", account_reference(self.account_id, &self.name))
            .field("access", self.access.as_str())
    }
}

/// An admin replaced a service account's secret. Binds made with the old
/// one stop counting.
#[derive(Debug)]
pub struct DirectoryServiceAccountSecretRotated {
    /// The application identity whose bind secret was replaced.
    pub(crate) account_id: DirectoryServiceAccountId,
    /// The bind label captured when the secret changed.
    pub(crate) name: EventLabel,
    /// When the secret was replaced.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectoryServiceAccountSecretRotated => crate::types::event_type::AuthenticationEvent::DirectoryServiceAccountSecretRotated,
    fn payload(&self) -> EventData {
        EventData::new().reference("service_account", account_reference(self.account_id, &self.name))
    }
}

/// An admin changed what a service account may do, or where.
#[derive(Debug)]
pub struct DirectoryServiceAccountScopeChanged {
    /// The application identity whose directory permissions changed.
    pub(crate) account_id: DirectoryServiceAccountId,
    /// The bind label captured with the scope change.
    pub(crate) name: EventLabel,
    /// What it may do now.
    pub(crate) access: DirectoryAccess,
    /// How many subtrees it may do it in now.
    pub(crate) base_dns: usize,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectoryServiceAccountScopeChanged => crate::types::event_type::AuthenticationEvent::DirectoryServiceAccountScopeChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("service_account", account_reference(self.account_id, &self.name))
            .field("access", self.access.as_str())
            .field("base_dns", self.base_dns.to_string())
    }
}

/// An admin switched a service account off or on again.
#[derive(Debug)]
pub struct DirectoryServiceAccountStatusChanged {
    /// The application identity enabled or disabled for directory access.
    pub(crate) account_id: DirectoryServiceAccountId,
    /// The bind label captured when availability changed.
    pub(crate) name: EventLabel,
    /// The status it moved to.
    pub(crate) status: ServiceAccountStatus,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectoryServiceAccountStatusChanged => crate::types::event_type::AuthenticationEvent::DirectoryServiceAccountStatusChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("service_account", account_reference(self.account_id, &self.name))
            .field("status", self.status.as_str())
    }
}

/// An admin deleted a service account. It binds no more, and every
/// connection bound as it reads nothing more.
#[derive(Debug)]
pub struct DirectoryServiceAccountDeleted {
    /// The application identity removed from directory access.
    pub(crate) account_id: DirectoryServiceAccountId,
    /// Its name when it was deleted.
    pub(crate) name: EventLabel,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectoryServiceAccountDeleted => crate::types::event_type::AuthenticationEvent::DirectoryServiceAccountDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference("service_account", account_reference(self.account_id, &self.name))
    }
}

/// An application bound as a service account read the directory with an
/// LDAP search.
///
/// Recorded as a person's search is: a secret that leaks from an
/// application's configuration is used to export the directory. Only the
/// counts are kept, not the entries.
#[derive(Debug)]
pub struct DirectoryServiceSearchPerformed {
    /// The account bound as.
    pub(crate) account_id: DirectoryServiceAccountId,
    /// The bind label identifying who read these directory entries.
    pub(crate) name: EventLabel,
    /// User entries the search returned.
    pub(crate) users_returned: u32,
    /// Group entries the search returned.
    pub(crate) groups_returned: u32,
    /// When the search completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectoryServiceSearchPerformed => crate::types::event_type::AuthenticationEvent::DirectoryServiceSearchPerformed,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("service_account", account_reference(self.account_id, &self.name))
            .field("protocol", "ldap")
            .field("users_returned", self.users_returned.to_string())
            .field("groups_returned", self.groups_returned.to_string())
    }
}

/// An application bound as a service account was refused a search: aimed
/// outside the directory it bound to, or under a base its scope does not
/// cover.
#[derive(Debug)]
pub struct DirectoryServiceSearchDenied {
    /// The account bound as.
    pub(crate) account_id: DirectoryServiceAccountId,
    /// The bind label identifying whose directory search was refused.
    pub(crate) name: EventLabel,
    /// When the search was refused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectoryServiceSearchDenied => crate::types::event_type::AuthenticationEvent::DirectoryServiceSearchDenied,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("service_account", account_reference(self.account_id, &self.name))
            .field("protocol", "ldap")
    }
}

/// An application bound to the directory as a service account.
///
/// Like a person's bind, it opens no session. It is recorded because a
/// service account's secret sits in an application's configuration, where
/// it leaks more easily than a password a person keeps.
#[derive(Debug)]
pub struct DirectoryServiceBound {
    /// The account bound as.
    pub(crate) account_id: DirectoryServiceAccountId,
    /// The bind label identifying the successfully authenticated application.
    pub(crate) name: EventLabel,
    /// When the bind was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DirectoryServiceBound => crate::types::event_type::AuthenticationEvent::DirectoryServiceBound,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("service_account", account_reference(self.account_id, &self.name))
            .field("protocol", "ldap")
    }
}
