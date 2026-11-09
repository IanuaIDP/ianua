//! The decisions the LDAP server asks for: the directory use cases, and
//! where an entry's DN finds the user or group it names.

use std::sync::Arc;

use ianua_app::ports::authorization::GroupStore;
use ianua_app::ports::identity::UserStore;
use ianua_app::ports::shared::EventDispatcher;
use ianua_app::use_cases::directory::{self, groups, service_accounts, users};

/// What the LDAP server asks for every decision. It holds no rule of its
/// own: a bind, a search and a write are each one of these use cases.
pub struct LdapPorts {
    /// Binds a person, by their password over their client certificate.
    pub bind: Arc<directory::BindUseCase>,
    /// Binds an application as its service account.
    pub service_bind: Arc<service_accounts::BindUseCase>,
    /// Reads the directory for a bound person.
    pub search: Arc<directory::SearchUseCase>,
    /// Reads the directory for a bound service account.
    pub service_search: Arc<service_accounts::SearchAsUseCase>,
    /// A bound person's writes to the tenant's users.
    pub users: UserWrites,
    /// A bound person's writes to the tenant's groups.
    pub groups: GroupWrites,
    /// Where a write's DN finds what it names.
    pub targets: Targets,
    /// Where every request's records go.
    pub events: Arc<dyn EventDispatcher>,
}

/// A bound person's writes to the tenant's users.
pub struct UserWrites {
    /// `Add` under `ou=users`.
    pub add: Arc<users::AddDirectoryUseCase>,
    /// `Modify` of a user's `cn`.
    pub rename: Arc<users::RenameDirectoryUseCase>,
    /// `ModifyDN` of a user's entry, whose `uid` is their address.
    pub change_email: Arc<users::ChangeDirectoryEmailUseCase>,
    /// `Delete` of a user's entry.
    pub remove: Arc<users::RemoveDirectoryUseCase>,
    /// Password-Modify.
    pub change_password: Arc<users::ChangeDirectoryPasswordUseCase>,
}

/// A bound person's writes to the tenant's groups.
pub struct GroupWrites {
    /// `Add` under `ou=groups`.
    pub add: Arc<groups::AddDirectoryUseCase>,
    /// `ModifyDN` of a group's entry, whose `cn` is its name.
    pub rename: Arc<groups::RenameDirectoryUseCase>,
    /// `Delete` of a group's entry.
    pub remove: Arc<groups::RemoveDirectoryUseCase>,
    /// `Modify` adding to a group's `member`.
    pub add_member: Arc<groups::AddDirectoryMemberUseCase>,
    /// `Modify` deleting from a group's `member`.
    pub remove_member: Arc<groups::RemoveDirectoryMemberUseCase>,
}

/// Where a write's DN finds the user or group it names, in the tenant
/// bound to. Only the id is taken from what is found: whether the write may
/// touch it is the write's use case's to decide.
pub struct Targets {
    /// Finds a user by the address an entry's `uid` names.
    pub users: Arc<dyn UserStore>,
    /// Finds a group by the name an entry's `cn` names.
    pub groups: Arc<dyn GroupStore>,
}
