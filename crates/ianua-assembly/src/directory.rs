//! The directory use cases the API serves: a person's LDAP client
//! certificates, and the service accounts applications bind to the
//! directory as. Binds, searches and directory writes come over LDAP and are
//! the LDAP server's: [`LdapUseCases`] are built here over the dashboard's
//! own, so a write over LDAP runs through the same use case a write in the
//! dashboard does, and the server hands them to the LDAP server.

use std::sync::Arc;

use ianua_app::ports::authorization::GroupStore;
use ianua_app::ports::identity::UserStore;
use ianua_app::use_cases::directory::certificates::{
    IssueLdapPorts, IssueLdapUseCase, ListLdapPorts, ListLdapUseCase, RevokeLdapPorts,
    RevokeLdapUseCase,
};
use ianua_app::use_cases::directory::listing::EntryPorts;
use ianua_app::use_cases::directory::{self, groups, service_accounts, users};

use crate::authentication::{AuthenticationState, password_hashing, sign_in_counts};
use crate::authorization::AuthorizationState;
use crate::deps::{Adapters, Settings};
use crate::identity::IdentityState;

/// The directory use cases.
#[derive(Clone)]
pub struct DirectoryState {
    pub issue_certificate: Arc<IssueLdapUseCase>,
    pub list_certificates: Arc<ListLdapUseCase>,
    pub revoke_certificate: Arc<RevokeLdapUseCase>,
    pub service_accounts: ServiceAccountsState,
}

/// The use cases over the directory's service accounts.
#[derive(Clone)]
pub struct ServiceAccountsState {
    pub create: Arc<service_accounts::CreateUseCase>,
    pub list: Arc<service_accounts::ListUseCase>,
    pub get: Arc<service_accounts::GetUseCase>,
    pub change_scope: Arc<service_accounts::ChangeScopeUseCase>,
    pub change_status: Arc<service_accounts::ChangeStatusUseCase>,
    pub rotate_secret: Arc<service_accounts::RotateSecretUseCase>,
    pub delete: Arc<service_accounts::DeleteUseCase>,
}

/// The use cases the LDAP server serves, for the server to hand over.
#[derive(Clone)]
pub struct LdapUseCases {
    /// Binds a person, by their password over their client certificate.
    pub bind: Arc<directory::BindUseCase>,
    /// Binds an application as its service account.
    pub service_bind: Arc<service_accounts::BindUseCase>,
    /// Reads the directory for a bound person.
    pub search: Arc<directory::SearchUseCase>,
    /// Reads the directory for a bound service account.
    pub service_search: Arc<service_accounts::SearchAsUseCase>,
    /// A bound person's writes to the tenant's users.
    pub users: LdapUserWrites,
    /// A bound person's writes to the tenant's groups.
    pub groups: LdapGroupWrites,
    /// Finds the user an entry's DN names, in the tenant bound to.
    pub user_store: Arc<dyn UserStore>,
    /// Finds the group an entry's DN names, in the tenant bound to.
    pub group_store: Arc<dyn GroupStore>,
}

/// A bound person's writes to the tenant's users, each the dashboard's own.
#[derive(Clone)]
pub struct LdapUserWrites {
    /// `Add` under `ou=users`.
    pub add: Arc<users::AddDirectoryUseCase>,
    /// `Modify` of a user's `cn`.
    pub rename: Arc<users::RenameDirectoryUseCase>,
    /// `ModifyDN` of a user's entry.
    pub change_email: Arc<users::ChangeDirectoryEmailUseCase>,
    /// `Delete` of a user's entry.
    pub remove: Arc<users::RemoveDirectoryUseCase>,
    /// Password-Modify.
    pub change_password: Arc<users::ChangeDirectoryPasswordUseCase>,
}

/// A bound person's writes to the tenant's groups, each the dashboard's
/// own.
#[derive(Clone)]
pub struct LdapGroupWrites {
    /// `Add` under `ou=groups`.
    pub add: Arc<groups::AddDirectoryUseCase>,
    /// `ModifyDN` of a group's entry.
    pub rename: Arc<groups::RenameDirectoryUseCase>,
    /// `Delete` of a group's entry.
    pub remove: Arc<groups::RemoveDirectoryUseCase>,
    /// `Modify` adding to a group's `member`.
    pub add_member: Arc<groups::AddDirectoryMemberUseCase>,
    /// `Modify` deleting from a group's `member`.
    pub remove_member: Arc<groups::RemoveDirectoryMemberUseCase>,
}

/// The dashboard's use cases a write over LDAP goes through.
pub(crate) struct DashboardWrites<'a> {
    pub identity: &'a IdentityState,
    pub authentication: &'a AuthenticationState,
    pub authorization: &'a AuthorizationState,
}

/// Builds the LDAP server's use cases over `a`, its writes through
/// `dashboard`'s own.
pub(crate) fn ldap(a: &Adapters, dashboard: &DashboardWrites<'_>) -> LdapUseCases {
    LdapUseCases {
        bind: Arc::new(bind(a)),
        service_bind: Arc::new(service_accounts::BindUseCase::new(
            service_accounts::BindPorts {
                organizations: a.organization_store.clone(),
                tenants: a.tenant_store.clone(),
                throttle: a.bind_throttle.clone(),
                accounts: a.directory_service_account_store.clone(),
                secrets: a.service_account_secrets.clone(),
            },
        )),
        search: Arc::new(directory::SearchUseCase::new(directory::SearchPorts {
            entries: entries(a),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        service_search: Arc::new(service_accounts::SearchAsUseCase::new(
            service_accounts::SearchAsPorts {
                accounts: a.directory_service_account_store.clone(),
                entries: entries(a),
            },
        )),
        users: ldap_user_writes(dashboard),
        groups: ldap_group_writes(dashboard.authorization),
        user_store: a.user_store.clone(),
        group_store: a.group_store.clone(),
    }
}

/// Authenticates a directory user with certificate, password and admission limits.
fn bind(a: &Adapters) -> directory::BindUseCase {
    directory::BindUseCase::new(directory::BindPorts {
        organizations: a.organization_store.clone(),
        tenants: a.tenant_store.clone(),
        throttle: a.bind_throttle.clone(),
        certificates: a.ldap_certificate_store.clone(),
        users: a.user_store.clone(),
        credentials: a.credential_store.clone(),
        attempts: sign_in_counts(a),
        hashing: password_hashing(a),
        directory_authorities: a.directory_authorities.clone(),
        plan_limits: a.plan_limits_source.clone(),
    })
}

/// Where the directory's entries are read from.
fn entries(a: &Adapters) -> EntryPorts {
    EntryPorts {
        users: a.user_store.clone(),
        groups: a.group_store.clone(),
        memberships: a.group_membership_store.clone(),
    }
}

/// A bound person's writes to users, through `dashboard`'s use cases.
fn ldap_user_writes(dashboard: &DashboardWrites<'_>) -> LdapUserWrites {
    let identity = dashboard.identity;
    LdapUserWrites {
        add: Arc::new(users::AddDirectoryUseCase::new(users::AddDirectoryPorts {
            register: identity.users.register.clone(),
        })),
        rename: Arc::new(users::RenameDirectoryUseCase::new(
            users::RenameDirectoryPorts {
                rename_user: identity.users.rename.clone(),
            },
        )),
        change_email: Arc::new(users::ChangeDirectoryEmailUseCase::new(
            users::ChangeDirectoryEmailPorts {
                change_email: identity.email.change.clone(),
            },
        )),
        remove: Arc::new(users::RemoveDirectoryUseCase::new(
            users::RemoveDirectoryPorts {
                delete: identity.users.delete.clone(),
            },
        )),
        change_password: Arc::new(users::ChangeDirectoryPasswordUseCase::new(
            users::ChangeDirectoryPasswordPorts {
                password_change: dashboard.authentication.password.change.clone(),
                reset_password: identity.users.reset_password.clone(),
            },
        )),
    }
}

/// A bound person's writes to groups, through `authorization`'s use cases.
fn ldap_group_writes(authorization: &AuthorizationState) -> LdapGroupWrites {
    let dashboard = &authorization.groups;
    LdapGroupWrites {
        add: Arc::new(groups::AddDirectoryUseCase::new(
            groups::AddDirectoryPorts {
                create: dashboard.create.clone(),
            },
        )),
        rename: Arc::new(groups::RenameDirectoryUseCase::new(
            groups::RenameDirectoryPorts {
                rename_group: dashboard.rename.clone(),
            },
        )),
        remove: Arc::new(groups::RemoveDirectoryUseCase::new(
            groups::RemoveDirectoryPorts {
                delete: dashboard.delete.clone(),
            },
        )),
        add_member: Arc::new(groups::AddDirectoryMemberUseCase::new(
            groups::AddDirectoryMemberPorts {
                add_member: dashboard.add_member.clone(),
            },
        )),
        remove_member: Arc::new(groups::RemoveDirectoryMemberUseCase::new(
            groups::RemoveDirectoryMemberPorts {
                remove_member: dashboard.remove_member.clone(),
            },
        )),
    }
}

/// Builds the directory use cases over `a`, with `s`'s certificate validity.
pub fn build(a: &Adapters, s: &Settings) -> DirectoryState {
    DirectoryState {
        issue_certificate: Arc::new(IssueLdapUseCase::new(
            IssueLdapPorts {
                certificate_authority: a.ldap_certificate_authority.clone(),
                certificate_store: a.ldap_certificate_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
                fresh_proofs: a.fresh_proofs.clone(),
            },
            s.tunables.ldap_certificate_validity,
        )),
        list_certificates: Arc::new(ListLdapUseCase::new(ListLdapPorts {
            certificate_store: a.ldap_certificate_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        revoke_certificate: Arc::new(RevokeLdapUseCase::new(RevokeLdapPorts {
            certificate_store: a.ldap_certificate_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        service_accounts: service_accounts_state(a),
    }
}

/// Builds the service account use cases over `a`.
fn service_accounts_state(a: &Adapters) -> ServiceAccountsState {
    ServiceAccountsState {
        create: Arc::new(create_service_account(a)),
        list: Arc::new(service_accounts::ListUseCase::new(
            service_accounts::ListPorts {
                accounts: a.directory_service_account_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        get: Arc::new(service_accounts::GetUseCase::new(
            service_accounts::GetPorts {
                accounts: a.directory_service_account_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        change_scope: Arc::new(change_service_scope(a)),
        change_status: Arc::new(service_accounts::ChangeStatusUseCase::new(
            service_accounts::ChangeStatusPorts {
                accounts: a.directory_service_account_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        rotate_secret: Arc::new(rotate_service_secret(a)),
        delete: Arc::new(service_accounts::DeleteUseCase::new(
            service_accounts::DeletePorts {
                accounts: a.directory_service_account_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// Creates directory service accounts with generated secrets and tenant plan limits.
fn create_service_account(a: &Adapters) -> service_accounts::CreateUseCase {
    service_accounts::CreateUseCase::new(service_accounts::CreatePorts {
        accounts: a.directory_service_account_store.clone(),
        secrets: a.service_account_secrets.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes a service account's directory scope under tenant authority.
fn change_service_scope(a: &Adapters) -> service_accounts::ChangeScopeUseCase {
    service_accounts::ChangeScopeUseCase::new(service_accounts::ChangeScopePorts {
        accounts: a.directory_service_account_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Rotates the secret an application uses to bind to the directory.
fn rotate_service_secret(a: &Adapters) -> service_accounts::RotateSecretUseCase {
    service_accounts::RotateSecretUseCase::new(service_accounts::RotateSecretPorts {
        accounts: a.directory_service_account_store.clone(),
        secrets: a.service_account_secrets.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}
