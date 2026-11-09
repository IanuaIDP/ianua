//! Adding a user over LDAP: an `Add` under `ou=users`, made as the person
//! bound to the directory.
//!
//! It is the dashboard's registration, asked for by the bound person with
//! their own rights: the same plan limit, the same password rules, and the
//! same confirmation link to the new address. `Add` has no secure way to
//! hand a made-up password back, so the request brings one.

use std::sync::Arc;

use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DisplayName, Email, UserId};

use crate::auditor::RequestAuditor;
use crate::email::EmailVerification;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::directory::principal::DirectoryPrincipal;
use crate::use_cases::identity::users::{New, RegisterUseCase};

/// A user added through the directory. It holds the first password, so it
/// has no `Debug`.
pub struct NewDirectory {
    /// The address they sign in with.
    pub email: Email,
    /// The name shown to people.
    pub display_name: DisplayName,
    /// Their first password.
    pub password: Secret,
}

/// The ports [`AddDirectoryUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddDirectoryPorts {
    /// Registers the user, with the bound person's own rights.
    pub register: Arc<RegisterUseCase>,
}

/// Adds tenant users for a person bound to the directory.
pub struct AddDirectoryUseCase {
    ports: AddDirectoryPorts,
}

impl AddDirectoryUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AddDirectoryPorts) -> Self {
        Self { ports }
    }
}

impl Command for AddDirectoryUseCase {
    type Caller = DirectoryPrincipal;
    type Input = NewDirectory;
    type Output = Result<UserId, AppError>;

    /// Registers the user `user` describes, as the person `principal` is
    /// bound as. The account may sign in at once, and its address waits for
    /// the link mailed to it. It starts with the tenant's default roles
    /// only. Records what registration records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the certificate the person bound
    ///   over was revoked or ran out since, their account was shut, or its
    ///   password was reset or changed since the bind.
    /// - `AppError::Forbidden` when they may not create users, or the plan's
    ///   user limit is reached.
    /// - `AppError::Conflict` when the address already has an account.
    /// - `AppError::Domain` when the password breaks the tenant's rules.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        user: NewDirectory,
    ) -> Result<UserId, AppError> {
        let new_user = New {
            email: user.email,
            display_name: user.display_name,
            password: Some(user.password.expose().to_owned()),
            verification: EmailVerification::Automatic,
            roles: Vec::new(),
            scope: principal.link_scope(),
        };
        let registered = self
            .ports
            .register
            .execute(principal.caller(), auditor, new_user)
            .await?;
        Ok(registered.id)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::ports::identity::UserStore;
    use crate::test_support::directory::{BindRefusal, BoundDirectory};
    use crate::test_support::tenant::{FakeTenantStore, cfg, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::identity::users::RegisterPorts;

    fn ports_over(directory: &BoundDirectory) -> RegisterPorts {
        RegisterPorts {
            user_store: directory.users.clone(),
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            access_records: directory.access.clone(),
            role_store: directory.sources.roles.clone(),
            assignment_store: directory.sources.assignments.clone(),
            tenant_authorities: directory.authorities(),
            ..RegisterPorts::fakes()
        }
    }

    fn add(ports: RegisterPorts, principal: &DirectoryPrincipal) -> Result<UserId, AppError> {
        let use_case = AddDirectoryUseCase::new(AddDirectoryPorts {
            register: Arc::new(RegisterUseCase::new(ports)),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let bob = NewDirectory {
            email: Email::new("bob@acme.test").unwrap(),
            display_name: DisplayName::new("Bob", &cfg().display_name).unwrap(),
            password: Secret::new("a long enough password 1A!"),
        };
        block_on(use_case.execute(principal, &auditor, bob))
    }

    /// Ann, an admin bound to the directory, adds Bob. His account is there
    /// and can sign in.
    #[test]
    fn a_bound_admin_adds_a_user() {
        let directory = BoundDirectory::holding(SystemPermission::all());
        let principal = directory.bind();

        let bob = add(ports_over(&directory), &principal).unwrap();

        let stored = block_on(directory.users.find_by_id(&test_ctx().tenant(), &bob))
            .unwrap()
            .unwrap();
        assert!(stored.can_authenticate());
    }

    /// A revoked certificate, closed account or missing creation right
    /// prevents Ann's bound connection from adding Bob.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_adds_no_one() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());

            let result = add(ports_over(&directory), &principal);

            assert!(refusal.refused(&result), "{refusal:?}");
            assert_eq!(directory.users.count(), 1, "{refusal:?}");
        }
    }

    /// Resetting Ann's password invalidates her existing directory bind;
    /// an attempt to add Bob through that connection leaves no new user.
    #[test]
    fn a_password_reset_after_the_bind_stops_the_next_write() {
        let directory = BoundDirectory::holding(SystemPermission::all());
        let principal = directory.bind();
        directory.reset_password();

        let result = add(ports_over(&directory), &principal);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(directory.users.count(), 1);
    }

    /// At the tenant's user limit, Ann's LDAP addition is forbidden and
    /// leaves the user count unchanged.
    #[test]
    fn a_user_is_refused_at_the_tenants_user_limit() {
        let directory = BoundDirectory::holding(SystemPermission::all());
        let principal = directory.bind();
        let ports = RegisterPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports_over(&directory)
        };

        let result = add(ports, &principal);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(directory.users.count(), 1);
    }
}
