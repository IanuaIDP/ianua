//! Changing a password over LDAP's Password-Modify extended operation
//! (RFC 3062), the only way `userPassword` is ever set; a plain `Modify` of
//! it is refused by the adapter.
//!
//! The bound person changes their own password by giving the current one,
//! which is checked as a fresh proof of them, as in the dashboard. LDAP
//! cannot carry a code, so the client certificate the bind was made over
//! stands in for their second factor while the bind is fresh. Or they reset
//! another user's, with the rights an admin needs for it.

use std::sync::Arc;

use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::UserId;

use crate::auditor::RequestAuditor;
use crate::context::Credential;
use crate::error::AppError;
use crate::services::authentication::fresh_proof::ReenteredProof;
use crate::use_case::Command;
use crate::use_cases::authentication::password::{ChangeRequest, ChangeUseCase};
use crate::use_cases::directory::principal::DirectoryPrincipal;
use crate::use_cases::identity::users::{ResetPasswordRequest, ResetPasswordUseCase};

/// A Password-Modify request. It holds passwords, so it has no `Debug`.
pub enum DirectoryPasswordChange {
    /// The bound person changes their own password.
    Own {
        /// Their current password, which proves them again.
        old_password: Secret,
        /// The password to set.
        new_password: Secret,
    },
    /// The bound person resets another user's password. Nobody knows the
    /// other user's password, so what the bound person holds decides.
    ForOtherUser {
        /// The user whose password is reset.
        user_id: UserId,
        /// The password to set; `None` makes one up.
        new_password: Option<String>,
    },
}

/// The ports [`ChangeDirectoryPasswordUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeDirectoryPasswordPorts {
    /// Changes the bound person's own password, once they proved who they
    /// are again.
    pub password_change: Arc<ChangeUseCase>,
    /// Resets another user's password, with the bound person's own rights.
    pub reset_password: Arc<ResetPasswordUseCase>,
}

/// Changes passwords for a person bound to the directory.
pub struct ChangeDirectoryPasswordUseCase {
    ports: ChangeDirectoryPasswordPorts,
}

impl ChangeDirectoryPasswordUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeDirectoryPasswordPorts) -> Self {
        Self { ports }
    }

    /// Changes the bound person's own password, proved by their current
    /// one typed over the bind. LDAP cannot carry a code, so the
    /// certificate the bind was made over stands in for their second
    /// factor while the bind is fresh.
    async fn change_own(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        old_password: Secret,
        new_password: Secret,
    ) -> Result<Option<Secret>, AppError> {
        let Credential::DirectoryBind(bound) = principal.caller().credential() else {
            return Err(AppError::Unauthenticated);
        };
        let request = ChangeRequest {
            proof: ReenteredProof::OverDirectoryBind {
                password: old_password,
                bound: bound.clone(),
            },
            new_password,
        };
        self.ports
            .password_change
            .execute(principal.caller(), auditor, request)
            .await?;
        Ok(None)
    }

    /// Resets another user's password, handing back the one made up when
    /// none was given.
    async fn reset_other(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        request: ResetPasswordRequest,
    ) -> Result<Option<Secret>, AppError> {
        let made_up = request.new_password.is_none();
        let reset = self
            .ports
            .reset_password
            .execute(principal.caller(), auditor, request)
            .await?;
        Ok(made_up.then_some(reset.new_password))
    }
}

impl Command for ChangeDirectoryPasswordUseCase {
    type Caller = DirectoryPrincipal;
    type Input = DirectoryPasswordChange;
    type Output = Result<Option<Secret>, AppError>;

    /// Changes a password as `change` says, as the person `principal` is
    /// bound as. Returns the made-up password when a reset was given none,
    /// for the Password-Modify response's `genPasswd`. Records what a
    /// password change or reset records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for a revoked/expired bind certificate, closed account or password changed since binding.
    /// - `AppError::Forbidden` for a wrong current password, stale own-account bind, missing reset rights or a target holding more rights.
    /// - `AppError::NotFound` for a missing user/password; `Conflict` for password reuse, a change too soon or a deactivated target.
    /// - `AppError::Domain` for a password outside tenant rules; `Internal` on persistence or hashing failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        change: DirectoryPasswordChange,
    ) -> Result<Option<Secret>, AppError> {
        match change {
            DirectoryPasswordChange::Own {
                old_password,
                new_password,
            } => {
                self.change_own(principal, auditor, old_password, new_password)
                    .await
            }
            DirectoryPasswordChange::ForOtherUser {
                user_id,
                new_password,
            } => {
                let request = ResetPasswordRequest {
                    user_id,
                    new_password,
                };
                self.reset_other(principal, auditor, request).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::test_support::fakes::FakeHasher;

    use super::*;
    use crate::test_support::directory::{BOUND_PASSWORD, BindRefusal, BoundDirectory};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::authentication::password::{ChangePolicy, ChangePorts};
    use crate::use_cases::identity::users::ResetPasswordPorts;

    const NEW_PASSWORD: &str = "a brand new password 2B!";

    fn use_case_over(directory: &BoundDirectory) -> ChangeDirectoryPasswordUseCase {
        let tenants = Arc::new(FakeTenantStore::holding(test_tenant_for_ctx()));
        let policy = ChangePolicy {
            history_check_count: 0,
            min_age_seconds: 0,
        };
        let password_change = ChangeUseCase::new(
            policy,
            ChangePorts {
                tenant_authorities: directory.authorities(),
                credential_store: directory.credentials.clone(),
                user_store: directory.users.clone(),
                tenant_store: tenants.clone(),
                ..ChangePorts::fakes()
            },
        );
        let reset_password = ResetPasswordUseCase::new(ResetPasswordPorts {
            user_store: directory.users.clone(),
            access_records: directory.access.clone(),
            tenant_authorities: directory.authorities(),
            credential_store: directory.credentials.clone(),
            tenant_store: tenants,
            ..ResetPasswordPorts::fakes()
        });
        ChangeDirectoryPasswordUseCase::new(ChangeDirectoryPasswordPorts {
            password_change: Arc::new(password_change),
            reset_password: Arc::new(reset_password),
        })
    }

    fn changed(
        directory: &BoundDirectory,
        principal: &DirectoryPrincipal,
        change: DirectoryPasswordChange,
    ) -> Result<Option<Secret>, AppError> {
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case_over(directory).execute(principal, &auditor, change))
    }

    fn own(old_password: &str) -> DirectoryPasswordChange {
        DirectoryPasswordChange::Own {
            old_password: Secret::new(old_password),
            new_password: Secret::new(NEW_PASSWORD),
        }
    }

    fn holds_password(directory: &BoundDirectory, user: &UserId, password: &str) -> bool {
        let hash = directory.credentials.hash_of(user).unwrap();
        FakeHasher.verify(password, &hash).unwrap()
    }

    /// Ann, bound to the directory, changes her own password, giving the
    /// current one. The new one is hers now.
    #[test]
    fn a_bound_person_changes_their_own_password_with_the_old_one() {
        let directory = BoundDirectory::holding(&[]);

        changed(&directory, &directory.bind(), own(BOUND_PASSWORD)).unwrap();

        assert!(holds_password(&directory, &directory.ann, NEW_PASSWORD));
    }

    /// Guessing the current password on Ann's bound connection is
    /// forbidden and leaves her original password valid.
    #[test]
    fn changing_ones_own_password_needs_the_old_one() {
        let directory = BoundDirectory::holding(&[]);

        let result = changed(&directory, &directory.bind(), own("a guess"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(holds_password(&directory, &directory.ann, BOUND_PASSWORD));
    }

    /// Revoking Ann's certificate, closing her account or resetting her
    /// password invalidates the bind and prevents a password change.
    #[test]
    fn a_bind_that_no_longer_counts_changes_no_password() {
        let ended = [
            BindRefusal::CertificateRevoked,
            BindRefusal::AccountClosed,
            BindRefusal::PasswordReset,
        ];
        for refusal in ended {
            let (directory, principal) = refusal.bound(&[]);

            let result = changed(&directory, &principal, own(BOUND_PASSWORD));

            assert!(refusal.refused(&result), "{refusal:?}");
            assert!(holds_password(&directory, &directory.ann, BOUND_PASSWORD));
        }
    }

    /// Ann, an admin bound to the directory, resets Bob's password without
    /// choosing one. One is made up for him and handed back.
    #[test]
    fn a_bound_admin_resets_another_users_password() {
        let directory = BoundDirectory::holding(SystemPermission::all());
        let bob = UserId::new();
        directory.users.add_active_user(bob, "bob@acme.test");
        let reset = DirectoryPasswordChange::ForOtherUser {
            user_id: bob,
            new_password: None,
        };

        let made_up = changed(&directory, &directory.bind(), reset)
            .unwrap()
            .unwrap();

        assert!(holds_password(&directory, &bob, made_up.expose()));
    }

    /// An invalid bind or missing reset right prevents Ann from writing
    /// a password credential for Bob.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_resets_no_password() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());
            let bob = UserId::new();
            directory.users.add_active_user(bob, "bob@acme.test");
            let reset = DirectoryPasswordChange::ForOtherUser {
                user_id: bob,
                new_password: Some(NEW_PASSWORD.to_owned()),
            };

            let result = changed(&directory, &principal, reset);

            assert!(refusal.refused(&result), "{refusal:?}");
            assert!(directory.credentials.hash_of(&bob).is_none(), "{refusal:?}");
        }
    }
}
