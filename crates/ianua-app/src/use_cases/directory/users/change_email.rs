//! Changing a user's address over LDAP: a `ModifyDN` of their entry, since
//! `uid` names it, made as the person bound to the directory.
//!
//! It is the dashboard's change of address: the new one waits for its
//! holder to confirm it, and links mailed to the old one stop working.

use std::sync::Arc;

use ianua_domain::types::{Email, UserId};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::directory::principal::DirectoryPrincipal;
use crate::use_cases::identity::email::{ChangeRequest, ChangeUseCase};

/// A new address for a user, as the directory names it.
#[derive(Debug, Clone)]
pub struct DirectoryEmailChange {
    /// The user whose entry is renamed.
    pub user_id: UserId,
    /// Their new address.
    pub new_email: Email,
}

/// The ports [`ChangeDirectoryEmailUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeDirectoryEmailPorts {
    /// Changes the address, with the bound person's own rights.
    pub change_email: Arc<ChangeUseCase>,
}

/// Changes tenant users' addresses for a person bound to the directory.
pub struct ChangeDirectoryEmailUseCase {
    ports: ChangeDirectoryEmailPorts,
}

impl ChangeDirectoryEmailUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeDirectoryEmailPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeDirectoryEmailUseCase {
    type Caller = DirectoryPrincipal;
    type Input = DirectoryEmailChange;
    type Output = Result<(), AppError>;

    /// Gives `change.user_id` the address `change.new_email`, as the person
    /// `principal` is bound as, and mails the link that confirms it. Records
    /// what a change of address records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the certificate the person bound
    ///   over was revoked or ran out since, their account was shut, or its
    ///   password was reset or changed since the bind.
    /// - `AppError::NotFound` if the user doesn't exist.
    /// - `AppError::Forbidden` when they may not change the user's sign-in,
    ///   or the user holds more than they do.
    /// - `AppError::Conflict` if another user already has the address.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        change: DirectoryEmailChange,
    ) -> Result<(), AppError> {
        let request = ChangeRequest {
            user_id: change.user_id,
            new_email: change.new_email,
            scope: principal.link_scope(),
        };
        self.ports
            .change_email
            .execute(principal.caller(), auditor, request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::directory::{BindRefusal, BoundDirectory};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::identity::email::ChangePorts;

    const NEW_ADDRESS: &str = "robert@acme.test";

    fn change(
        directory: &BoundDirectory,
        principal: &DirectoryPrincipal,
    ) -> (UserId, Result<(), AppError>) {
        let bob = UserId::new();
        directory.users.add_active_user(bob, "bob@acme.test");
        let use_case = ChangeDirectoryEmailUseCase::new(ChangeDirectoryEmailPorts {
            change_email: Arc::new(ChangeUseCase::new(ChangePorts {
                user_store: directory.users.clone(),
                access_records: directory.access.clone(),
                tenant_authorities: directory.authorities(),
                ..ChangePorts::fakes()
            })),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let request = DirectoryEmailChange {
            user_id: bob,
            new_email: Email::new(NEW_ADDRESS).unwrap(),
        };
        (
            bob,
            block_on(use_case.execute(principal, &auditor, request)),
        )
    }

    /// Ann, an admin bound to the directory, moves Bob to a new address. He
    /// has it now, waiting for him to confirm it.
    #[test]
    fn a_bound_admin_changes_a_users_address() {
        let directory = BoundDirectory::holding(SystemPermission::all());

        let (bob, result) = change(&directory, &directory.bind());

        result.unwrap();
        assert_eq!(
            directory.users.get_email(&bob).unwrap().as_str(),
            NEW_ADDRESS
        );
    }

    /// An invalid bind or missing authority prevents Ann from assigning
    /// Bob the requested address.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_moves_no_address() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());

            let (bob, result) = change(&directory, &principal);

            assert!(refusal.refused(&result), "{refusal:?}");
            assert_ne!(
                directory.users.get_email(&bob).unwrap().as_str(),
                NEW_ADDRESS
            );
        }
    }
}
