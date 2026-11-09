//! Removing a user over LDAP: a `Delete` of their entry, made as the person
//! bound to the directory, with the dashboard's own checks.

use std::sync::Arc;

use ianua_domain::types::UserId;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::directory::principal::DirectoryPrincipal;
use crate::use_cases::identity::users::DeleteUseCase;

/// The ports [`RemoveDirectoryUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveDirectoryPorts {
    /// Deletes the user, with the bound person's own rights.
    pub delete: Arc<DeleteUseCase>,
}

/// Removes tenant users for a person bound to the directory.
pub struct RemoveDirectoryUseCase {
    ports: RemoveDirectoryPorts,
}

impl RemoveDirectoryUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveDirectoryPorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveDirectoryUseCase {
    type Caller = DirectoryPrincipal;
    type Input = UserId;
    type Output = Result<(), AppError>;

    /// Deletes `user_id` for good, as the person `principal` is bound as,
    /// ending their sessions and the delegations they granted first.
    /// Records what a deletion records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an expired/revoked bind certificate,
    ///   a closed account, or a password changed or reset since binding.
    /// - `AppError::NotFound` if the user doesn't exist.
    /// - `AppError::Forbidden` without user-deletion rights or when the user holds more rights.
    /// - `AppError::Conflict` for the tenant's last administrator.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        user_id: UserId,
    ) -> Result<(), AppError> {
        self.ports
            .delete
            .execute(principal.caller(), auditor, user_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::directory::{BindRefusal, BoundDirectory};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::identity::users::DeletePorts;

    fn remove(
        directory: &BoundDirectory,
        principal: &DirectoryPrincipal,
    ) -> (UserId, Result<(), AppError>) {
        let bob = UserId::new();
        directory.users.add_active_user(bob, "bob@acme.test");
        let use_case = RemoveDirectoryUseCase::new(RemoveDirectoryPorts {
            delete: Arc::new(DeleteUseCase::new(DeletePorts {
                user_store: directory.users.clone(),
                access_records: directory.access.clone(),
                tenant_authorities: directory.authorities(),
                ..DeletePorts::fakes()
            })),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        (bob, block_on(use_case.execute(principal, &auditor, bob)))
    }

    /// Ann, an admin bound to the directory, removes Bob. His account is
    /// gone.
    #[test]
    fn a_bound_admin_removes_a_user() {
        let directory = BoundDirectory::holding(SystemPermission::all());

        let (bob, result) = remove(&directory, &directory.bind());

        result.unwrap();
        assert!(directory.users.get_status(&bob).is_none());
    }

    /// An invalid bind or missing deletion right prevents Ann from
    /// removing Bob's account.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_removes_no_one() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());

            let (bob, result) = remove(&directory, &principal);

            assert!(refusal.refused(&result), "{refusal:?}");
            assert!(directory.users.get_status(&bob).is_some(), "{refusal:?}");
        }
    }
}
