//! Renaming a user over LDAP: a `Modify` of their `cn`, made as the person
//! bound to the directory, with the dashboard's own checks.

use std::sync::Arc;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::directory::principal::DirectoryPrincipal;
use crate::use_cases::identity::users::{RenameRequest, RenameUseCase};

/// The ports [`RenameDirectoryUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenameDirectoryPorts {
    /// Renames the user, with the bound person's own rights.
    pub rename_user: Arc<RenameUseCase>,
}

/// Renames tenant users for a person bound to the directory.
pub struct RenameDirectoryUseCase {
    ports: RenameDirectoryPorts,
}

impl RenameDirectoryUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenameDirectoryPorts) -> Self {
        Self { ports }
    }
}

impl Command for RenameDirectoryUseCase {
    type Caller = DirectoryPrincipal;
    type Input = RenameRequest;
    type Output = Result<(), AppError>;

    /// Gives `request.user_id` the name `request.new_name`, as the person
    /// `principal` is bound as. Records what a rename records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the certificate the person bound
    ///   over was revoked or ran out since, their account was shut, or its
    ///   password was reset or changed since the bind.
    /// - `AppError::NotFound` if the user doesn't exist.
    /// - `AppError::Forbidden` when they may not edit the user's profile, or
    ///   the user holds more than they do.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        request: RenameRequest,
    ) -> Result<(), AppError> {
        self.ports
            .rename_user
            .execute(principal.caller(), auditor, request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::{DisplayName, UserId};

    use super::*;
    use crate::test_support::directory::{BindRefusal, BoundDirectory};
    use crate::test_support::tenant::cfg;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::identity::users::RenamePorts;

    fn rename(
        directory: &BoundDirectory,
        principal: &DirectoryPrincipal,
    ) -> (UserId, Result<(), AppError>) {
        let bob = UserId::new();
        directory.users.add_active_user(bob, "bob@acme.test");
        let use_case = RenameDirectoryUseCase::new(RenameDirectoryPorts {
            rename_user: Arc::new(RenameUseCase::new(RenamePorts {
                user_store: directory.users.clone(),
                access_records: directory.access.clone(),
                tenant_authorities: directory.authorities(),
            })),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let request = RenameRequest {
            user_id: bob,
            new_name: DisplayName::new("Robert", &cfg().display_name).unwrap(),
        };
        (
            bob,
            block_on(use_case.execute(principal, &auditor, request)),
        )
    }

    /// Ann, an admin bound to the directory, renames Bob. He is called
    /// Robert now.
    #[test]
    fn a_bound_admin_renames_a_user() {
        let directory = BoundDirectory::holding(SystemPermission::all());

        let (bob, result) = rename(&directory, &directory.bind());

        result.unwrap();
        assert_eq!(
            directory.users.get_display_name(&bob).unwrap().as_str(),
            "Robert"
        );
    }

    /// An invalid bind or missing editing right prevents Ann from
    /// assigning Bob the requested name.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_renames_no_one() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());

            let (bob, result) = rename(&directory, &principal);

            assert!(refusal.refused(&result), "{refusal:?}");
            assert_ne!(
                directory.users.get_display_name(&bob).unwrap().as_str(),
                "Robert"
            );
        }
    }
}
