//! Removing a group over LDAP: a `Delete` of its entry, made as the person
//! bound to the directory, with the dashboard's own checks.

use std::sync::Arc;

use ianua_domain::types::GroupId;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authorization::groups::DeleteUseCase;
use crate::use_cases::directory::principal::DirectoryPrincipal;

/// The ports [`RemoveDirectoryUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveDirectoryPorts {
    /// Deletes the group, with the bound person's own rights.
    pub delete: Arc<DeleteUseCase>,
}

/// Removes groups for a person bound to the directory.
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
    type Input = GroupId;
    type Output = Result<(), AppError>;

    /// Deletes `group_id`, as the person `principal` is bound as. Records
    /// what deleting a group records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an expired/revoked bind certificate,
    ///   a closed account, or a password changed or reset since binding.
    /// - `AppError::NotFound` when the group does not exist.
    /// - `AppError::Forbidden` without role-deletion rights or authority to grant the group's rights.
    /// - `AppError::Conflict` when another group sits under it, or deleting
    ///   it leaves the tenant nobody can administer.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        group_id: GroupId,
    ) -> Result<(), AppError> {
        self.ports
            .delete
            .execute(principal.caller(), auditor, group_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::directory::{BindRefusal, BoundDirectory};
    use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::authorization::groups::DeletePorts;

    fn remove(directory: &BoundDirectory, principal: &DirectoryPrincipal) -> Result<(), AppError> {
        let group_id = directory.add_group("Engineering");
        let use_case = RemoveDirectoryUseCase::new(RemoveDirectoryPorts {
            delete: Arc::new(DeleteUseCase::new(DeletePorts {
                group_store: directory.sources.groups.clone(),
                access_records: directory.access.clone(),
                tenant_authorities: directory.authorities(),
                connection_store: Fake::fake(),
            })),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(principal, &auditor, group_id))
    }

    /// Ann, an admin bound to the directory, removes "Engineering". The
    /// tenant no longer has it.
    #[test]
    fn a_bound_admin_removes_a_group() {
        let directory = BoundDirectory::holding(SystemPermission::all());

        remove(&directory, &directory.bind()).unwrap();

        assert_eq!(directory.sources.groups.count(), 0);
    }

    /// An invalid bind or missing deletion right prevents Ann from
    /// removing Engineering.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_removes_no_group() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());

            let result = remove(&directory, &principal);

            assert!(refusal.refused(&result), "{refusal:?}");
            assert_eq!(directory.sources.groups.count(), 1, "{refusal:?}");
        }
    }
}
