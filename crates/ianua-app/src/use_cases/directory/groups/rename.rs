//! Renaming a group over LDAP: a `ModifyDN` of its entry, made as the
//! person bound to the directory, with the dashboard's own checks.

use std::sync::Arc;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authorization::groups::{RenameRequest, RenameUseCase};
use crate::use_cases::directory::principal::DirectoryPrincipal;

/// The ports [`RenameDirectoryUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenameDirectoryPorts {
    /// Renames the group, with the bound person's own rights.
    pub rename_group: Arc<RenameUseCase>,
}

/// Renames groups for a person bound to the directory.
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

    /// Gives `request.group_id` the name `request.new_name`, as the person
    /// `principal` is bound as. Records what renaming a group records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an expired/revoked bind certificate,
    ///   a closed account, or a password changed or reset since binding.
    /// - `AppError::NotFound` when the group does not exist.
    /// - `AppError::Conflict` when another group already has the name.
    /// - `AppError::Forbidden` when they may not update roles, which covers
    ///   groups.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        request: RenameRequest,
    ) -> Result<(), AppError> {
        self.ports
            .rename_group
            .execute(principal.caller(), auditor, request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::Label;

    use super::*;
    use crate::ports::authorization::GroupStore;
    use crate::test_support::directory::{BindRefusal, BoundDirectory};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authorization::groups::RenamePorts;

    fn rename(directory: &BoundDirectory, principal: &DirectoryPrincipal) -> Result<(), AppError> {
        let group_id = directory.add_group("Engineering");
        let use_case = RenameDirectoryUseCase::new(RenameDirectoryPorts {
            rename_group: Arc::new(RenameUseCase::new(RenamePorts {
                group_store: directory.sources.groups.clone(),
                tenant_authorities: directory.authorities(),
            })),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let request = RenameRequest {
            group_id,
            new_name: Label::new("group_name", "Platform").unwrap(),
        };
        block_on(use_case.execute(principal, &auditor, request))
    }

    fn named_platform(directory: &BoundDirectory) -> bool {
        let name = Label::new("group_name", "Platform").unwrap();
        block_on(
            directory
                .sources
                .groups
                .find_by_name(&test_ctx().tenant(), &name),
        )
        .unwrap()
        .is_some()
    }

    /// Ann, an admin bound to the directory, renames "Engineering" to
    /// "Platform". The group goes by its new name.
    #[test]
    fn a_bound_admin_renames_a_group() {
        let directory = BoundDirectory::holding(SystemPermission::all());

        rename(&directory, &directory.bind()).unwrap();

        assert!(named_platform(&directory));
    }

    /// An invalid bind or missing editing right prevents Ann from
    /// renaming Engineering to Platform.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_renames_no_group() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());

            let result = rename(&directory, &principal);

            assert!(refusal.refused(&result), "{refusal:?}");
            assert!(!named_platform(&directory), "{refusal:?}");
        }
    }
}
