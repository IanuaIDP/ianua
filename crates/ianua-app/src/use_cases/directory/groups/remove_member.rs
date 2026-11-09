//! Removing a member from a group over LDAP: a `Modify` deleting from its
//! `member`, made as the person bound to the directory, with the
//! dashboard's own checks.

use std::sync::Arc;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authorization::groups::{RemoveMemberRequest, RemoveMemberUseCase};
use crate::use_cases::directory::principal::DirectoryPrincipal;

/// The ports [`RemoveDirectoryMemberUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveDirectoryMemberPorts {
    /// Takes the member out of the group, with the bound person's own
    /// rights.
    pub remove_member: Arc<RemoveMemberUseCase>,
}

/// Removes group members for a person bound to the directory.
pub struct RemoveDirectoryMemberUseCase {
    ports: RemoveDirectoryMemberPorts,
}

impl RemoveDirectoryMemberUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveDirectoryMemberPorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveDirectoryMemberUseCase {
    type Caller = DirectoryPrincipal;
    type Input = RemoveMemberRequest;
    type Output = Result<(), AppError>;

    /// Takes `request.member` out of `request.group_id`, as the person
    /// `principal` is bound as. Records what removing a member records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an expired/revoked bind certificate,
    ///   a closed account, or a password changed or reset since binding.
    /// - `AppError::NotFound` for a missing group or membership.
    /// - `AppError::Forbidden` without role-assignment rights or authority to grant the group's rights.
    /// - `AppError::Conflict` when the member is the tenant's last
    ///   administrator, through this group.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        request: RemoveMemberRequest,
    ) -> Result<(), AppError> {
        self.ports
            .remove_member
            .execute(principal.caller(), auditor, request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::test_support::directory::{BindRefusal, BoundDirectory};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::authorization::groups::RemoveMemberPorts;

    fn remove(directory: &BoundDirectory, principal: &DirectoryPrincipal) -> Result<(), AppError> {
        let engineering = directory.add_group("Engineering");
        let bob = PrincipalRef::User(UserId::new());
        directory.add_member(engineering, bob);
        let use_case = RemoveDirectoryMemberUseCase::new(RemoveDirectoryMemberPorts {
            remove_member: Arc::new(RemoveMemberUseCase::new(RemoveMemberPorts {
                group_store: directory.sources.groups.clone(),
                membership_store: directory.sources.memberships.clone(),
                access_records: directory.access.clone(),
                tenant_authorities: directory.authorities(),
                ..RemoveMemberPorts::fakes()
            })),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let request = RemoveMemberRequest {
            group_id: engineering,
            member: bob,
        };
        block_on(use_case.execute(principal, &auditor, request))
    }

    /// Ann, an admin bound to the directory, takes Bob out of
    /// "Engineering". He no longer belongs to it.
    #[test]
    fn a_bound_admin_removes_a_member() {
        let directory = BoundDirectory::holding(SystemPermission::all());

        remove(&directory, &directory.bind()).unwrap();

        assert_eq!(directory.sources.memberships.count(), 0);
    }

    /// An invalid bind or missing assignment right prevents Ann from
    /// removing Bob's membership in Engineering.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_removes_no_member() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());

            let result = remove(&directory, &principal);

            assert!(refusal.refused(&result), "{refusal:?}");
            assert_eq!(directory.sources.memberships.count(), 1, "{refusal:?}");
        }
    }
}
