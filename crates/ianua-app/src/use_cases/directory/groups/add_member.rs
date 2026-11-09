//! Adding a member to a group over LDAP: a `Modify` adding to its
//! `member`, made as the person bound to the directory.
//!
//! The person hands out what the group carries, so the domain asks whether
//! they may, as it does in the dashboard. Sam, who may only assign roles,
//! adds himself to Admins over LDAP and is refused just the same.

use std::sync::Arc;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authorization::groups::{AddMemberRequest, AddMemberUseCase};
use crate::use_cases::directory::principal::DirectoryPrincipal;

/// The ports [`AddDirectoryMemberUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddDirectoryMemberPorts {
    /// Puts the member into the group, granted by the bound person.
    pub add_member: Arc<AddMemberUseCase>,
}

/// Adds group members for a person bound to the directory.
pub struct AddDirectoryMemberUseCase {
    ports: AddDirectoryMemberPorts,
}

impl AddDirectoryMemberUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AddDirectoryMemberPorts) -> Self {
        Self { ports }
    }
}

impl Command for AddDirectoryMemberUseCase {
    type Caller = DirectoryPrincipal;
    type Input = AddMemberRequest;
    type Output = Result<(), AppError>;

    /// Puts `request.member` into `request.group_id`, granted by the person
    /// `principal` is bound as. Records what adding a member records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an expired/revoked bind certificate,
    ///   a closed account, or a password changed or reset since binding.
    /// - `AppError::NotFound` when the group or the member does not exist.
    /// - `AppError::Conflict` when the member already belongs to the group.
    /// - `AppError::Forbidden` when they may not assign roles, or may not
    ///   hand out everything the group and the groups above it carry.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        request: AddMemberRequest,
    ) -> Result<(), AppError> {
        self.ports
            .add_member
            .execute(principal.caller(), auditor, request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
    use ianua_domain::types::{Expiry, GroupId, PrincipalRef, UserId};

    use super::*;
    use crate::test_support::directory::{BindRefusal, BoundDirectory};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::authorization::groups::AddMemberPorts;

    fn add(
        directory: &BoundDirectory,
        principal: &DirectoryPrincipal,
        group_id: GroupId,
        member: PrincipalRef,
    ) -> Result<(), AppError> {
        let use_case = AddDirectoryMemberUseCase::new(AddDirectoryMemberPorts {
            add_member: Arc::new(AddMemberUseCase::new(AddMemberPorts {
                group_store: directory.sources.groups.clone(),
                membership_store: directory.sources.memberships.clone(),
                access_records: directory.access.clone(),
                tenant_authorities: directory.authorities(),
                ..AddMemberPorts::fakes()
            })),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let request = AddMemberRequest {
            group_id,
            member,
            until: Expiry::Never,
        };
        block_on(use_case.execute(principal, &auditor, request))
    }

    fn bob() -> PrincipalRef {
        PrincipalRef::User(UserId::new())
    }

    /// Ann, an admin bound to the directory, puts Bob into "Engineering".
    /// He belongs to it.
    #[test]
    fn a_bound_admin_adds_a_member() {
        let directory = BoundDirectory::holding(SystemPermission::all());
        let engineering = directory.add_group("Engineering");

        add(&directory, &directory.bind(), engineering, bob()).unwrap();

        assert_eq!(directory.sources.memberships.count(), 1);
    }

    /// An invalid bind or missing assignment right prevents Ann from
    /// adding Bob to Engineering.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_adds_no_member() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());
            let engineering = directory.add_group("Engineering");

            let result = add(&directory, &principal, engineering, bob());

            assert!(refusal.refused(&result), "{refusal:?}");
            assert_eq!(directory.sources.memberships.count(), 0, "{refusal:?}");
        }
    }

    /// Role assignment alone does not let a bound person join Admins and
    /// acquire its stronger rights; no membership is created.
    #[test]
    fn a_bound_person_cannot_join_a_group_with_more_than_they_hold() {
        let directory = BoundDirectory::holding(&[SystemPermission::Roles(RoleAction::Assign)]);
        let admins = directory.add_admins();
        let sam = PrincipalRef::User(directory.ann);

        let result = add(&directory, &directory.bind(), admins, sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(directory.sources.memberships.count(), 0);
    }
}
