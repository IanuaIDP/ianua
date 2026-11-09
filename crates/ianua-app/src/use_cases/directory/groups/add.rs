//! Adding a group over LDAP: an `Add` under `ou=groups`, made as the person
//! bound to the directory, with the dashboard's own checks and plan limit.
//! A group made this way sits at the top of the tree.

use std::sync::Arc;

use ianua_domain::types::{GroupId, Label};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authorization::groups::{CreateRequest, CreateUseCase};
use crate::use_cases::directory::principal::DirectoryPrincipal;

/// The ports [`AddDirectoryUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddDirectoryPorts {
    /// Creates the group, with the bound person's own rights.
    pub create: Arc<CreateUseCase>,
}

/// Adds groups for a person bound to the directory.
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
    type Input = Label;
    type Output = Result<GroupId, AppError>;

    /// Creates the top-level group `name`, as the person `principal` is
    /// bound as. Records what creating a group records.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the certificate the person bound
    ///   over was revoked or ran out since, their account was shut, or its
    ///   password was reset or changed since the bind.
    /// - `AppError::Forbidden` when they may not create roles, which covers
    ///   groups, or the plan's group limit is reached.
    /// - `AppError::Conflict` when a group with the same name already exists.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        name: Label,
    ) -> Result<GroupId, AppError> {
        let request = CreateRequest {
            name,
            parent_id: None,
        };
        self.ports
            .create
            .execute(principal.caller(), auditor, request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::directory::{BindRefusal, BoundDirectory};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor,
    };
    use crate::use_cases::authorization::groups::CreatePorts;

    fn ports_over(directory: &BoundDirectory) -> CreatePorts {
        CreatePorts {
            group_store: directory.sources.groups.clone(),
            access_records: directory.access.clone(),
            tenant_authorities: directory.authorities(),
            ..CreatePorts::fakes()
        }
    }

    fn add(ports: CreatePorts, principal: &DirectoryPrincipal) -> Result<GroupId, AppError> {
        let use_case = AddDirectoryUseCase::new(AddDirectoryPorts {
            create: Arc::new(CreateUseCase::new(ports)),
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let name = Label::new("group_name", "Engineering").unwrap();
        block_on(use_case.execute(principal, &auditor, name))
    }

    /// Ann, an admin bound to the directory, adds the group "Engineering".
    /// The tenant has it.
    #[test]
    fn a_bound_admin_adds_a_group() {
        let directory = BoundDirectory::holding(SystemPermission::all());

        add(ports_over(&directory), &directory.bind()).unwrap();

        assert_eq!(directory.sources.groups.count(), 1);
    }

    /// An invalid bind or missing creation right prevents Ann from adding
    /// a group through LDAP.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_adds_no_group() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());

            let result = add(ports_over(&directory), &principal);

            assert!(refusal.refused(&result), "{refusal:?}");
            assert_eq!(directory.sources.groups.count(), 0, "{refusal:?}");
        }
    }

    /// At the tenant's group limit, Ann's LDAP addition is forbidden and
    /// leaves the group store empty.
    #[test]
    fn a_group_is_refused_at_the_tenants_group_limit() {
        let directory = BoundDirectory::holding(SystemPermission::all());
        let ports = CreatePorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports_over(&directory)
        };

        let result = add(ports, &directory.bind());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(directory.sources.groups.count(), 0);
    }
}
