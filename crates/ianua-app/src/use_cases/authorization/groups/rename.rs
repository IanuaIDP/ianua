//! Rename group: change a group's name within the tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{GroupId, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::GroupStore;
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::{ensure_group_name_free, existing_group};

/// The ports [`RenameUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenamePorts {
    /// Loads and saves groups.
    pub group_store: Arc<dyn GroupStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which group to rename, and its new name.
pub struct RenameRequest {
    /// The group to rename.
    pub group_id: GroupId,
    /// The name it takes, unique within the tenant.
    pub new_name: Label,
}

/// Renames a group of the caller's tenant.
pub struct RenameUseCase {
    ports: RenamePorts,
}

impl RenameUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenamePorts) -> Self {
        Self { ports }
    }
}

impl Command for RenameUseCase {
    type Caller = CallerContext;
    type Input = RenameRequest;
    type Output = Result<(), AppError>;

    /// Gives `request.group_id` the name `request.new_name`, for the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update roles, which
    ///   covers groups, checked before the group is looked up so a made-up
    ///   id is refused the same as a real one.
    /// - `AppError::NotFound` when the group does not exist.
    /// - `AppError::Conflict` when another group already has the name.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RenameRequest,
    ) -> Result<(), AppError> {
        let RenameRequest { group_id, new_name } = request;
        let tenant = ctx.tenant();
        let store = self.ports.group_store.as_ref();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .standing()
            .ensure_holds(SystemPermission::Roles(RoleAction::Update))
            .map_err(AppError::from_domain)?;
        let mut group = existing_group(store, &tenant, &group_id).await?;
        ensure_group_name_free(store, &tenant, &new_name, Some(&group_id)).await?;
        group
            .rename(new_name, &authority.standing())
            .map_err(AppError::from_domain)?;

        store.save(&tenant, &group).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), group.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeGroupStore, stored_group};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn name(value: &str) -> Label {
        Label::new("group_name", value).unwrap()
    }

    /// The tenant's groups, "Engineering" first.
    struct Groups {
        engineering: GroupId,
        store: Arc<FakeGroupStore>,
    }

    impl Groups {
        fn named(names: &[&str]) -> Self {
            let groups: Vec<_> = names
                .iter()
                .map(|name| stored_group(name, GroupPlace::TopLevel, Vec::new()))
                .collect();
            let engineering = *groups[0].id();
            Self {
                engineering,
                store: Arc::new(FakeGroupStore::holding(test_ctx().tenant_id(), groups)),
            }
        }

        fn ports(&self) -> RenamePorts {
            RenamePorts {
                group_store: self.store.clone(),
                ..RenamePorts::fakes()
            }
        }

        fn renaming_engineering(&self, to: &str) -> RenameRequest {
            RenameRequest {
                group_id: self.engineering,
                new_name: name(to),
            }
        }

        fn engineering_name(&self) -> String {
            let group = block_on(
                self.store
                    .find_by_id(&test_ctx().tenant(), &self.engineering),
            );
            group.unwrap().unwrap().name().as_str().to_owned()
        }
    }

    fn rename(
        ports: RenamePorts,
        sink: &Arc<FakeEventDispatcher>,
        request: RenameRequest,
    ) -> Result<(), AppError> {
        block_on(RenameUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    /// Ann renames "Engineering" to "Platform". It is saved under the new
    /// name and the rename is recorded.
    #[test]
    fn a_group_is_renamed_and_recorded() {
        let groups = Groups::named(&["Engineering"]);
        let sink = Arc::new(FakeEventDispatcher::new());

        rename(
            groups.ports(),
            &sink,
            groups.renaming_engineering("Platform"),
        )
        .unwrap();

        assert_eq!(groups.engineering_name(), "Platform");
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.group_renamed"]
        );
    }

    /// Ann renames a group the tenant does not have. It is not found.
    #[test]
    fn an_unknown_group_is_not_found() {
        let groups = Groups::named(&["Engineering"]);
        let request = RenameRequest {
            group_id: GroupId::new(),
            new_name: name("Platform"),
        };

        let result = rename(
            groups.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            request,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann renames "Engineering" to "Sales", another group's name. She is
    /// refused as a conflict and the name stays.
    #[test]
    fn a_name_another_group_has_is_a_conflict() {
        let groups = Groups::named(&["Engineering", "Sales"]);

        let result = rename(
            groups.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            groups.renaming_engineering("Sales"),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(groups.engineering_name(), "Engineering");
    }

    /// Ann renames "Engineering" to "Engineering". The group keeps its own
    /// name; that is no conflict.
    #[test]
    fn a_group_may_keep_its_own_name() {
        let groups = Groups::named(&["Engineering"]);

        let result = rename(
            groups.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            groups.renaming_engineering("Engineering"),
        );

        assert!(result.is_ok());
    }

    /// Without role update permission, renaming Engineering is forbidden
    /// and its name stays unchanged.
    #[test]
    fn a_caller_who_may_not_update_roles_is_refused() {
        let groups = Groups::named(&["Engineering"]);
        let ports = RenamePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..groups.ports()
        };

        let result = rename(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            groups.renaming_engineering("Interns"),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(groups.engineering_name(), "Engineering");
    }

    /// Renaming a group rejects a signed-out session as unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let groups = Groups::named(&["Engineering"]);
        let ports = RenamePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..groups.ports()
        };

        let result = rename(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            groups.renaming_engineering("Interns"),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
