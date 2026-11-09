//! Revoke role: take a role back from a user of the tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::role::{RoleAssignment, assignment_right};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{PrincipalRef, RoleId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::{AccessRecordStore, RoleAssignmentStore, RoleStore};
use crate::ports::shared::AuditLabelResolver;
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::audit_labels::user_label;
use crate::use_cases::authorization::stewardship::{Lost, ensure_administered_after_losing};

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// Loads and removes who holds which role.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// Loads the role taken back.
    pub role_store: Arc<dyn RoleStore>,
    /// Reads the user's own records and the tenant's count of
    /// administrators, to keep one.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Names the user in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
}

/// Which role to take from which user.
pub struct RevokeRequest {
    /// The user who loses the role.
    pub user_id: UserId,
    /// The role to take back.
    pub role_id: RoleId,
}

/// Takes a role back from a user of the caller's tenant.
pub struct RevokeUseCase {
    ports: RevokePorts,
}

impl RevokeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokePorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeUseCase {
    type Caller = CallerContext;
    type Input = RevokeRequest;
    type Output = Result<(), AppError>;

    /// Takes `request.role_id` from `request.user_id`, for the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without assignment rights, before reading the role.
    /// - `AppError::NotFound` for a missing role/assignment; `Forbidden` when the caller could not grant all its rights.
    /// - `AppError::Conflict` when revocation removes the last administrator; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RevokeRequest,
    ) -> Result<(), AppError> {
        let RevokeRequest { user_id, role_id } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let revocation = Revocation { user_id, role_id };
        let mut assignment = revoked(&self.ports, &tenant, &authority, &revocation).await?;

        self.ports
            .assignment_store
            .delete(&tenant, &revocation.holder(), &role_id)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), assignment.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// A role to take from one user.
struct Revocation {
    /// Who loses the role.
    user_id: UserId,
    /// The role they lose.
    role_id: RoleId,
}

impl Revocation {
    /// The user who loses the role, as a holder of roles.
    fn holder(&self) -> PrincipalRef {
        PrincipalRef::User(self.user_id)
    }
}

/// Refuses `revocation` when it leaves the tenant nobody can administer,
/// read from the user's own records and the tenant's count.
async fn ensure_administered_without(
    store: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    revocation: &Revocation,
) -> Result<(), AppError> {
    let losing = [revocation.holder()];
    let lost = Lost::Role(&revocation.role_id);
    ensure_administered_after_losing(store, tenant, &losing, lost).await
}

/// The assignment `revocation` takes away, taken back by `authority` once
/// they may and the tenant keeps an administrator without it.
async fn revoked(
    ports: &RevokePorts,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
    revocation: &Revocation,
) -> Result<RoleAssignment<ResolvedTenant>, AppError> {
    authority
        .standing()
        .ensure_holds(assignment_right(&revocation.holder()))
        .map_err(AppError::from_domain)?;
    let mut assignment = held(ports.assignment_store.as_ref(), tenant, revocation).await?;
    let role = existing_role(ports.role_store.as_ref(), tenant, &revocation.role_id).await?;
    let holder = user_label(
        ports.audit_label_resolver.as_ref(),
        tenant,
        &revocation.user_id,
    )
    .await?;
    assignment
        .revoke(&role, &authority.standing(), holder)
        .map_err(AppError::from_domain)?;
    ensure_administered_without(ports.access_records.as_ref(), tenant, revocation).await?;
    Ok(assignment)
}

/// The assignment `revocation` takes away.
async fn held(
    store: &dyn RoleAssignmentStore,
    tenant: &ScopedTenant,
    revocation: &Revocation,
) -> Result<RoleAssignment<ResolvedTenant>, AppError> {
    store
        .find_by_principal(tenant, &revocation.holder())
        .await
        .or_internal()?
        .into_iter()
        .find(|assignment| *assignment.role_id() == revocation.role_id)
        .or_not_found(message!(
            "authorization-user-does-not-hold-this-role",
            "user does not hold this role"
        ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::role::{
        DefaultAssignment, NewRole, Role, RoleAssignmentRow,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::{ActorRef, Expiry, Label};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeRoleAssignmentStore, FakeRoleStore,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn role(name: &str, system: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", name).unwrap(),
            system_permissions: system,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn admin_role() -> Role<ResolvedTenant> {
        role(
            "admin",
            vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
        )
    }

    fn given(user: UserId, role_id: RoleId) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::reconstitute(RoleAssignmentRow {
            principal: PrincipalRef::User(user),
            role_id,
            assigned_by: ActorRef::System,
            assigned_at: clock::now(),
            expires: Expiry::Never,
        })
        .unwrap()
    }

    /// A tenant whose only role is held by the users it names.
    struct Tenant {
        role_id: RoleId,
        stores: AccessSources,
    }

    impl Tenant {
        fn where_role_is_held_by(role: Role<ResolvedTenant>, holders: &[UserId]) -> Self {
            let tenant = test_ctx().tenant_id();
            let role_id = *role.id();
            Self {
                role_id,
                stores: AccessSources {
                    roles: Arc::new(FakeRoleStore::holding(tenant, [role])),
                    assignments: Arc::new(FakeRoleAssignmentStore::holding(
                        tenant,
                        holders.iter().map(|user| given(*user, role_id)),
                    )),
                    ..AccessSources::default()
                },
            }
        }

        fn ports(&self) -> RevokePorts {
            RevokePorts {
                assignment_store: self.stores.assignments.clone(),
                role_store: self.stores.roles.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.stores.clone())),
                ..RevokePorts::fakes()
            }
        }

        fn request(&self, user_id: UserId) -> RevokeRequest {
            RevokeRequest {
                user_id,
                role_id: self.role_id,
            }
        }
    }

    fn revoke(
        ports: RevokePorts,
        sink: &Arc<FakeEventDispatcher>,
        request: RevokeRequest,
    ) -> Result<(), AppError> {
        block_on(RevokeUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    /// Ann takes "editor" back from Bob. He no longer holds it, and the
    /// record names him and the role.
    #[test]
    fn a_role_is_taken_back_and_recorded() {
        let bob = UserId::new();
        let tenant = Tenant::where_role_is_held_by(role("editor", Vec::new()), &[bob]);
        let sink = Arc::new(FakeEventDispatcher::new());

        revoke(tenant.ports(), &sink, tenant.request(bob)).unwrap();

        let event = "authorization.role_revoked";
        assert_eq!(tenant.stores.assignments.count(), 0);
        assert_eq!(sink.records.lock().unwrap().as_slice(), [event]);
        assert_eq!(sink.label_of(event, "holder").as_deref(), Some("test user"));
        assert_eq!(sink.label_of(event, "role").as_deref(), Some("editor"));
    }

    /// Ann takes "admin" from Bob while Carol still administers the tenant.
    /// It goes through.
    #[test]
    fn an_administrator_may_lose_the_role_while_another_remains() {
        let (bob, carol) = (UserId::new(), UserId::new());
        let tenant = Tenant::where_role_is_held_by(admin_role(), &[bob, carol]);

        revoke(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(bob),
        )
        .unwrap();

        assert_eq!(tenant.stores.assignments.count(), 1);
    }

    /// Ann takes "admin" from Bob while Carol still administers the tenant.
    /// Whether an administrator stays is worked out from Bob's own records
    /// and the tenant's count, never from every record of the tenant.
    #[test]
    fn taking_a_role_reads_only_the_holders_records() {
        let (bob, carol) = (UserId::new(), UserId::new());
        let tenant = Tenant::where_role_is_held_by(admin_role(), &[bob, carol]);
        let records = Arc::new(FakeAccessRecordStore::reading(tenant.stores.clone()));
        let ports = RevokePorts {
            access_records: records.clone(),
            ..tenant.ports()
        };

        revoke(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(bob),
        )
        .unwrap();

        assert_eq!(records.whole_reads(), 0);
    }

    /// Ann is the only administrator. Revoking her role conflicts, keeps
    /// her assignment and records no revocation.
    #[test]
    fn the_last_administrator_keeps_the_role() {
        let ann = UserId::new();
        let tenant = Tenant::where_role_is_held_by(admin_role(), &[ann]);
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = revoke(tenant.ports(), &sink, tenant.request(ann));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.stores.assignments.count(), 1);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann takes "editor" from Bob, who does not hold it. It is not found.
    #[test]
    fn a_role_not_held_is_not_found() {
        let tenant = Tenant::where_role_is_held_by(role("editor", Vec::new()), &[]);

        let result = revoke(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(UserId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A refused revocation leaves no record behind.
    #[test]
    fn a_refused_revocation_is_not_recorded() {
        let tenant = Tenant::where_role_is_held_by(role("editor", Vec::new()), &[]);
        let sink = Arc::new(FakeEventDispatcher::new());

        let _ = revoke(tenant.ports(), &sink, tenant.request(UserId::new()));

        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// User-update permission alone cannot revoke an admin role that grants
    /// user management. The request is forbidden and both assignments remain.
    #[test]
    fn a_caller_cannot_take_back_a_role_they_could_not_have_given() {
        let (ann, carol) = (UserId::new(), UserId::new());
        let tenant = Tenant::where_role_is_held_by(admin_role(), &[ann, carol]);
        let sam = RevokePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..tenant.ports()
        };

        let result = revoke(
            sam,
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(ann),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.stores.assignments.count(), 2);
    }

    /// Without permission to update users, Mallory cannot revoke Bob's
    /// editor role. The request is forbidden and his assignment remains.
    #[test]
    fn a_caller_who_may_not_update_users_is_refused() {
        let bob = UserId::new();
        let tenant = Tenant::where_role_is_held_by(role("editor", Vec::new()), &[bob]);
        let ports = RevokePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };

        let result = revoke(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(bob),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.stores.assignments.count(), 1);
    }

    /// An unknown role still returns forbidden when the caller lacks
    /// user-update permission, rather than revealing that it is missing.
    #[test]
    fn a_caller_who_may_not_update_users_is_refused_for_an_unknown_role_too() {
        let bob = UserId::new();
        let tenant = Tenant::where_role_is_held_by(role("editor", Vec::new()), &[bob]);
        let ports = RevokePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };
        let request = RevokeRequest {
            user_id: bob,
            role_id: RoleId::new(),
        };

        let result = revoke(ports, &Arc::new(FakeEventDispatcher::new()), request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Revoking Bob's role with signed-out authority returns unauthenticated
    /// and preserves his assignment.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bob = UserId::new();
        let tenant = Tenant::where_role_is_held_by(role("editor", Vec::new()), &[bob]);
        let ports = RevokePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = revoke(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(bob),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.stores.assignments.count(), 1);
    }
}
