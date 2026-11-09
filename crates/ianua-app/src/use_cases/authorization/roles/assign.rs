//! Assign role: give a role to a user of the tenant, for good or until a
//! time.
//!
//! A role given until a time counts for nothing from then on, whether or
//! not the sweep has cleared it yet. Given again, the hold that ran out is
//! cleared and its end recorded by the platform first, as the sweep would.
//! Nobody is given a role that, with what they hold, breaks one of the
//! tenant's separation-of-duties rules.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::holding::NewHolding;
use ianua_domain::domains::authorization::role::{Role, RoleAssignment, assignment_right};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{EventLabel, Expiry, PrincipalRef, RoleId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{
    AccessRecordStore, RoleAssignmentStore, RoleStore, SeparationRuleStore,
};
use crate::ports::shared::{AuditLabelResolver, UserExistenceChecker};
use crate::ports::workflows::ChangeGuard;
use crate::services::authorization::duties::{DutySources, Granting, ensure_duties_kept};
use crate::services::guarded::{AdminHolder, ensure_admin_rules_allow};
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::audit_labels::user_label;
use crate::use_cases::authorization::holdings::lapsed::{RanOut, role_cleared};

/// The ports [`AssignUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AssignPorts {
    /// Loads roles.
    pub role_store: Arc<dyn RoleStore>,
    /// Saves who holds which role.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// Says whether the user exists.
    pub user_checker: Arc<dyn UserExistenceChecker>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Names the user in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Reads who holds what, for the separation-of-duties check.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's separation-of-duties rules.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
    /// The company's "before" rules, asked before an admin role is given.
    pub guard: Arc<dyn ChangeGuard>,
}

/// Which role to give to which user, and until when.
pub struct AssignRequest {
    /// The user who receives the role.
    pub user_id: UserId,
    /// The role to give.
    pub role_id: RoleId,
    /// When it is taken away again, or that it is not.
    pub until: Expiry,
}

/// Gives a role to a user of the caller's tenant.
pub struct AssignUseCase {
    ports: AssignPorts,
}

impl AssignUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AssignPorts) -> Self {
        Self { ports }
    }

    /// The assignment `request` asks for, given by `authority` once they
    /// may give it, with the role and how the holder is named.
    async fn assignment(
        &self,
        tenant: &ScopedTenant,
        authority: &TenantAuthority,
        request: &AssignRequest,
    ) -> Result<Granted, AppError> {
        let principal = PrincipalRef::User(request.user_id);
        authority
            .standing()
            .ensure_holds(assignment_right(&principal))
            .map_err(AppError::from_domain)?;
        let role = existing_role(self.ports.role_store.as_ref(), tenant, &request.role_id).await?;
        let resolver = self.ports.audit_label_resolver.as_ref();
        let label = user_label(resolver, tenant, &request.user_id).await?;
        let holding = NewHolding {
            principal,
            label: label.clone(),
            until: request.until,
        };
        let assignment = RoleAssignment::assign_until(holding, &role, authority)
            .map_err(AppError::from_domain)?;
        Ok(Granted {
            assignment,
            role,
            label,
        })
    }

    /// Refuses giving `role` to `granted`'s holder when that leaves them with
    /// both roles of a separation-of-duties rule.
    async fn ensure_duties(
        &self,
        tenant: &ScopedTenant,
        granted: &Granted,
        role: &RoleId,
    ) -> Result<(), AppError> {
        let granting = Granting::Role {
            principal: *granted.assignment.principal(),
            role,
        };
        let duties = DutySources::of(
            self.ports.access_records.as_ref(),
            self.ports.separation_rules.as_ref(),
        );
        ensure_duties_kept(duties, tenant, granting).await
    }

    /// Asks the company's "before admin given" rules about `granted`.
    async fn ensure_rules_allow(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        granted: &Granted,
    ) -> Result<(), AppError> {
        let holder = AdminHolder::Principal(granted.assignment.principal());
        let guard = self.ports.guard.as_ref();
        ensure_admin_rules_allow(guard, tenant, auditor, &granted.role, holder).await
    }

    /// The record of the end of the holder's hold of the role that ran out
    /// and the sweep has not cleared, cleared now so the fresh grant does
    /// not replace it unrecorded.
    async fn ran_out(
        &self,
        tenant: &ScopedTenant,
        granted: &Granted,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let ran_out = RanOut {
            principal: granted.assignment.principal(),
            label: granted.label.clone(),
            now: clock::now(),
        };
        role_cleared(
            self.ports.assignment_store.as_ref(),
            tenant,
            &granted.role,
            ran_out,
        )
        .await
    }
}

/// An assignment about to be given, with its role and how its holder is
/// named.
struct Granted {
    assignment: RoleAssignment<ResolvedTenant>,
    role: Role<ResolvedTenant>,
    label: EventLabel,
}

impl Command for AssignUseCase {
    type Caller = CallerContext;
    type Input = AssignRequest;
    type Output = Result<(), AppError>;

    /// Gives `request.role_id` to `request.user_id` until `request.until`,
    /// granted by the caller.
    ///
    /// A user who already holds the role is left as they are, and the call
    /// succeeds without a record: they asked for a state that is already
    /// true. Every check still runs first, so asking again is no way to hand
    /// out what the caller could not.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without assignment rights, before reading the role.
    /// - `AppError::NotFound` for a missing role/user; `Forbidden` when the caller cannot grant all the role's rights.
    /// - `AppError::Domain` for an end not in the future; `Conflict` for a separation-of-duties violation.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: AssignRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut granted = self.assignment(&tenant, &authority, &request).await?;
        ensure_user_exists(self.ports.user_checker.as_ref(), &tenant, &request.user_id).await?;
        self.ensure_duties(&tenant, &granted, &request.role_id)
            .await?;
        let store = self.ports.assignment_store.as_ref();
        if already_held(store, &tenant, &granted.assignment).await? {
            return Ok(());
        }
        let ended = self.ran_out(&tenant, &granted).await?;
        self.ensure_rules_allow(&tenant, auditor, &granted).await?;
        store
            .save(&tenant, &granted.assignment)
            .await
            .or_internal()?;
        auditor.dispatch(&ended).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), granted.assignment.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// Refuses a user the tenant does not have.
async fn ensure_user_exists(
    checker: &dyn UserExistenceChecker,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<(), AppError> {
    if checker.user_exists(tenant, user_id).await.or_internal()? {
        return Ok(());
    }
    Err(AppError::NotFound(message!(
        "app-user-not-found",
        "user not found"
    )))
}

/// Whether the principal `assignment` names already holds its role.
async fn already_held(
    store: &dyn RoleAssignmentStore,
    tenant: &ScopedTenant,
    assignment: &RoleAssignment<ResolvedTenant>,
) -> Result<bool, AppError> {
    store
        .exists(tenant, assignment.principal(), assignment.role_id())
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole, Role};
    use ianua_domain::shared::clock;
    use ianua_domain::types::Label;
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeRoleAssignmentStore, FakeRoleStore,
        FakeSeparationRuleStore, separation_between, stored_assignment, stored_assignment_until,
    };
    use crate::test_support::{
        FakeAuditLabelResolver, FakeEventDispatcher, FakeUserChecker, block_on, test_auditor,
        test_ctx,
    };

    fn role(name: &str, system: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", name).unwrap(),
            system_permissions: system,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    /// A tenant with the role "editor", which grants nothing, and the ports
    /// to give it out.
    struct Tenant {
        role_id: RoleId,
        roles: Arc<FakeRoleStore>,
        assignments: Arc<FakeRoleAssignmentStore>,
    }

    impl Tenant {
        fn with(role: Role<ResolvedTenant>) -> Self {
            Self {
                role_id: *role.id(),
                roles: Arc::new(FakeRoleStore::holding(test_ctx().tenant_id(), [role])),
                assignments: Arc::new(FakeRoleAssignmentStore::empty()),
            }
        }

        fn with_editor() -> Self {
            Self::with(role("editor", Vec::new()))
        }

        fn ports(&self) -> AssignPorts {
            AssignPorts {
                role_store: self.roles.clone(),
                assignment_store: self.assignments.clone(),
                ..AssignPorts::fakes()
            }
        }

        fn request(&self, user_id: UserId) -> AssignRequest {
            AssignRequest {
                user_id,
                role_id: self.role_id,
                until: Expiry::Never,
            }
        }
    }

    fn assign(
        ports: AssignPorts,
        sink: &Arc<FakeEventDispatcher>,
        request: AssignRequest,
    ) -> Result<(), AppError> {
        block_on(AssignUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    /// Ann gives Bob "editor". He holds it, and the grant is recorded.
    #[test]
    fn a_role_is_given_and_recorded() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());

        assign(tenant.ports(), &sink, tenant.request(UserId::new())).unwrap();

        assert_eq!(tenant.assignments.count(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.role_assigned"]
        );
    }

    /// The record of Ann giving Bob "editor" names Bob and the role.
    #[test]
    fn the_record_names_the_holder_and_the_role() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());

        assign(tenant.ports(), &sink, tenant.request(UserId::new())).unwrap();

        let event = "authorization.role_assigned";
        assert_eq!(sink.label_of(event, "holder").as_deref(), Some("test user"));
        assert_eq!(sink.label_of(event, "role").as_deref(), Some("editor"));
    }

    /// Bob's user row cannot be named. The record names him by his id.
    #[test]
    fn the_record_falls_back_to_the_user_id_when_the_name_is_gone() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let bob = UserId::new();
        let ports = AssignPorts {
            audit_label_resolver: Arc::new(FakeAuditLabelResolver::missing()),
            ..tenant.ports()
        };

        assign(ports, &sink, tenant.request(bob)).unwrap();

        assert_eq!(
            sink.label_of("authorization.role_assigned", "holder"),
            Some(bob.to_string())
        );
    }

    /// Ann gives Bob a role the tenant does not have. It is not found.
    #[test]
    fn an_unknown_role_is_not_found() {
        let tenant = Tenant::with_editor();
        let request = AssignRequest {
            user_id: UserId::new(),
            role_id: RoleId::new(),
            until: Expiry::Never,
        };

        let result = assign(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            request,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann gives "editor" to a user the tenant does not have. It is not
    /// found and nothing is saved.
    #[test]
    fn an_unknown_user_is_not_found() {
        let tenant = Tenant::with_editor();
        let ports = AssignPorts {
            user_checker: Arc::new(FakeUserChecker::rejecting()),
            ..tenant.ports()
        };

        let result = assign(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(UserId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.assignments.count(), 0);
    }

    /// Ann gives Bob "editor" twice. The second time succeeds and changes
    /// nothing: he holds it once, and only the first grant is recorded.
    #[test]
    fn giving_a_role_already_held_succeeds_and_changes_nothing() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let bob = UserId::new();
        assign(tenant.ports(), &sink, tenant.request(bob)).unwrap();

        let again = assign(tenant.ports(), &sink, tenant.request(bob));

        assert!(again.is_ok());
        assert_eq!(tenant.assignments.count(), 1);
        assert_eq!(sink.records.lock().unwrap().len(), 1);
    }

    /// Bob's expired editor assignment has not been swept. Granting it
    /// again leaves one active assignment and records expiry before the
    /// new grant.
    #[test]
    fn a_role_that_ran_out_is_given_again() {
        let tenant = Tenant::with_editor();
        let bob = UserId::new();
        let ran_out = stored_assignment_until(
            PrincipalRef::User(bob),
            tenant.role_id,
            Expiry::At(clock::now() - Duration::days(1)),
        );
        let tenant = Tenant {
            assignments: Arc::new(FakeRoleAssignmentStore::holding(
                test_ctx().tenant_id(),
                [ran_out],
            )),
            ..tenant
        };
        let sink = Arc::new(FakeEventDispatcher::new());

        assign(tenant.ports(), &sink, tenant.request(bob)).unwrap();

        let held = holds_role(&tenant, bob);
        assert!(held);
        assert_eq!(tenant.assignments.count(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "authorization.role_assignment_expired",
                "authorization.role_assigned"
            ]
        );
    }

    /// Reads Bob's assignment through the same port used to grant it.
    fn holds_role(tenant: &Tenant, bob: UserId) -> bool {
        block_on(tenant.ports().assignment_store.exists(
            &test_ctx().tenant(),
            &PrincipalRef::User(bob),
            &tenant.role_id,
        ))
        .unwrap()
    }

    /// Bob already holds admin, but granting it again still requires its
    /// user-management permission. Sam's user-update permission is not
    /// enough, so his repeat request is forbidden.
    #[test]
    fn giving_again_still_refuses_a_role_the_caller_cannot_hand_out() {
        let tenant = Tenant::with(role("admin", vec![SystemPermission::ManageUsers]));
        let sink = Arc::new(FakeEventDispatcher::new());
        let bob = UserId::new();
        assign(tenant.ports(), &sink, tenant.request(bob)).unwrap();
        let sam = AssignPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..tenant.ports()
        };

        let result = assign(sam, &sink, tenant.request(bob));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A refused grant leaves no record behind.
    #[test]
    fn a_refused_grant_is_not_recorded() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let request = AssignRequest {
            user_id: UserId::new(),
            role_id: RoleId::new(),
            until: Expiry::Never,
        };

        let _ = assign(tenant.ports(), &sink, request);

        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann gives Bob "editor" until tomorrow, for a fortnight's cover cut
    /// short. The assignment is saved with its end, and the record says
    /// when it ends.
    #[test]
    fn a_role_is_given_until_a_time() {
        let tenant = Tenant::with_editor();
        let sink = Arc::new(FakeEventDispatcher::new());
        let tomorrow = clock::now() + Duration::days(1);
        let request = AssignRequest {
            until: Expiry::At(tomorrow),
            ..tenant.request(UserId::new())
        };

        assign(tenant.ports(), &sink, request).unwrap();

        let held = tenant
            .assignments
            .of_tenant(test_ctx().tenant_id())
            .unwrap();
        assert_eq!(held[0].expires(), Expiry::At(tomorrow));
        assert!(
            sink.payload_of("authorization.role_assigned")
                .get("expires_at")
                .is_some()
        );
    }

    /// Ann gives Bob "editor" until an hour ago. A grant that ends before
    /// it begins would record access nobody had, so it is refused and
    /// nothing is saved.
    #[test]
    fn a_role_ending_in_the_past_is_refused() {
        let tenant = Tenant::with_editor();
        let request = AssignRequest {
            until: Expiry::At(clock::now() - Duration::hours(1)),
            ..tenant.request(UserId::new())
        };

        let result = assign(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            request,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(tenant.assignments.count(), 0);
    }

    /// The tenant separates payment raisers from approvers. Bob already
    /// holds raiser, so granting approver conflicts without saving an
    /// assignment or recording a grant.
    #[test]
    fn a_role_breaking_a_separation_of_duties_is_refused() {
        let raiser = role("raiser", Vec::new());
        let approver = role("approver", Vec::new());
        let bob = UserId::new();
        let tenant_id = test_ctx().tenant_id();
        let rule = separation_between("raise or approve payments", &raiser, &approver);
        let held = stored_assignment(PrincipalRef::User(bob), *raiser.id());
        let sources = AccessSources {
            roles: Arc::new(FakeRoleStore::holding(tenant_id, [raiser])),
            assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant_id, [held])),
            ..AccessSources::default()
        };
        let tenant = Tenant::with(approver);
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = AssignPorts {
            access_records: Arc::new(FakeAccessRecordStore::reading(sources)),
            separation_rules: Arc::new(FakeSeparationRuleStore::holding(tenant_id, [rule])),
            ..tenant.ports()
        };

        let result = assign(ports, &sink, tenant.request(bob));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.assignments.count(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Granting editor without user-update permission is forbidden and
    /// leaves the assignment store empty.
    #[test]
    fn a_caller_who_may_not_update_users_is_refused() {
        let tenant = Tenant::with_editor();
        let ports = AssignPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };

        let result = assign(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(UserId::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.assignments.count(), 0);
    }

    /// A caller lacking user-update permission receives forbidden even
    /// when the requested role does not exist.
    #[test]
    fn a_caller_who_may_not_update_users_is_refused_for_an_unknown_role_too() {
        let tenant = Tenant::with_editor();
        let ports = AssignPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };
        let request = AssignRequest {
            role_id: RoleId::new(),
            ..tenant.request(UserId::new())
        };

        let result = assign(ports, &Arc::new(FakeEventDispatcher::new()), request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Signed-out authority cannot grant a role. The result is
    /// unauthenticated and the assignment store remains empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::with_editor();
        let ports = AssignPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = assign(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(UserId::new()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.assignments.count(), 0);
    }

    /// Ann's company rule refuses every admin role. Tess gives Bob "admin":
    /// it is refused and he holds nothing.
    #[test]
    fn a_company_rule_refusing_stops_an_admin_role() {
        let tenant = Tenant::with(role("admin", vec![SystemPermission::ManageUsers]));
        let ports = AssignPorts {
            guard: Arc::new(crate::test_support::workflows::RefusingGuard),
            ..tenant.ports()
        };

        let result = assign(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(UserId::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.assignments.count(), 0);
    }

    /// The same rule is not asked about "editor", which does no admin work:
    /// Bob is given it.
    #[test]
    fn a_role_doing_no_admin_work_is_not_asked_about() {
        let tenant = Tenant::with_editor();
        let ports = AssignPorts {
            guard: Arc::new(crate::test_support::workflows::RefusingGuard),
            ..tenant.ports()
        };

        assign(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            tenant.request(UserId::new()),
        )
        .unwrap();

        assert_eq!(tenant.assignments.count(), 1);
    }
}
