//! What an identity provider or a directory hands out with nobody choosing
//! each person: the role a sign-in connection or a SCIM endpoint gives the
//! accounts it makes, and the roles and groups a connection's group mapping
//! brings.
//!
//! Each is held to the tenant's separation of duties like any other grant.
//! Nobody asked for it, so one that would break a rule is not turned into
//! an error the person signing in, or the directory syncing, could act on:
//! it is left out with a warning for the admins who set up the rule and the
//! provider, and the sign-in or sync goes on without it. Leaving it out
//! grants less, never more.

use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{PrincipalRef, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{RoleAssignmentStore, RoleStore};
use crate::services::authorization::duties::{DutySources, Granting, ensure_duties_kept};
use crate::services::authorization::starting_roles::{self, RoleStores};
use crate::tenancy::ScopedTenant;

/// Where the roles a new account starts with are read and given, and the
/// tenant's separation of duties they are held to.
#[derive(Clone, Copy)]
pub(crate) struct ProviderRoleStores<'a> {
    /// Reads the default roles.
    pub(crate) role_store: &'a dyn RoleStore,
    /// Records the grants.
    pub(crate) assignment_store: &'a dyn RoleAssignmentStore,
    /// The rules and records separation of duties is checked against.
    pub(crate) duties: DutySources<'a>,
}

/// Gives `user_id`, an account a provider or a directory just made, the
/// tenant's default roles, then each of `given`, the provider's role for
/// new accounts. A provider role the account holds already as a default is
/// given once; one that would break the tenant's separation of duties
/// alongside the defaults is left out.
///
/// # Errors
///
/// - `AppError::Internal` when a provider role was made for another
///   account, or a grant, a default, a rule or a record cannot be read or
///   saved.
pub(crate) async fn grant_starting_roles(
    stores: ProviderRoleStores<'_>,
    tenant: &ScopedTenant,
    user_id: UserId,
    given: Vec<RoleAssignment<ResolvedTenant>>,
) -> Result<(), AppError> {
    let defaults = RoleStores {
        role_store: stores.role_store,
        assignment_store: stores.assignment_store,
    };
    starting_roles::grant(defaults, tenant, user_id, Vec::new()).await?;
    for assignment in given {
        provider_role_given(stores, tenant, user_id, assignment).await?;
    }
    Ok(())
}

/// Whether the tenant's separation of duties lets `granting` go out. One
/// that would break a rule is left out with a warning naming the rule.
///
/// # Errors
///
/// - `AppError::Internal` when the rules or the records cannot be read.
pub(crate) async fn duties_allow(
    duties: DutySources<'_>,
    tenant: &ScopedTenant,
    granting: Granting<'_>,
) -> Result<bool, AppError> {
    match ensure_duties_kept(duties, tenant, granting).await {
        Ok(()) => Ok(true),
        Err(AppError::Conflict(rule)) => {
            tracing::warn!(
                %rule,
                "a grant from a provider would break a separation of duties and was left out"
            );
            Ok(false)
        }
        Err(failed) => Err(failed),
    }
}

/// Saves `assignment`, a provider's role for `user_id`, unless they hold
/// the role already or the tenant's separation of duties forbids it.
async fn provider_role_given(
    stores: ProviderRoleStores<'_>,
    tenant: &ScopedTenant,
    user_id: UserId,
    assignment: RoleAssignment<ResolvedTenant>,
) -> Result<(), AppError> {
    let principal = PrincipalRef::User(user_id);
    if *assignment.principal() != principal {
        return Err(AppError::internal_msg(
            "a provider's role was made for another account",
        ));
    }
    let store = stores.assignment_store;
    let held = store
        .exists(tenant, &principal, assignment.role_id())
        .await
        .or_internal()?;
    if held {
        return Ok(());
    }
    ensure_nothing_ran_out(store, tenant, &assignment).await?;
    let granting = Granting::Role {
        principal,
        role: assignment.role_id(),
    };
    if !duties_allow(stores.duties, tenant, granting).await? {
        return Ok(());
    }
    store.save(tenant, &assignment).await.or_internal()
}

/// Refuses giving `assignment` to an account a provider or a directory just
/// made when the account already holds the role, run out.
///
/// Both callers make the account with a fresh id a moment before, so it
/// can hold nothing earlier. A hold of the role that ran out would mean the
/// records do not fit together, and saving over it would replace it with
/// its end never recorded, so the grant is refused instead of made.
///
/// # Errors
///
/// - `AppError::Internal` when the holds cannot be read, or the account
///   holds the role run out.
async fn ensure_nothing_ran_out(
    store: &dyn RoleAssignmentStore,
    tenant: &ScopedTenant,
    assignment: &RoleAssignment<ResolvedTenant>,
) -> Result<(), AppError> {
    let held = store
        .find_by_principal(tenant, assignment.principal())
        .await
        .or_internal()?;
    if held
        .iter()
        .any(|held| held.role_id() == assignment.role_id())
    {
        return Err(AppError::internal_msg(
            "an account just made already held the role it is given, run out",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole, Role};
    use ianua_domain::domains::federation::scim::{
        ScimActivation, ScimEndpoint, ScimEndpointRow, ScimRemoval,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Enablement, Expiry, Label, RoleId, Setting, TokenHash};

    use super::*;
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeRoleAssignmentStore, FakeRoleStore,
        FakeSeparationRuleStore, separation_between, stored_assignment_until,
    };
    use crate::test_support::{block_on, test_ctx};

    fn role(name: &str, assignment: DefaultAssignment) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("name", name).unwrap(),
            system_permissions: Vec::new(),
            custom_permissions: Vec::new(),
            assignment,
        })
    }

    /// Acme's directory, giving the accounts it makes `role`.
    fn directory_giving(role: &Role<ResolvedTenant>) -> ScimEndpoint<ResolvedTenant> {
        ScimEndpoint::reconstitute(ScimEndpointRow {
            bearer_token_hash: TokenHash::from_stored("scim".to_owned()),
            enabled: Enablement::Enabled,
            default_role_id: Setting::Set(*role.id()),
            auto_activate: ScimActivation::Immediate,
            deactivate_on_remove: ScimRemoval::Deactivate,
            last_sync_at: None,
            created_at: clock::now(),
        })
        .unwrap()
    }

    struct Harness {
        sources: AccessSources,
        records: FakeAccessRecordStore,
        rules: FakeSeparationRuleStore,
    }

    /// Acme, holding `roles`, with the rule that nobody both requests and
    /// approves payments.
    fn acme(
        roles: &[Role<ResolvedTenant>],
        requester: &Role<ResolvedTenant>,
        approver: &Role<ResolvedTenant>,
    ) -> Harness {
        let tenant = test_ctx().tenant_id();
        let sources = AccessSources {
            roles: Arc::new(FakeRoleStore::holding(tenant, roles.to_vec())),
            assignments: Arc::new(FakeRoleAssignmentStore::empty()),
            ..AccessSources::default()
        };
        let rule = separation_between("payments", requester, approver);
        Harness {
            records: FakeAccessRecordStore::reading(sources.clone()),
            rules: FakeSeparationRuleStore::holding(tenant, [rule]),
            sources,
        }
    }

    /// A new account the directory makes, given the tenant's defaults and
    /// `role`, the directory's role for new accounts.
    fn start(h: &Harness, role: &Role<ResolvedTenant>) -> UserId {
        let user = UserId::new();
        let given = directory_giving(role)
            .default_assignment(user, role)
            .unwrap();
        let stores = ProviderRoleStores {
            role_store: h.sources.roles.as_ref(),
            assignment_store: h.sources.assignments.as_ref(),
            duties: DutySources::of(&h.records, &h.rules),
        };
        let tenant = test_ctx().tenant();
        block_on(grant_starting_roles(stores, &tenant, user, vec![given])).unwrap();
        user
    }

    fn holds(h: &Harness, user: UserId, role: &Role<ResolvedTenant>) -> bool {
        let tenant = test_ctx().tenant();
        let holder = PrincipalRef::User(user);
        block_on(h.sources.assignments.exists(&tenant, &holder, role.id())).unwrap()
    }

    /// A directory's Approver grant is omitted when it conflicts with the
    /// default Requester role, which the new account still receives.
    #[test]
    fn a_provider_role_that_breaks_a_separation_is_left_out() {
        let requester = role("Requester", DefaultAssignment::NewUsers);
        let approver = role("Approver", DefaultAssignment::Manual);
        let h = acme(
            &[requester.clone(), approver.clone()],
            &requester,
            &approver,
        );

        let ann = start(&h, &approver);

        assert!(holds(&h, ann, &requester));
        assert!(!holds(&h, ann, &approver));
    }

    /// An expired Viewer assignment on a new account makes the provider grant
    /// fail internally; the account gains no active Viewer assignment.
    #[test]
    fn a_role_run_out_on_an_account_just_made_is_not_saved_over() {
        let requester = role("Requester", DefaultAssignment::NewUsers);
        let approver = role("Approver", DefaultAssignment::Manual);
        let viewer = role("Viewer", DefaultAssignment::Manual);
        let all = [requester.clone(), approver.clone(), viewer.clone()];
        let h = acme(&all, &requester, &approver);
        let user = UserId::new();
        let ran_out = stored_assignment_until(
            PrincipalRef::User(user),
            *viewer.id(),
            Expiry::At(clock::now() - time::Duration::days(1)),
        );
        let tenant = test_ctx().tenant();
        block_on(h.sources.assignments.save(&tenant, &ran_out)).unwrap();
        let given = directory_giving(&viewer)
            .default_assignment(user, &viewer)
            .unwrap();
        let stores = ProviderRoleStores {
            role_store: h.sources.roles.as_ref(),
            assignment_store: h.sources.assignments.as_ref(),
            duties: DutySources::of(&h.records, &h.rules),
        };

        let result = block_on(grant_starting_roles(stores, &tenant, user, vec![given]));

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert!(!holds(&h, user, &viewer));
    }

    /// Acme's directory gives the accounts it makes the Viewer role, which
    /// no rule keeps apart from Requester. Ann gets both.
    #[test]
    fn a_provider_role_within_the_rules_is_given() {
        let requester = role("Requester", DefaultAssignment::NewUsers);
        let approver = role("Approver", DefaultAssignment::Manual);
        let viewer = role("Viewer", DefaultAssignment::Manual);
        let all = [requester.clone(), approver.clone(), viewer.clone()];
        let h = acme(&all, &requester, &approver);

        let ann = start(&h, &viewer);

        assert!(holds(&h, ann, &requester));
        assert!(holds(&h, ann, &viewer));
    }
}
