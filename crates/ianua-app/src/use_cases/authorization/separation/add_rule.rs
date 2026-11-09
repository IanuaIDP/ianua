//! Add separation rule: name two roles nobody in the tenant may hold
//! together, such as raising payments and approving them.
//!
//! The rule holds for every grant from then on. People who hold both
//! already are not taken out; an access review finds them.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::separation::SeparationRule;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, RoleId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{RoleStore, SeparationRuleStore};
use crate::services::lookup::existing_role;
use crate::use_case::Command;

/// The ports [`AddRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddRulePorts {
    /// Saves the rule.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
    /// Loads the two roles.
    pub role_store: Arc<dyn RoleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// What the rule is called and which two roles it keeps apart.
pub struct AddRuleRequest {
    /// Its name, such as "raise or approve payments".
    pub name: Label,
    /// One of the roles.
    pub first: RoleId,
    /// The other.
    pub second: RoleId,
}

/// Adds a separation-of-duties rule to the caller's tenant.
pub struct AddRuleUseCase {
    ports: AddRulePorts,
}

impl AddRuleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AddRulePorts) -> Self {
        Self { ports }
    }
}

impl Command for AddRuleUseCase {
    type Caller = CallerContext;
    type Input = AddRuleRequest;
    type Output = Result<SeparationRule<ResolvedTenant>, AppError>;

    /// Saves the rule `request` names, for the caller, and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update roles, checked
    ///   before the roles are looked up so a made-up id is refused the same
    ///   as a real one.
    /// - `AppError::NotFound` when either role does not exist.
    /// - `AppError::Domain` when both are one role.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: AddRuleRequest,
    ) -> Result<SeparationRule<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Roles(RoleAction::Update))
            .map_err(AppError::from_domain)?;
        let roles = self.ports.role_store.as_ref();
        let first = existing_role(roles, &tenant, &request.first).await?;
        let second = existing_role(roles, &tenant, &request.second).await?;
        let mut rule = SeparationRule::declare(request.name, &first, &second, &authority)
            .map_err(AppError::from_domain)?;

        self.ports
            .separation_rules
            .save(&tenant, &rule)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), rule.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(rule)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeRoleStore, FakeSeparationRuleStore, stored_role};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A tenant with "raiser" and "approver".
    struct Tenant {
        raiser: RoleId,
        approver: RoleId,
        rules: Arc<FakeSeparationRuleStore>,
        ports: AddRulePorts,
    }

    fn tenant() -> Tenant {
        let raiser = stored_role("raiser", Vec::new(), Vec::new());
        let approver = stored_role("approver", Vec::new(), Vec::new());
        let (raiser_id, approver_id) = (*raiser.id(), *approver.id());
        let rules = Arc::new(FakeSeparationRuleStore::empty());
        Tenant {
            raiser: raiser_id,
            approver: approver_id,
            ports: AddRulePorts {
                separation_rules: rules.clone(),
                role_store: Arc::new(FakeRoleStore::holding(
                    test_ctx().tenant_id(),
                    [raiser, approver],
                )),
                ..AddRulePorts::fakes()
            },
            rules,
        }
    }

    fn apart(first: RoleId, second: RoleId) -> AddRuleRequest {
        AddRuleRequest {
            name: Label::new("rule_name", "raise or approve payments").unwrap(),
            first,
            second,
        }
    }

    fn add(
        ports: AddRulePorts,
        sink: &Arc<FakeEventDispatcher>,
        request: AddRuleRequest,
    ) -> Result<SeparationRule<ResolvedTenant>, AppError> {
        block_on(AddRuleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    /// Ann keeps raising and approving payments apart. The rule is saved
    /// and recorded.
    #[test]
    fn a_rule_is_added_and_recorded() {
        let tenant = tenant();
        let sink = Arc::new(FakeEventDispatcher::new());
        let request = apart(tenant.raiser, tenant.approver);

        add(tenant.ports, &sink, request).unwrap();

        assert_eq!(tenant.rules.count(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.separation_rule_added"]
        );
    }

    /// Ann keeps "raiser" apart from itself. That means nothing, so it is
    /// refused.
    #[test]
    fn a_role_is_not_kept_apart_from_itself() {
        let tenant = tenant();
        let request = apart(tenant.raiser, tenant.raiser);

        let result = add(tenant.ports, &Arc::new(FakeEventDispatcher::new()), request);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(tenant.rules.count(), 0);
    }

    /// Ann names a role the tenant does not have. It is not found.
    #[test]
    fn an_unknown_role_is_not_found() {
        let tenant = tenant();
        let request = apart(tenant.raiser, RoleId::new());

        let result = add(tenant.ports, &Arc::new(FakeEventDispatcher::new()), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Permission to view roles does not permit adding a separation rule.
    /// The refusal leaves the rule store and audit trail empty.
    #[test]
    fn a_caller_who_may_not_update_roles_is_refused() {
        let tenant = tenant();
        let sink = Arc::new(FakeEventDispatcher::new());
        let request = apart(tenant.raiser, tenant.approver);
        let ports = AddRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::View),
            ])),
            ..tenant.ports
        };

        let result = add(ports, &sink, request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.rules.count(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot add a separation rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = tenant();
        let request = apart(tenant.raiser, tenant.approver);
        let ports = AddRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports
        };

        let result = add(ports, &Arc::new(FakeEventDispatcher::new()), request);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
