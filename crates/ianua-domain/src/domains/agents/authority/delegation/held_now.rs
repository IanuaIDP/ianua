//! What the person behind a delegation holds now, worked out from the
//! tenant's records for whoever checks the delegation later, such as the
//! worker.
//!
//! A delegation keeps a copy of what it was given. Ann loses "view reports"
//! on Monday. Her agent's delegation still lists it, and only what Ann holds
//! now says it no longer stands. That answer is never the caller's word: if
//! the worker wrote it, one slip would keep every delegation alive.

use crate::domains::agents::authority::capability::CapabilitySet;
use crate::domains::agents::authority::delegation::held_by::{
    HeldResources, ceiling_from, ensure_answered_for,
};
use crate::domains::agents::execution::tool::AgentTool;
use crate::domains::authorization::authority::TenantAccess;
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::organization::members::account_now::AccountNow;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::PrincipalRef;

/// What a delegation's delegator holds now, named together with them.
///
/// Its fields are private. Only [`HeldNow::worked_out`] makes one, from the
/// tenant's records, so it always names the delegator it was worked out
/// for.
#[derive(Debug, Clone)]
pub struct HeldNow {
    holder: PrincipalRef,
    caps: CapabilitySet,
}

impl HeldNow {
    /// What `delegator` currently holds in the tenant, restricted to `wanted`.
    /// Use the current grant to check liveness or its proposed expansion to widen it.
    /// Tenant roles or organization membership determine standing rights; break-glass
    /// adds nothing. Uses [`HeldBy::worked_out`](crate::domains::agents::authority::delegation::HeldBy::worked_out).
    /// Agent-issued delegations instead use [`Delegation::live_under`](crate::domains::agents::authority::delegation::Delegation::live_under).
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another person's holdings or an account unable to act.
    /// Also propagates missing role/group errors from
    /// [`TenantGrants::administrators`](crate::domains::authorization::stewardship::TenantGrants::administrators).
    pub fn worked_out<T: TenantScope>(
        access: &TenantAccess<'_, T>,
        delegator: &AccountNow<'_, T>,
        wanted: &CapabilitySet,
        held: &HeldResources,
        registry: &[AgentTool<T>],
    ) -> Result<Self, DomainError> {
        let holder = delegator.principal();
        ensure_answered_for(held, &holder)?;
        let standing = delegator.standing_in(access)?;
        let granter = HeldByGranter::new(standing.system(), &[]);
        Ok(Self {
            holder,
            caps: ceiling_from(granter, wanted, held, registry),
        })
    }

    /// Who holds them: the delegator.
    #[must_use]
    pub fn holder(&self) -> PrincipalRef {
        self.holder
    }

    /// What they hold now.
    #[must_use]
    pub fn caps(&self) -> &CapabilitySet {
        &self.caps
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::DelegationConstraints;
    use crate::domains::agents::authority::delegation::{
        Delegate, Delegation, GrantDelegationParams, HeldBy, ReviewDuty,
    };
    use crate::domains::agents::identity::agent::tests::fixtures::{agent_of, ann, sam};
    use crate::domains::agents::identity::control::AgentControl;
    use crate::domains::authorization::permission::{RoutingAction, SystemPermission};
    use crate::domains::consumers::fixtures::{ConsumerRecords, acme};
    use crate::domains::identity::account::user::User;
    use crate::domains::identity::account::user::tests::control_over;
    use crate::domains::organization::access::session::tests::acme_with;
    use crate::domains::organization::members::account_now::MemberNow;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::builders::user;
    use crate::types::{Human, HumanAccount, PersonKey, Seconds, TenantId};

    const VIEW_ROUTES: SystemPermission = SystemPermission::Routing(RoutingAction::View);

    /// The active tenant account `person` signs in with.
    pub(crate) fn account_of(person: &Human) -> User<ResolvedTenant> {
        let HumanAccount::User(id) = person.account() else {
            unreachable!("the test people sign in with tenant accounts")
        };
        let mut account = user(id, person.person().as_str());
        account.activate(&control_over(&account)).unwrap();
        account
    }

    /// `person`, holding "view routes", gives their agent "view routes".
    fn granted_by(person: &Human) -> Delegation<ResolvedTenant> {
        let wanted = CapabilitySet::new(vec![VIEW_ROUTES], Vec::new());
        let control = AgentControl::new(assumed_authority(
            person,
            TenantId::new(),
            &[VIEW_ROUTES],
            &[],
        ));
        let held = HeldBy::worked_out::<ResolvedTenant>(
            &control,
            &wanted,
            &HeldResources::answered(person.principal(), Vec::new()),
            &[],
        )
        .unwrap();
        Delegation::grant(
            GrantDelegationParams {
                granted: wanted,
                constraints: DelegationConstraints::new(Seconds::new(600), 1).unwrap(),
                name: None,
            },
            &held,
            &Delegate {
                agent: &agent_of(person),
                duty: ReviewDuty::NotReviewing,
            },
        )
        .unwrap()
    }

    /// What the tenant's records say `ann` holds now through `account`, when
    /// her roles give `system`, for `delegation`.
    fn now_holding(
        ann: &Human,
        account: &User<ResolvedTenant>,
        system: &[SystemPermission],
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<HeldNow, DomainError> {
        let records = ConsumerRecords::where_holding(ann.principal(), system);
        HeldNow::worked_out(
            &records.access(),
            &AccountNow::User(account),
            delegation.granted(),
            &HeldResources::answered(ann.principal(), Vec::new()),
            &[],
        )
    }

    /// A route-viewing delegation remains allowed while its delegator's
    /// current role grants that right, and becomes disallowed without it.
    #[test]
    fn a_delegation_follows_what_the_records_say_its_delegator_holds_now() {
        let ann = ann();
        let account = account_of(&ann);
        let delegation = granted_by(&ann);
        let still_holding = now_holding(&ann, &account, &[VIEW_ROUTES], &delegation).unwrap();
        let lost_it = now_holding(&ann, &account, &[], &delegation).unwrap();

        assert!(delegation.still_allowed(&still_holding));
        assert!(!delegation.still_allowed(&lost_it));
    }

    /// Current holdings cannot be established for a deactivated delegator,
    /// even when the tenant's records still grant route-viewing rights.
    #[test]
    fn a_delegator_who_may_no_longer_act_holds_nothing() {
        let ann = ann();
        let mut account = account_of(&ann);
        account.deactivate(&control_over(&account)).unwrap();
        let delegation = granted_by(&ann);

        let result = now_holding(&ann, &account, &[VIEW_ROUTES], &delegation);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ann, an owner of Acme's organization, gives her agent "view routes"
    /// through the reach her organization role gives her, with no tenant
    /// record naming her. The delegation still stands on what that role
    /// gives her now.
    #[test]
    fn an_organization_owner_holds_what_their_role_reaches() {
        let (organization, founder) = acme_with(acme());
        let owner = Human::new(
            HumanAccount::OrgUser(*founder.id()),
            PersonKey::new("ann@acme.com").unwrap(),
        );
        let delegation = granted_by(&owner);
        let records = ConsumerRecords::empty();
        let account = AccountNow::Member(MemberNow {
            member: &founder,
            organization: &organization,
            grants: &[],
        });

        let held = HeldNow::worked_out(
            &records.access(),
            &account,
            delegation.granted(),
            &HeldResources::answered(owner.principal(), Vec::new()),
            &[],
        )
        .unwrap();

        assert!(delegation.still_allowed(&held));
    }

    /// Current holdings are refused for an organization owner whose
    /// organization does not own the tenant being checked.
    #[test]
    fn an_organization_member_outside_the_tenant_holds_nothing() {
        let (organization, founder) = acme_with(TenantId::new());
        let records = ConsumerRecords::empty();
        let account = AccountNow::Member(MemberNow {
            member: &founder,
            organization: &organization,
            grants: &[],
        });
        let owner = Human::new(
            HumanAccount::OrgUser(*founder.id()),
            PersonKey::new("ann@acme.com").unwrap(),
        );

        let result = HeldNow::worked_out(
            &records.access(),
            &account,
            granted_by(&owner).granted(),
            &HeldResources::answered(owner.principal(), Vec::new()),
            &[],
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A resource-graph answer naming another person cannot establish
    /// the delegator's current holdings.
    #[test]
    fn an_answer_for_someone_else_is_refused() {
        let ann = ann();
        let account = account_of(&ann);
        let delegation = granted_by(&ann);
        let records = ConsumerRecords::where_holding(ann.principal(), &[VIEW_ROUTES]);

        let result = HeldNow::worked_out(
            &records.access(),
            &AccountNow::User(&account),
            delegation.granted(),
            &HeldResources::answered(sam().principal(), Vec::new()),
            &[],
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Holdings established for another person do not back a delegation,
    /// even when that person holds the delegated permission.
    #[test]
    fn holdings_of_someone_else_do_not_back_a_delegation() {
        let ann = ann();
        let sam = sam();
        let sams = account_of(&sam);
        let delegation = granted_by(&ann);
        let records = ConsumerRecords::where_holding(sam.principal(), &[VIEW_ROUTES]);

        let held = HeldNow::worked_out(
            &records.access(),
            &AccountNow::User(&sams),
            delegation.granted(),
            &HeldResources::answered(sam.principal(), Vec::new()),
            &[],
        )
        .unwrap();

        assert!(!delegation.still_allowed(&held));
    }
}
