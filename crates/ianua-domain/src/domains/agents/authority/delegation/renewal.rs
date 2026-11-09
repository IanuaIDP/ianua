//! How a person renews a delegation they granted, for another lifetime.
//!
//! A delegation ends at a set time. Its delegator may renew it before then,
//! which is granting it again: they must still hold all it grants, and its
//! agent must still be free to receive it. A renewed delegation lives its
//! lifetime again from the moment of the renewal. Children passed on from
//! it keep the expiry they were given, never more than it had then.

use crate::domains::agents::authority::delegation::{
    Delegate, Delegation, DelegationRenewal, HeldBy, Lineage, lifetime_end, recorded,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::types::PrincipalRef;

impl<T: TenantScope> Delegation<T> {
    /// Whether, and when last, its delegator renewed it.
    #[must_use]
    pub fn renewed(&self) -> DelegationRenewal {
        self.renewed
    }

    /// Renews the delegation for its lifetime again, from now, as the
    /// person `held` names asks, for `delegate`, the agent it was given to.
    ///
    /// Only the person who granted a delegation at the top of its chain
    /// renews it. A child or a task token is cut from what sits above it,
    /// and lives no longer than that. Ann lost "view reports" last week.
    /// Without the holding check, she renews the delegation that still lists
    /// it, and her agent keeps a right she no longer has. Its agent is
    /// suspended after a leak: without the agent check, she renews authority
    /// for whoever holds it now.
    ///
    /// Raises `agents.delegation_renewed`, with the time it now expires.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when a person did not grant it
    ///   at the top of its chain.
    /// - [`DomainError::Forbidden`] when `held` names someone other than its
    ///   delegator, or one who no longer holds all it grants.
    /// - [`DomainError::Forbidden`] when `delegate` is another agent, or
    ///   one that may not receive authority now.
    /// - [`DomainError::InvalidTransition`] when it is revoked or expired.
    ///   An expired delegation is granted anew instead.
    pub fn renew(&mut self, held: &HeldBy, delegate: &Delegate<'_, T>) -> Result<(), DomainError> {
        self.ensure_renewable_by(held)?;
        if delegate.id() != self.delegate {
            return Err(DomainError::forbidden(message!(
                "agents-the-delegation-was-given-to-another",
                "the delegation was given to another agent"
            )));
        }
        delegate.ensure_may_receive()?;
        let now = clock::now();
        if !self.is_valid(now) {
            return Err(DomainError::invalid_transition(message!(
                "agents-a-revoked-or-expired-delegation-is",
                "a revoked or expired delegation is granted anew, not renewed"
            )));
        }
        self.expires_at = lifetime_end(now, &self.constraints);
        self.renewed = DelegationRenewal::RenewedAt(now);
        self.updated_at = now;
        recorded::raise_renewal(self);
        Ok(())
    }

    /// Refuses a renewal of anything but a root a person granted, by anyone
    /// but that person holding all it grants today.
    fn ensure_renewable_by(&self, held: &HeldBy) -> Result<(), DomainError> {
        let person_granted = matches!(
            self.delegator,
            PrincipalRef::User(_) | PrincipalRef::OrgUser(_)
        );
        if self.lineage != Lineage::Root || !person_granted {
            return Err(DomainError::invalid_transition(message!(
                "agents-only-a-delegation-a-person-granted",
                "only a delegation a person granted at the top of its chain is renewed"
            )));
        }
        if held.holder() != self.delegator {
            return Err(DomainError::forbidden(message!(
                "agents-only-the-person-who-granted-a",
                "only the person who granted a delegation renews it"
            )));
        }
        if !self.granted.subset_of(held.caps()) {
            return Err(DomainError::forbidden(message!(
                "agents-the-delegator-no-longer-holds-all",
                "the delegator no longer holds all the delegation grants"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
    use crate::domains::agents::authority::delegation::{
        AttenuateParams, Attenuator, DelegationRow, GrantDelegationParams, HeldResources,
        ReviewDuty,
    };
    use crate::domains::agents::execution::run::tests::fixtures::{agent, ann};
    use crate::domains::agents::execution::tool::tests::fixtures::{holding, person};
    use crate::domains::agents::identity::agent::{AgentIdentity, SuspendedBy};
    use crate::domains::authorization::permission::{RoutingAction, SystemPermission};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_names;
    use crate::types::{Human, Seconds};

    /// What Ann holds and grants: viewing routes.
    const VIEW_ROUTES: [SystemPermission; 1] = [SystemPermission::Routing(RoutingAction::View)];

    /// What viewing routes grants.
    fn view_routes() -> CapabilitySet {
        CapabilitySet::new(VIEW_ROUTES.to_vec(), Vec::new())
    }

    /// `by`, holding `system`, granting or renewing `wanted`.
    fn held_by(by: &Human, system: &[SystemPermission]) -> HeldBy {
        HeldBy::worked_out::<ResolvedTenant>(
            &holding(by, system),
            &view_routes(),
            &HeldResources::answered(by.principal(), Vec::new()),
            &[],
        )
        .unwrap()
    }

    /// The agent receiving it, reviewing nobody.
    fn to(agent: &AgentIdentity<ResolvedTenant>) -> Delegate<'_, ResolvedTenant> {
        Delegate {
            agent,
            duty: ReviewDuty::NotReviewing,
        }
    }

    /// Ann's hour-long delegation of viewing routes to `agent`.
    fn granted_to(agent: &AgentIdentity<ResolvedTenant>) -> Delegation<ResolvedTenant> {
        Delegation::grant(
            GrantDelegationParams {
                granted: view_routes(),
                constraints: DelegationConstraints::new(Seconds::new(3600), 1).unwrap(),
                name: None,
            },
            &held_by(&ann(), &VIEW_ROUTES),
            &to(agent),
        )
        .unwrap()
    }

    /// Fifty minutes into her hour-long delegation, Ann renews it. It now
    /// expires an hour from the renewal, and the renewal is raised.
    #[test]
    fn the_delegator_renews_her_delegation_for_another_lifetime() {
        let agent = agent();
        let mut d = granted_to(&agent);
        raised_names(&mut d);
        let at = d.issued_at + Duration::minutes(50);
        let frozen = clock::freeze(at);

        d.renew(&held_by(&ann(), &VIEW_ROUTES), &to(&agent))
            .unwrap();

        assert_eq!(d.expires_at(), at + Duration::hours(1));
        assert_eq!(d.renewed(), DelegationRenewal::RenewedAt(at));
        assert_eq!(raised_names(&mut d), ["agents.delegation_renewed"]);
        drop(frozen);
    }

    /// Someone other than the delegator cannot renew a delegation, even
    /// with its granted rights. The refusal leaves its expiry unchanged.
    #[test]
    fn only_the_delegator_renews() {
        let agent = agent();
        let mut d = granted_to(&agent);
        let before = d.expires_at();

        let result = d.renew(
            &held_by(&person("sam@corp.test"), &VIEW_ROUTES),
            &to(&agent),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(d.expires_at(), before);
    }

    /// A delegator who no longer holds route-viewing rights cannot renew
    /// a delegation granting that permission.
    #[test]
    fn a_delegator_who_lost_a_right_cannot_renew_it() {
        let agent = agent();
        let mut d = granted_to(&agent);

        let result = d.renew(&held_by(&ann(), &[]), &to(&agent));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A delegation cannot be renewed after a monitor suspends its agent,
    /// even when the delegator still holds the granted rights.
    #[test]
    fn a_delegation_of_an_agent_that_may_not_receive_is_not_renewed() {
        let mut agent = agent();
        let mut d = granted_to(&agent);
        agent.suspend(SuspendedBy::Monitor).unwrap();

        let result = d.renew(&held_by(&ann(), &VIEW_ROUTES), &to(&agent));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A delegation past its expiry is granted anew, never renewed.
    #[test]
    fn an_expired_delegation_is_not_renewed() {
        let agent = agent();
        let mut expired = granted_to(&agent);
        let later = clock::freeze(expired.expires_at() + Duration::SECOND);

        let result = expired.renew(&held_by(&ann(), &VIEW_ROUTES), &to(&agent));

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        drop(later);
    }

    /// A child delegation cannot be renewed through its root delegator's
    /// holdings; renewal is an invalid transition for the child.
    #[test]
    fn a_child_is_not_renewed() {
        let holder = agent();
        let other = agent();
        let parent = granted_to(&holder);
        let mut child = parent
            .attenuate(
                &Attenuator::Owner {
                    control: holding(&ann(), &[]),
                    holder: &holder,
                },
                &to(&other),
                AttenuateParams {
                    granted: view_routes(),
                    constraints: DelegationConstraints::new(Seconds::new(600), 1).unwrap(),
                    name: None,
                },
            )
            .unwrap();

        let result = child.renew(&held_by(&ann(), &VIEW_ROUTES), &to(&other));

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
    }

    /// A stored delegation that expires an hour after a renewal it never
    /// had, past its lifetime from when it was issued, is refused. With the
    /// renewal stored, it reads back.
    #[test]
    fn a_stored_renewal_bounds_the_lifetime() {
        let agent = agent();
        let mut d = granted_to(&agent);
        let frozen = clock::freeze(d.issued_at + Duration::minutes(50));
        d.renew(&held_by(&ann(), &VIEW_ROUTES), &to(&agent))
            .unwrap();
        drop(frozen);
        let row = |renewed| DelegationRow {
            id: d.id,
            delegator: d.delegator,
            delegate: d.delegate,
            granted: d.granted.clone(),
            constraints: d.constraints.clone(),
            lineage: d.lineage.clone(),
            depth: d.depth,
            status: d.status,
            issued_at: d.issued_at,
            expires_at: d.expires_at,
            renewed,
            updated_at: d.updated_at,
            name: None,
        };

        assert!(Delegation::<ResolvedTenant>::reconstitute(row(d.renewed)).is_ok());
        assert!(refused_as_corrupt(
            &Delegation::<ResolvedTenant>::reconstitute(row(DelegationRenewal::NotRenewed))
        ));
    }
}
