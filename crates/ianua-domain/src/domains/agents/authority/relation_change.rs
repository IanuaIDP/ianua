//! A relation on a resource handed to a principal, or taken from one.
//!
//! The relationship graph answers "may this person hand out `reader` on the
//! Q1 ledger?", so something has to put edges into it and take them out.
//! Authority propagates rather than being conjured: the person acting must
//! hold the relation themselves, or administer agents, to change who holds
//! it. A [`RelationChange`] is that change once the domain allowed it, with
//! its record raised; the application writes it to the graph and records
//! what it raised.

use std::marker::PhantomData;

use crate::domains::agents::authority::capability::ResourceCapability;
use crate::domains::agents::events::authority::{
    AgentResourceRelationGranted, AgentResourceRelationRevoked, ResourceRelationChange,
};
use crate::domains::agents::identity::control::{AgentControl, RelationHolding};
use crate::isolation::scope::TenantScope;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::PrincipalRef;

/// Who gains or loses a relation, and which relation on which object, as
/// the person acting was allowed to change it.
#[derive(Debug)]
pub struct RelationChange<T: TenantScope> {
    subject: PrincipalRef,
    capability: ResourceCapability,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> RelationChange<T> {
    /// `subject` given `capability` by the person `control` names, who
    /// holds it as `holding` says.
    ///
    /// Sam holds nothing on the payroll export. Without this check, he gives
    /// his own agent the right to read it.
    ///
    /// Raises `agents.resource_relation_granted`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person neither administers
    ///   agents nor holds the relation.
    pub fn grant(
        control: &AgentControl<'_>,
        holding: RelationHolding,
        subject: PrincipalRef,
        capability: ResourceCapability,
    ) -> Result<Self, DomainError> {
        let mut change = Self::allowed(control, holding, subject, capability)?;
        let event = AgentResourceRelationGranted(change.recorded());
        change.raised.raise(event);
        Ok(change)
    }

    /// `capability` taken from `subject` by the person `control` names,
    /// who holds it as `holding` says. Taking away a relation the person
    /// could not have given is still a change to authority they do not
    /// hold, so the same rule applies.
    ///
    /// Raises `agents.resource_relation_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person neither administers
    ///   agents nor holds the relation.
    pub fn revoke(
        control: &AgentControl<'_>,
        holding: RelationHolding,
        subject: PrincipalRef,
        capability: ResourceCapability,
    ) -> Result<Self, DomainError> {
        let mut change = Self::allowed(control, holding, subject, capability)?;
        let event = AgentResourceRelationRevoked(change.recorded());
        change.raised.raise(event);
        Ok(change)
    }

    /// The principal gaining or losing the relation.
    #[must_use]
    pub fn subject(&self) -> &PrincipalRef {
        &self.subject
    }

    /// The relation and the object it is on.
    #[must_use]
    pub fn capability(&self) -> &ResourceCapability {
        &self.capability
    }

    /// The change, once the person acting may make it.
    fn allowed(
        control: &AgentControl<'_>,
        holding: RelationHolding,
        subject: PrincipalRef,
        capability: ResourceCapability,
    ) -> Result<Self, DomainError> {
        control.ensure_may_pass_on_relation(holding)?;
        Ok(Self {
            subject,
            capability,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Who and what the record names.
    fn recorded(&self) -> ResourceRelationChange {
        ResourceRelationChange {
            subject: self.subject,
            capability: self.capability.clone(),
            occurred_at: clock::now(),
        }
    }
}

impl<T: TenantScope> Raises for RelationChange<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::{Relation, ResourceRef};
    use crate::domains::authorization::permission::{AgentAction, SystemPermission};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{Human, HumanAccount, PersonKey, TenantId, UserId};

    fn person(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    fn holding<'a>(by: &'a Human, system: &'a [SystemPermission]) -> AgentControl<'a> {
        AgentControl::new(assumed_authority(by, TenantId::new(), system, &[]))
    }

    fn budget_owner() -> ResourceCapability {
        ResourceCapability::new(
            Relation::new("owner").unwrap(),
            ResourceRef::new("doc:budget").unwrap(),
        )
    }

    /// Ann owns the budget and passes ownership on to Bob. The grant is
    /// raised, naming Bob, the relation and the object.
    #[test]
    fn a_holder_passing_a_relation_on_raises_the_grant() {
        let ann = person("ann@corp.test");
        let bob = PrincipalRef::User(UserId::new());

        let mut change = RelationChange::<ResolvedTenant>::grant(
            &holding(&ann, &[]),
            RelationHolding::Held,
            bob,
            budget_owner(),
        )
        .unwrap();

        let events = raised(&mut change);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.resource_relation_granted"
        );
        let payload = events[0].payload();
        assert_eq!(
            payload.value("relation"),
            Some(&FieldValue::Text("owner".to_owned()))
        );
        assert_eq!(
            payload.value("object"),
            Some(&FieldValue::Text("doc:budget".to_owned()))
        );
        assert_eq!(change.subject(), &bob);
    }

    /// Bob administers agents and takes ownership of the budget from Ann,
    /// though he holds none himself. The revoke is raised.
    #[test]
    fn an_administrator_taking_a_relation_away_raises_the_revoke() {
        let bob = person("bob@corp.test");
        let manage = [SystemPermission::Agents(AgentAction::Manage)];

        let mut change = RelationChange::<ResolvedTenant>::revoke(
            &holding(&bob, &manage),
            RelationHolding::NotHeld,
            PrincipalRef::User(UserId::new()),
            budget_owner(),
        )
        .unwrap();

        assert_eq!(
            raised_names(&mut change),
            ["agents.resource_relation_revoked"]
        );
    }

    /// A caller without agent management rights or the budget's ownership
    /// relation cannot construct a grant of that relation to another user.
    #[test]
    fn a_refused_change_raises_nothing() {
        let sam = person("sam@corp.test");

        let refused = RelationChange::<ResolvedTenant>::grant(
            &holding(&sam, &[]),
            RelationHolding::NotHeld,
            PrincipalRef::User(UserId::new()),
            budget_owner(),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }
}
