//! Who may change an agent, or act on its behalf in a way that matters.

use crate::domains::agents::identity::agent::OwnershipOffer;
use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::permission::{AgentAction, SystemPermission};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::two_cases::two_cases;
use crate::types::Human;

/// A person acting on an agent, with what they hold.
///
/// An agent acts with everything it holds, so changing it is changing what
/// that authority does. Its owner may do it. So may someone holding the agent
/// permission the action needs. Sam may view agents only. Without this
/// check, Sam enrols his own key for Ann's agent and signs in as it.
#[derive(Debug, Clone, Copy)]
pub struct AgentControl<'a> {
    authority: &'a TenantAuthority,
}

impl<'a> AgentControl<'a> {
    /// The person `authority` names, acting with what it says they hold.
    #[must_use]
    pub fn new(authority: &'a TenantAuthority) -> Self {
        Self { authority }
    }

    /// The person acting.
    #[must_use]
    pub fn by(&self) -> &'a Human {
        self.authority.who()
    }

    /// What the tenant's records say the person holds.
    pub(crate) fn authority(&self) -> &'a TenantAuthority {
        self.authority
    }

    /// What they may hand on: their standing rights.
    #[must_use]
    pub fn holds(&self) -> HeldByGranter<'a> {
        self.authority.standing()
    }

    /// Refuses `action` on an agent owned by `owner`, unless the person
    /// acting is that owner, through any of their accounts, or holds the
    /// agent permission for it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they are neither the owner nor hold
    ///   the permission.
    pub fn ensure_may(&self, owner: &Human, action: AgentAction) -> Result<(), DomainError> {
        if self.may(owner, action) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "agents-only-the-agent-s-owner-or-2",
            "only the agent's owner, or someone allowed to manage agents, may do this"
        )))
    }

    /// Whether the person acting may take `action` on an agent owned by
    /// `owner`: they are that owner, through any of their accounts, or hold
    /// the agent permission for it.
    ///
    /// A lookup asks it to read an agent the person may not act on as
    /// missing, so an id they name tells them nothing about whose agents
    /// exist.
    #[must_use]
    pub fn may(&self, owner: &Human, action: AgentAction) -> bool {
        self.by().is_same_person_as(owner) || self.holds_agent(action)
    }

    /// Whether `offer` was made to the person acting, through the account
    /// acting, whether it is still open or has lapsed.
    #[must_use]
    pub fn is_offered(&self, offer: &OwnershipOffer) -> bool {
        offer
            .recipient()
            .is_some_and(|recipient| recipient.is_same_account_as(self.by()))
    }

    /// Whether the person acting holds the agent permission for `action`.
    #[must_use]
    pub fn holds_agent(&self, action: AgentAction) -> bool {
        self.authority.holds(SystemPermission::Agents(action))
    }

    /// Refuses handing on, or taking away, a relation on a resource unless
    /// the person acting administers agents or `holding` says they hold it
    /// themselves.
    ///
    /// Authority propagates rather than being conjured. Every relation in
    /// the graph traces back to someone who held it first, and the root is
    /// the tenant's agent administrator, who may seed one nobody holds yet.
    /// Sam holds nothing on the payroll export. Without this check, he gives
    /// his own agent the right to read it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they neither administer agents nor
    ///   hold the relation.
    pub fn ensure_may_pass_on_relation(&self, holding: RelationHolding) -> Result<(), DomainError> {
        if self.holds_agent(AgentAction::Manage) || holding == RelationHolding::Held {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "agents-cannot-grant-a-resource-relation-you",
            "cannot grant a resource relation you do not hold"
        )))
    }
}

two_cases! {
    /// Whether the person acting holds a relation on a resource, as the
    /// relationship graph answers.
    pub enum RelationHolding {
        /// They hold it.
        Held => true,
        /// They do not.
        NotHeld => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authority::assumed_authority;
    use crate::types::{HumanAccount, PersonKey, TenantId, UserId};

    fn person(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    fn holding<'a>(by: &'a Human, system: &'a [SystemPermission]) -> AgentControl<'a> {
        AgentControl::new(assumed_authority(by, TenantId::new(), system, &[]))
    }

    /// A viewer cannot update another person's agent, while its owner and
    /// an agent manager both pass the same authority check.
    #[test]
    fn only_the_owner_or_a_manager_changes_an_agent() {
        let ann = person("ann@corp.test");
        let sam = person("sam@corp.test");
        let bob = person("bob@corp.test");
        let view = [SystemPermission::Agents(AgentAction::View)];
        let manage = [SystemPermission::ManageAgents];

        assert!(matches!(
            holding(&sam, &view).ensure_may(&ann, AgentAction::Update),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            holding(&ann, &[])
                .ensure_may(&ann, AgentAction::Update)
                .is_ok()
        );
        assert!(
            holding(&bob, &manage)
                .ensure_may(&ann, AgentAction::Update)
                .is_ok()
        );
    }

    /// Sam, who may only view agents, may not update Ann's agent, so a
    /// lookup for him reads it as missing. Ann, its owner, may.
    #[test]
    fn may_answers_as_ensure_may_refuses() {
        let ann = person("ann@corp.test");
        let sam = person("sam@corp.test");
        let view = [SystemPermission::Agents(AgentAction::View)];

        assert!(!holding(&sam, &view).may(&ann, AgentAction::Update));
        assert!(holding(&ann, &[]).may(&ann, AgentAction::Update));
    }

    /// Ann offered her agent to Bob. The offer is his, even once it lapsed,
    /// and not Sam's. An agent never offered is nobody's.
    #[test]
    fn an_offer_is_the_recipients_only() {
        let bob = person("bob@corp.test");
        let sam = person("sam@corp.test");
        let now = crate::shared::clock::now();
        let lapsed = OwnershipOffer::Open {
            recipient: bob.clone(),
            offered_at: now.saturating_sub(time::Duration::days(30)),
            expires_at: now.saturating_sub(time::Duration::days(23)),
        };

        assert!(holding(&bob, &[]).is_offered(&lapsed));
        assert!(!holding(&sam, &[]).is_offered(&lapsed));
        assert!(!holding(&bob, &[]).is_offered(&OwnershipOffer::Unoffered));
    }

    /// A non-holder cannot pass on a resource relation. A holder can, and an
    /// agent manager can grant it without holding it personally.
    #[test]
    fn only_a_holder_or_an_administrator_passes_a_relation_on() {
        let (ann, sam, bob) = (
            person("ann@corp.test"),
            person("sam@corp.test"),
            person("bob@corp.test"),
        );
        let manage = [SystemPermission::Agents(AgentAction::Manage)];

        let by_sam = holding(&sam, &[]).ensure_may_pass_on_relation(RelationHolding::NotHeld);
        let by_ann = holding(&ann, &[]).ensure_may_pass_on_relation(RelationHolding::Held);
        let by_bob = holding(&bob, &manage).ensure_may_pass_on_relation(RelationHolding::NotHeld);

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_ann.is_ok());
        assert!(by_bob.is_ok());
    }
}
