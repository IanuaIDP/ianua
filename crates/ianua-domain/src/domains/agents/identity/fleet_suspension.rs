//! Suspending every running agent of a tenant at once.
//!
//! When a tenant cannot tell which of its agents has gone wrong, a person
//! stops all of them and looks. The stop happens in storage, every active
//! agent in one statement, so no single agent changes in memory. This is
//! the change the audit trail records instead: who stopped the fleet and how
//! many agents it stopped.

use crate::domains::agents::events::identity::AllAgentsSuspended;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};

/// Every active agent of a tenant suspended in one step.
///
/// Only [`FleetSuspension::ordered`] makes one, so the store suspends the
/// whole fleet only for a person allowed to update every agent. Owning one
/// agent is not enough: it would let Sam stop everyone else's.
#[derive(Debug)]
pub struct FleetSuspension<T: TenantScope> {
    raised: Raised<T>,
}

impl<T: TenantScope> FleetSuspension<T> {
    /// The person `control` names orders every active agent stopped.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update agents.
    pub fn ordered(control: &AgentControl<'_>) -> Result<Self, DomainError> {
        if !control.holds_agent(AgentAction::Update) {
            return Err(DomainError::forbidden(message!(
                "agents-only-someone-allowed-to-update-agents",
                "only someone allowed to update agents may suspend every agent"
            )));
        }
        Ok(Self {
            raised: Raised::default(),
        })
    }

    /// Records that the store suspended `count` agents. Raises
    /// `agents.all_agents_suspended`.
    pub fn record_suspensions(&mut self, count: u64) {
        self.raised.raise(AllAgentsSuspended {
            suspended_count: count,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for FleetSuspension<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::identity::agent::tests::fixtures::{managing, person, viewing};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::events::{raised, raised_names};

    /// The text an event stores under `key`.
    fn text_at(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not text: {other:?}"),
        }
    }

    /// Bob, who manages agents, stops the whole fleet and the store stops
    /// seven. One record says so, with the count.
    #[test]
    fn carrying_out_raises_one_record_with_the_count() {
        let bob = person("bob@corp.test");
        let mut stop = FleetSuspension::<ResolvedTenant>::ordered(&managing(&bob)).unwrap();

        stop.record_suspensions(7);
        let events = raised(&mut stop);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.all_agents_suspended"
        );
        assert_eq!(text_at(&events[0], "suspended_count"), "7");
    }

    /// An order the store never carried out raises nothing.
    #[test]
    fn an_order_alone_raises_nothing() {
        let bob = person("bob@corp.test");
        let mut stop = FleetSuspension::<ResolvedTenant>::ordered(&managing(&bob)).unwrap();

        assert!(raised_names(&mut stop).is_empty());
    }

    /// Read-only agent authority cannot order a suspension of the tenant's fleet.
    #[test]
    fn a_viewer_may_not_stop_every_agent() {
        let sam = person("sam@corp.test");

        let result = FleetSuspension::<ResolvedTenant>::ordered(&viewing(&sam));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}
