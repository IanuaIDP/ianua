//! A person lowering a stopped agent's data mark.
//!
//! An agent's mark is the most sensitive data class it has read. It only
//! rises while the agent works, because its context still holds what it
//! read. Once the agent is stopped and its context is gone, a person who has
//! looked may lower the mark so the agent can go back to less sensitive
//! work. The mark guards the tenant's data from the agent, so lowering it is
//! for an agent administrator, not for the owner it would free.

use crate::domains::agents::events::execution::AgentExposureReset;
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::{AgentId, EventLabel, Human, Label, UntrustedText};

/// What a person asks for when they lower an agent's mark.
pub struct LowerExposureParams {
    /// The mark the store holds for the agent now.
    pub from: DataClassLevel,
    /// The mark to lower it to.
    pub to: DataClassLevel,
    /// Why, in the person's words.
    pub reason: Label,
}

/// A lowering of an agent's data mark, checked here.
///
/// Its fields are private. Only [`ExposureReset::ordered`] makes one, so the
/// store lowers a mark only by a person allowed to, for a stopped agent,
/// and only ever downwards.
#[derive(Debug, Clone, PartialEq)]
pub struct ExposureReset<T: TenantScope> {
    agent_id: AgentId,
    from: DataClassLevel,
    to: DataClassLevel,
    reason: Label,
    by: Human,
    raised: Raised<T>,
}

impl<T: TenantScope> ExposureReset<T> {
    /// The person `control` names lowers `agent`'s mark as `params` asks.
    ///
    /// Sam owns an agent that read restricted HR records. Without the right
    /// check, he lowers its mark to public and points it at a public tool.
    /// Without the status check, a running agent whose context still holds
    /// those records would be cleared to send them anywhere.
    ///
    /// Raises `agents.exposure_reset`, taken once the store has lowered the
    /// mark.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage agents.
    /// - [`DomainError::InvalidTransition`] while the agent is active.
    /// - [`DomainError::Validation`] when the mark asked for is not below
    ///   the one it has.
    pub fn ordered(
        control: &AgentControl<'_>,
        agent: &AgentIdentity<T>,
        params: LowerExposureParams,
    ) -> Result<Self, DomainError> {
        ensure_may_lower(control, agent, &params)?;
        let mut reset = Self {
            agent_id: *agent.id(),
            from: params.from,
            to: params.to,
            reason: params.reason,
            by: control.by().clone(),
            raised: Raised::default(),
        };
        reset.raised.raise(AgentExposureReset {
            agent_id: reset.agent_id,
            agent_label: EventLabel::of(agent.name().as_str()),
            from: reset.from,
            to: reset.to,
            reason: UntrustedText::record(reset.reason.as_str()),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(reset)
    }

    /// The agent whose mark is lowered.
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// The mark before the reset.
    #[must_use]
    pub fn previous(&self) -> DataClassLevel {
        self.from
    }

    /// The mark after the reset.
    #[must_use]
    pub fn lowered_to(&self) -> DataClassLevel {
        self.to
    }

    /// Why, in the person's words.
    #[must_use]
    pub fn reason(&self) -> &Label {
        &self.reason
    }

    /// The person who lowered it.
    #[must_use]
    pub fn by(&self) -> &Human {
        &self.by
    }
}

impl<T: TenantScope> Raises for ExposureReset<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses a reset by someone who may not manage agents, of an agent still
/// running, or to a mark that is not lower.
fn ensure_may_lower<T: TenantScope>(
    control: &AgentControl<'_>,
    agent: &AgentIdentity<T>,
    params: &LowerExposureParams,
) -> Result<(), DomainError> {
    if !control.holds_agent(AgentAction::Manage) {
        return Err(DomainError::forbidden(message!(
            "agents-only-someone-allowed-to-manage-agents-3",
            "only someone allowed to manage agents lowers an agent's data mark"
        )));
    }
    if agent.is_active() {
        return Err(DomainError::invalid_transition(message!(
            "agents-an-agent-is-stopped-before-its",
            "an agent is stopped before its data mark is lowered"
        )));
    }
    if params.to >= params.from {
        return Err(DomainError::invalid(message!(
            "agents-a-reset-only-lowers-the-mark",
            "a reset only lowers the mark"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::identity::agent::SuspendedBy;
    use crate::domains::agents::identity::agent::tests::fixtures::{
        acting, agent_of, ann, managing, person,
    };
    use crate::shared::events::data::FieldValue;
    use crate::test_support::events::raised;

    fn lowering(from: DataClassLevel, to: DataClassLevel) -> LowerExposureParams {
        LowerExposureParams {
            from,
            to,
            reason: Label::new("reason", "context cleared after the HR review").unwrap(),
        }
    }

    /// An agent administrator lowers a suspended agent's mark from
    /// restricted to internal. The reset names the agent, both marks and
    /// who lowered it.
    #[test]
    fn an_administrator_lowers_a_stopped_agents_mark() {
        let ann = ann();
        let bob = person("bob@corp.test");
        let mut agent = agent_of(&ann);
        agent.suspend(SuspendedBy::Monitor).unwrap();

        let reset = ExposureReset::ordered(
            &managing(&bob),
            &agent,
            lowering(DataClassLevel::Restricted, DataClassLevel::Internal),
        )
        .unwrap();

        assert_eq!(reset.agent_id(), agent.id());
        assert_eq!(reset.previous(), DataClassLevel::Restricted);
        assert_eq!(reset.lowered_to(), DataClassLevel::Internal);
        assert!(reset.by().is_same_person_as(&bob));
    }

    /// Owning a suspended agent does not authorize lowering its data
    /// exposure; an owner without management rights is refused.
    #[test]
    fn the_owner_alone_does_not_lower_the_mark() {
        let ann = ann();
        let mut agent = agent_of(&ann);
        agent.suspend(SuspendedBy::Monitor).unwrap();

        let result = ExposureReset::ordered(
            &acting(&ann),
            &agent,
            lowering(DataClassLevel::Restricted, DataClassLevel::Public),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Even an administrator cannot lower an active agent's data mark;
    /// the reset is refused while the agent is running.
    #[test]
    fn a_running_agents_mark_is_not_lowered() {
        let bob = person("bob@corp.test");
        let agent = agent_of(&ann());

        let result = ExposureReset::ordered(
            &managing(&bob),
            &agent,
            lowering(DataClassLevel::Restricted, DataClassLevel::Public),
        );

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
    }

    /// A reset that keeps the mark, or raises it, is refused. A reset only
    /// ever lowers.
    #[test]
    fn a_reset_only_lowers() {
        let bob = person("bob@corp.test");
        let mut agent = agent_of(&ann());
        agent.suspend(SuspendedBy::Monitor).unwrap();

        for to in [DataClassLevel::Internal, DataClassLevel::Restricted] {
            let result = ExposureReset::ordered(
                &managing(&bob),
                &agent,
                lowering(DataClassLevel::Internal, to),
            );

            assert!(matches!(result, Err(DomainError::Validation(_))), "{to:?}");
        }
    }

    /// Bob lowers a suspended agent's mark from restricted to internal. The
    /// reset raises its record once, with both marks.
    #[test]
    fn ordering_a_reset_raises_it_with_both_marks() {
        let bob = person("bob@corp.test");
        let mut agent = agent_of(&ann());
        agent.suspend(SuspendedBy::Monitor).unwrap();

        let mut reset = ExposureReset::ordered(
            &managing(&bob),
            &agent,
            lowering(DataClassLevel::Restricted, DataClassLevel::Internal),
        )
        .unwrap();

        let events = raised(&mut reset);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "agents.exposure_reset");
        let payload = events[0].payload();
        assert!(
            matches!(payload.value("from"), Some(FieldValue::Text(from)) if from == "restricted")
        );
        assert!(matches!(payload.value("to"), Some(FieldValue::Text(to)) if to == "internal"));
        assert!(raised(&mut reset).is_empty());
    }
}
