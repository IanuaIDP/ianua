//! Events about separation-of-duties rules.

use time::OffsetDateTime;

use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, Label, SeparationRuleId};

/// Two roles were declared that nobody may hold together.
#[derive(Debug)]
pub struct SeparationRuleAdded {
    /// The prohibition preventing these two roles from being held together.
    pub(crate) rule_id: SeparationRuleId,
    /// What it is called.
    pub(crate) name: Label,
    /// One role's name, for the audit trail.
    pub(crate) first: EventLabel,
    /// The other's.
    pub(crate) second: EventLabel,
    /// When it was added.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SeparationRuleAdded => crate::types::event_type::AuthorizationEvent::SeparationRuleAdded,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_id", self.rule_id.to_string())
            .field("name", self.name.to_string())
            .field(
                "roles",
                format!("{}, {}", self.first.as_str(), self.second.as_str()),
            )
    }
}

/// A separation-of-duties rule was lifted.
#[derive(Debug)]
pub struct SeparationRuleRemoved {
    /// The prohibition that no longer prevents the role combination.
    pub(crate) rule_id: SeparationRuleId,
    /// What it was called.
    pub(crate) name: Label,
    /// When it was lifted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SeparationRuleRemoved => crate::types::event_type::AuthorizationEvent::SeparationRuleRemoved,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_id", self.rule_id.to_string())
            .field("name", self.name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::event::DomainEventCore;

    /// A rule keeping "raise payments" and "approve payments" apart is
    /// added. The record names both roles.
    #[test]
    fn an_added_rule_records_both_roles() {
        let event = SeparationRuleAdded {
            rule_id: SeparationRuleId::new(),
            name: Label::new("name", "raise or approve").unwrap(),
            first: EventLabel::of("raise payments"),
            second: EventLabel::of("approve payments"),
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(
            event.payload().get("roles"),
            Some("raise payments, approve payments")
        );
    }
}
