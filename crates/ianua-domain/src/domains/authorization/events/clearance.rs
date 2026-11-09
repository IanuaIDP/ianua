//! Events about clearance rules: which app permissions clear their holders
//! for which data.

use time::OffsetDateTime;

use crate::domains::authorization::permission::CustomPermission;
use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;

/// Holding an app permission was made to clear its holders for a data
/// class.
#[derive(Debug)]
pub struct ClearanceRuleAdded {
    /// The permission that clears.
    pub(crate) permission: CustomPermission,
    /// The most sensitive data it clears for.
    pub(crate) up_to: DataClassLevel,
    /// When the rule was added.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ClearanceRuleAdded => crate::types::event_type::AuthorizationEvent::ClearanceRuleAdded,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("permissions", self.permission.to_string())
            .field("clearance", self.up_to.as_str())
    }
}

/// The data class a clearance rule clears for changed. The record keeps
/// both, since lowering it takes data away from its holders.
#[derive(Debug)]
pub struct ClearanceRuleChanged {
    /// The permission that clears.
    pub(crate) permission: CustomPermission,
    /// What it cleared for before.
    pub(crate) previous: DataClassLevel,
    /// What it clears for now.
    pub(crate) up_to: DataClassLevel,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ClearanceRuleChanged => crate::types::event_type::AuthorizationEvent::ClearanceRuleChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("permissions", self.permission.to_string())
            .change("clearance", self.previous.as_str(), self.up_to.as_str())
    }
}

/// A clearance rule was removed; its permission clears for nothing more.
#[derive(Debug)]
pub struct ClearanceRuleRemoved {
    /// The permission that cleared.
    pub(crate) permission: CustomPermission,
    /// When it was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ClearanceRuleRemoved => crate::types::event_type::AuthorizationEvent::ClearanceRuleRemoved,
    fn payload(&self) -> EventData {
        EventData::new().field("permissions", self.permission.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    /// The payroll rule is lowered from restricted to confidential. The
    /// record keeps both levels.
    #[test]
    fn a_changed_rule_records_the_level_before_and_after() {
        let event = ClearanceRuleChanged {
            permission: CustomPermission::new("payroll", "read").unwrap(),
            previous: DataClassLevel::Restricted,
            up_to: DataClassLevel::Confidential,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("clearance") else {
            panic!("the clearance is recorded as a change");
        };

        assert_eq!(payload.get("permissions"), Some("payroll:read"));
        assert_eq!(
            (change.from(), change.to()),
            (Some("restricted"), Some("confidential"))
        );
    }
}
