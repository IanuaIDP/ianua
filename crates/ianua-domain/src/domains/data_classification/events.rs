//! Events about the fields a tenant classifies as sensitive.

use time::OffsetDateTime;

use crate::domains::data_classification::classification::RedactionStrategy;
use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::{ClassificationRuleId, FieldPath};

/// A tenant classified a field, so the proxy's redaction stage starts
/// treating it as sensitive.
#[derive(Debug)]
pub struct ClassificationRuleAdded {
    /// The new rule.
    pub(crate) rule_id: ClassificationRuleId,
    /// The dot-notation path of the field the rule classifies.
    pub(crate) field_path: FieldPath,
    /// How sensitive the field is.
    pub(crate) level: DataClassLevel,
    /// What the proxy does to the field once it is above the threshold.
    pub(crate) redaction: RedactionStrategy,
    /// When the rule was added.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ClassificationRuleAdded => crate::types::event_type::ProxyEvent::ClassificationRuleAdded,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_id", self.rule_id.to_string())
            .field("field_path", self.field_path.to_string())
            .field("level", self.level.as_str().to_owned())
            .field("redaction", self.redaction.as_str().to_owned())
    }
}

/// A tenant removed a field classification, so the proxy stops redacting
/// that field.
#[derive(Debug)]
pub struct ClassificationRuleRemoved {
    /// The removed rule.
    pub(crate) rule_id: ClassificationRuleId,
    /// The dot-notation path of the field the rule classified.
    pub(crate) field_path: FieldPath,
    /// When the rule was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ClassificationRuleRemoved => crate::types::event_type::ProxyEvent::ClassificationRuleRemoved,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_id", self.rule_id.to_string())
            .field("field_path", self.field_path.to_string())
    }
}

/// A tenant changed how sensitive a classified field is, or how the proxy
/// redacts it. The record keeps both, since lowering either lets more of
/// the field through.
#[derive(Debug)]
pub struct ClassificationRuleChanged {
    /// The declaration whose sensitivity or redaction behavior changed.
    pub(crate) rule_id: ClassificationRuleId,
    /// The dot-notation path of the field the rule classifies.
    pub(crate) field_path: FieldPath,
    /// How sensitive the field was.
    pub(crate) previous_level: DataClassLevel,
    /// How sensitive it is now.
    pub(crate) level: DataClassLevel,
    /// How it was redacted.
    pub(crate) previous_redaction: RedactionStrategy,
    /// How it is redacted now.
    pub(crate) redaction: RedactionStrategy,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ClassificationRuleChanged => crate::types::event_type::ProxyEvent::ClassificationRuleChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("rule_id", self.rule_id.to_string())
            .field("field_path", self.field_path.to_string())
            .change("level", self.previous_level.as_str(), self.level.as_str())
            .change(
                "redaction",
                self.previous_redaction.as_str(),
                self.redaction.as_str(),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn text(payload: &EventData, key: &str) -> String {
        match payload.value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not text: {other:?}"),
        }
    }

    /// Ann classifies `user.ssn` as restricted, masked. The record names the
    /// field, the level and how it is redacted, so a review sees what the
    /// proxy started hiding.
    #[test]
    fn adding_a_rule_records_the_field_its_level_and_its_redaction() {
        let event = ClassificationRuleAdded {
            rule_id: ClassificationRuleId::new(),
            field_path: FieldPath::new("user.ssn").unwrap(),
            level: DataClassLevel::Restricted,
            redaction: RedactionStrategy::Mask,
            occurred_at: now(),
        };

        let payload = event.payload();

        assert_eq!(text(&payload, "field_path"), "user.ssn");
        assert_eq!(text(&payload, "level"), "restricted");
        assert_eq!(text(&payload, "redaction"), "mask");
    }

    /// Ann removes the rule on `user.ssn`. The record names the rule and the
    /// field that now reaches callers unredacted.
    #[test]
    fn removing_a_rule_records_the_rule_and_its_field() {
        let rule_id = ClassificationRuleId::new();
        let event = ClassificationRuleRemoved {
            rule_id,
            field_path: FieldPath::new("user.ssn").unwrap(),
            occurred_at: now(),
        };

        let payload = event.payload();

        assert_eq!(text(&payload, "rule_id"), rule_id.to_string());
        assert_eq!(text(&payload, "field_path"), "user.ssn");
    }
}
