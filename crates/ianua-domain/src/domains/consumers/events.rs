//! Consumer domain events.

use time::OffsetDateTime;

use crate::domains::consumers::quota::ConsumerQuota;
use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::ConsumersEvent;
use crate::types::{ConsumerId, EventLabel, Expiry};

/// References the consumer an event acted on, labelled as it was at that time.
fn consumer_reference(consumer_id: &ConsumerId, label: &str) -> Reference {
    Reference::new(RefKind::CONSUMER, consumer_id.to_string(), label)
}

/// A new consumer was created.
#[derive(Debug)]
pub struct ConsumerCreated {
    /// The new consumer's id.
    pub(crate) consumer_id: ConsumerId,
    /// The consumer's name, for the audit reference.
    pub(crate) consumer_label: EventLabel,
    /// When it was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerCreated => ConsumersEvent::ConsumerCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "consumer",
            consumer_reference(&self.consumer_id, self.consumer_label.as_str()),
        )
    }
}

/// A consumer was renamed. The record keeps both names, so entries made
/// under the old one are still found.
#[derive(Debug)]
pub struct ConsumerRenamed {
    /// The consumer's id.
    pub(crate) consumer_id: ConsumerId,
    /// The name before the change.
    pub(crate) previous_name: EventLabel,
    /// The name now.
    pub(crate) current_name: EventLabel,
    /// When it was renamed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerRenamed => ConsumersEvent::ConsumerRenamed,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "consumer",
                consumer_reference(&self.consumer_id, self.current_name.as_str()),
            )
            .change(
                "name",
                self.previous_name.as_str(),
                self.current_name.as_str(),
            )
    }
}

/// The most sensitive data a consumer may receive changed.
///
/// Raising it lets the consumer reach topics it could not before. The record
/// keeps both levels, so a review sees what it could reach before and after.
#[derive(Debug)]
pub(crate) struct ConsumerClearanceChanged {
    /// The consumer's id.
    pub(crate) consumer_id: ConsumerId,
    /// The consumer's name, for the audit reference.
    pub(crate) consumer_label: EventLabel,
    /// The clearance before the change.
    pub(crate) previous: DataClassLevel,
    /// The clearance now.
    pub(crate) current: DataClassLevel,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerClearanceChanged => ConsumersEvent::ClearanceChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "consumer",
                consumer_reference(&self.consumer_id, self.consumer_label.as_str()),
            )
            .change(
                "clearance",
                self.previous.as_str(),
                self.current.as_str(),
            )
    }
}

/// A consumer was disabled.
#[derive(Debug)]
pub struct ConsumerDisabled {
    /// The external client whose requests were disabled.
    pub(crate) consumer_id: ConsumerId,
    /// The consumer's name, for the audit reference.
    pub(crate) consumer_label: EventLabel,
    /// When it was disabled.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerDisabled => ConsumersEvent::ConsumerDisabled,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "consumer",
            consumer_reference(&self.consumer_id, self.consumer_label.as_str()),
        )
    }
}

/// A consumer's credentials were rotated.
///
/// The record says until when the old credential keeps working, so a review
/// sees how long a leaked one stayed open.
#[derive(Debug)]
pub(crate) struct ConsumerCredentialRotated {
    /// The external client whose current and overlapping credentials changed.
    pub(crate) consumer_id: ConsumerId,
    /// The consumer's name, for the audit reference.
    pub(crate) consumer_label: EventLabel,
    /// When the old credential stops working. The rotation itself when it
    /// was not kept.
    pub(crate) previous_works_until: OffsetDateTime,
    /// When the new credential stops working.
    pub(crate) expiry: Expiry,
    /// When credentials were rotated.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerCredentialRotated => ConsumersEvent::CredentialRotated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "consumer",
                consumer_reference(&self.consumer_id, self.consumer_label.as_str()),
            )
            .field("previous_works_until", self.previous_works_until.to_string())
            .field("expires_at", expiry_text(self.expiry))
    }
}

/// A consumer's old credential was stopped before its overlap ran out,
/// once every caller had moved to the new one.
#[derive(Debug)]
pub(crate) struct ConsumerCredentialOverlapEnded {
    /// The external client whose previous credential stopped working.
    pub(crate) consumer_id: ConsumerId,
    /// The consumer's name, for the audit reference.
    pub(crate) consumer_label: EventLabel,
    /// When the old credential was stopped.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerCredentialOverlapEnded => ConsumersEvent::CredentialOverlapEnded,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "consumer",
            consumer_reference(&self.consumer_id, self.consumer_label.as_str()),
        )
    }
}

/// When a consumer's current credential stops working changed.
#[derive(Debug)]
pub(crate) struct ConsumerCredentialExpiryChanged {
    /// The external client whose current credential lifetime changed.
    pub(crate) consumer_id: ConsumerId,
    /// The consumer's name, for the audit reference.
    pub(crate) consumer_label: EventLabel,
    /// The expiry before the change.
    pub(crate) previous: Expiry,
    /// The expiry now.
    pub(crate) current: Expiry,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerCredentialExpiryChanged => ConsumersEvent::CredentialExpiryChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "consumer",
                consumer_reference(&self.consumer_id, self.consumer_label.as_str()),
            )
            .change(
                "expires_at",
                expiry_text(self.previous),
                expiry_text(self.current),
            )
    }
}

/// How many requests a consumer may send changed.
///
/// Raising it lets the consumer send more than its contract paid for, so the
/// record keeps both quotas.
#[derive(Debug)]
pub(crate) struct ConsumerQuotaChanged {
    /// The external client whose request allowance changed.
    pub(crate) consumer_id: ConsumerId,
    /// The consumer's name, for the audit reference.
    pub(crate) consumer_label: EventLabel,
    /// The quota before the change.
    pub(crate) previous: ConsumerQuota,
    /// The quota now.
    pub(crate) current: ConsumerQuota,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerQuotaChanged => ConsumersEvent::QuotaChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "consumer",
                consumer_reference(&self.consumer_id, self.consumer_label.as_str()),
            )
            .change("quota", self.previous.describe(), self.current.describe())
    }
}

/// A consumer's description was changed or cleared.
///
/// The record names the consumer, not the words: what a description says
/// is the tenant's to read in the consumer itself.
#[derive(Debug)]
pub(crate) struct ConsumerDescriptionChanged {
    /// The external client whose descriptive metadata changed.
    pub(crate) consumer_id: ConsumerId,
    /// The consumer's name, for the audit reference.
    pub(crate) consumer_label: EventLabel,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerDescriptionChanged => ConsumersEvent::DescriptionChanged,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "consumer",
            consumer_reference(&self.consumer_id, self.consumer_label.as_str()),
        )
    }
}

/// A consumer was re-enabled.
#[derive(Debug)]
pub struct ConsumerEnabled {
    /// The external client whose requests were enabled again.
    pub(crate) consumer_id: ConsumerId,
    /// The consumer's name, for the audit reference.
    pub(crate) consumer_label: EventLabel,
    /// When it was re-enabled.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerEnabled => ConsumersEvent::ConsumerEnabled,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "consumer",
            consumer_reference(&self.consumer_id, self.consumer_label.as_str()),
        )
    }
}

/// A consumer was permanently deleted.
#[derive(Debug)]
pub struct ConsumerDeleted {
    /// The external client permanently removed from service.
    pub(crate) consumer_id: ConsumerId,
    /// The consumer's name, for the audit reference.
    pub(crate) consumer_label: EventLabel,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsumerDeleted => ConsumersEvent::ConsumerDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "consumer",
            consumer_reference(&self.consumer_id, self.consumer_label.as_str()),
        )
    }
}

/// An expiry as a record writes it: the instant, or `never`.
fn expiry_text(expiry: Expiry) -> String {
    expiry
        .instant()
        .map_or_else(|| "never".to_owned(), |at| at.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn consumer(payload: &EventData) -> (String, String) {
        match payload.value("consumer") {
            Some(FieldValue::Reference(reference)) => {
                assert_eq!(reference.kind(), RefKind::CONSUMER);
                (reference.id().to_owned(), reference.label().to_owned())
            }
            other => panic!("consumer is not an entity reference: {other:?}"),
        }
    }

    /// Creation, disabling and credential rotation link the consumer by its
    /// ID and the name "billing-export".
    #[test]
    fn every_consumer_event_names_the_consumer() {
        let id = ConsumerId::new();
        let label = "billing-export";

        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(ConsumerCreated {
                consumer_id: id,
                consumer_label: EventLabel::of(label),
                occurred_at: now(),
            }),
            Box::new(ConsumerDisabled {
                consumer_id: id,
                consumer_label: EventLabel::of(label),
                occurred_at: now(),
            }),
            Box::new(ConsumerCredentialRotated {
                consumer_id: id,
                consumer_label: EventLabel::of(label),
                previous_works_until: now(),
                expiry: Expiry::Never,
                occurred_at: now(),
            }),
        ];

        assert_consumer_references(events, id, label);
    }

    /// Ending credential overlap, enabling and deleting a consumer retain its
    /// ID and name for the audit link.
    #[test]
    fn consumer_transitions_keep_the_consumer_reference() {
        let id = ConsumerId::new();
        let label = "billing-export";
        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(ConsumerCredentialOverlapEnded {
                consumer_id: id,
                consumer_label: EventLabel::of(label),
                occurred_at: now(),
            }),
            Box::new(ConsumerEnabled {
                consumer_id: id,
                consumer_label: EventLabel::of(label),
                occurred_at: now(),
            }),
            Box::new(ConsumerDeleted {
                consumer_id: id,
                consumer_label: EventLabel::of(label),
                occurred_at: now(),
            }),
        ];

        assert_consumer_references(events, id, label);
    }

    /// Every event must identify the same consumer using its current label.
    fn assert_consumer_references(
        events: Vec<Box<dyn DomainEventCore>>,
        id: ConsumerId,
        label: &str,
    ) {
        for event in events {
            let kind = event.event_type();
            assert_eq!(
                consumer(&event.payload()),
                (id.to_string(), label.to_owned()),
                "{kind}"
            );
        }
    }

    /// Fay clears `billing-sync` for confidential data, up from internal.
    /// The record names the consumer and keeps both levels, so a review
    /// sees what it could reach before and after.
    #[test]
    fn a_clearance_change_keeps_both_levels() {
        let consumer_id = ConsumerId::new();

        let event = ConsumerClearanceChanged {
            consumer_id,
            consumer_label: EventLabel::of("billing-sync"),
            previous: DataClassLevel::Internal,
            current: DataClassLevel::Confidential,
            occurred_at: now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("clearance") else {
            panic!("clearance is not a change");
        };
        assert_eq!(
            (change.from(), change.to()),
            (Some("internal"), Some("confidential"))
        );
        assert_eq!(
            consumer(&payload),
            (consumer_id.to_string(), "billing-sync".to_owned())
        );
    }

    /// The text of the change recorded under `key`.
    fn change_in(payload: &EventData, key: &str) -> (String, String) {
        let Some(FieldValue::Change(change)) = payload.value(key) else {
            panic!("{key} is not a change");
        };
        (
            change.from().unwrap_or_default().to_owned(),
            change.to().unwrap_or_default().to_owned(),
        )
    }

    /// Fay raises `billing-sync` from unlimited to 10000 requests a day. The
    /// record keeps both quotas in plain words.
    #[test]
    fn a_quota_change_keeps_both_quotas() {
        let event = ConsumerQuotaChanged {
            consumer_id: ConsumerId::new(),
            consumer_label: EventLabel::of("billing-sync"),
            previous: ConsumerQuota::Unlimited,
            current: ConsumerQuota::Limited(
                crate::domains::consumers::quota::RequestAllowance::new(
                    10_000,
                    crate::domains::consumers::quota::QuotaPeriod::Day,
                )
                .unwrap(),
            ),
            occurred_at: now(),
        };

        assert_eq!(
            change_in(&event.payload(), "quota"),
            ("unlimited".to_owned(), "10000 per day".to_owned())
        );
    }

    /// Ann gives the key of `billing-sync`, which never expired, an expiry.
    /// The record keeps `never` and the new instant.
    #[test]
    fn an_expiry_change_keeps_both_expiries() {
        let event = ConsumerCredentialExpiryChanged {
            consumer_id: ConsumerId::new(),
            consumer_label: EventLabel::of("billing-sync"),
            previous: Expiry::Never,
            current: Expiry::At(now()),
            occurred_at: now(),
        };

        assert_eq!(
            change_in(&event.payload(), "expires_at"),
            ("never".to_owned(), now().to_string())
        );
    }

    /// Ann rotates the key of `billing-sync`, keeping the old one until
    /// `now`. The record says until when the old key works.
    #[test]
    fn a_rotation_records_until_when_the_old_credential_works() {
        let event = ConsumerCredentialRotated {
            consumer_id: ConsumerId::new(),
            consumer_label: EventLabel::of("billing-sync"),
            previous_works_until: now(),
            expiry: Expiry::Never,
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            payload.get("previous_works_until"),
            Some(now().to_string().as_str())
        );
        assert_eq!(payload.get("expires_at"), Some("never"));
    }

    /// The `billing-export` consumer is renamed `billing-sync`. The record
    /// links it under its new name and keeps both names, so entries made
    /// under the old one are still found.
    #[test]
    fn renaming_a_consumer_keeps_both_names() {
        let consumer_id = ConsumerId::new();

        let event = ConsumerRenamed {
            consumer_id,
            previous_name: EventLabel::of("billing-export"),
            current_name: EventLabel::of("billing-sync"),
            occurred_at: now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("name") else {
            panic!("name is not a change");
        };
        assert_eq!(
            (change.from(), change.to()),
            (Some("billing-export"), Some("billing-sync"))
        );
        let Some(FieldValue::Reference(consumer)) = payload.value("consumer") else {
            panic!("the consumer is not referenced");
        };
        assert_eq!(consumer.id(), consumer_id.to_string());
    }
}
