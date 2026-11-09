//! Events about consent and erasure.

use time::OffsetDateTime;

use crate::domains::identity::events::user_reference;
use crate::domains::identity::privacy::consent::{ConsentTerms, ConsentType};
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, UserId};

/// A consent kind as the audit trail names it, stable across releases.
pub(crate) fn consent_type_text(consent_type: ConsentType) -> &'static str {
    match consent_type {
        ConsentType::DataProcessing => "data_processing",
        ConsentType::Marketing => "marketing",
        ConsentType::TermsOfService => "terms_of_service",
        ConsentType::PrivacyPolicy => "privacy_policy",
        ConsentType::HealthDataSharing => "health_data_sharing",
        ConsentType::Cookies => "cookies",
    }
}

/// The payload both consent events carry: whose decision, about which kind
/// of consent and which version of the terms.
fn consent_payload(user_id: &UserId, user_label: &EventLabel, terms: &ConsentTerms) -> EventData {
    EventData::new()
        .reference("user", user_reference(user_id, user_label.as_str()))
        .field("consent_type", consent_type_text(terms.consent_type))
        .field("version", terms.version.as_str())
}

/// A person gave their consent, such as to the terms of service or to
/// marketing, for one version of the terms.
///
/// GDPR Article 7 asks for proof of when consent was given; the stored
/// record is that proof, and this is its entry in the audit trail. Consent
/// an OAuth client receives is `OAuthConsentGranted`.
#[derive(Debug)]
pub struct ConsentGranted {
    /// The person who consented.
    pub(crate) user_id: UserId,
    /// How the person is named in the entry, taken when they consented.
    pub(crate) user_label: EventLabel,
    /// What they consented to, and which version.
    pub(crate) terms: ConsentTerms,
    /// When they consented.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsentGranted => crate::types::event_type::IdentityEvent::ConsentGranted,
    fn payload(&self) -> EventData {
        consent_payload(&self.user_id, &self.user_label, &self.terms)
    }
}

/// A person's consent was withdrawn, by them or for them by staff they
/// asked. From now on what it allowed is no longer done with their data.
#[derive(Debug)]
pub struct ConsentRevoked {
    /// The person whose consent was withdrawn.
    pub(crate) user_id: UserId,
    /// How the person is named in the entry, taken when it was withdrawn.
    pub(crate) user_label: EventLabel,
    /// What was withdrawn, and which version of the terms it was given for.
    pub(crate) terms: ConsentTerms,
    /// When it was withdrawn.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConsentRevoked => crate::types::event_type::IdentityEvent::ConsentRevoked,
    fn payload(&self) -> EventData {
        consent_payload(&self.user_id, &self.user_label, &self.terms)
    }
}

/// A user asked for their data to be erased, under the right to be
/// forgotten.
#[derive(Debug)]
pub struct ErasureRequested {
    /// When deletion is due to start.
    pub(crate) scheduled_at: OffsetDateTime,
    /// When the user asked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ErasureRequested => crate::types::event_type::IdentityEvent::ErasureRequested,
    fn payload(&self) -> EventData {
        EventData::new().field("scheduled_at", self.scheduled_at.to_string())
    }
}

/// A user cancelled their erasure request before it was due to start.
#[derive(Debug)]
pub struct ErasureCancelled {
    /// When it was cancelled.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ErasureCancelled => crate::types::event_type::IdentityEvent::ErasureCancelled,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A legal hold paused a user's erasure request. It waits, past its grace
/// period, until the hold is lifted.
#[derive(Debug)]
pub struct ErasureHeld {
    /// When it was held.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ErasureHeld => crate::types::event_type::IdentityEvent::ErasureHeld,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A legal hold on a user's erasure request was lifted. The request waits
/// again, and is due at once if its grace period has passed.
#[derive(Debug)]
pub struct ErasureReleased {
    /// When it was released.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ErasureReleased => crate::types::event_type::IdentityEvent::ErasureReleased,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// Erasing a user's data started, after the waiting period ended.
#[derive(Debug)]
pub struct ErasureStarted {
    /// The user whose data is being deleted.
    pub(crate) user_id: UserId,
    /// The user's label, kept before the deletion removes it.
    pub(crate) user_label: EventLabel,
    /// When it started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ErasureStarted => crate::types::event_type::IdentityEvent::ErasureStarted,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.user_label.as_str()))
    }
}

/// All of a user's data was deleted for good.
#[derive(Debug)]
pub struct ErasureCompleted {
    /// The user whose data was deleted.
    pub(crate) user_id: UserId,
    /// The user's label, kept before the deletion removed it.
    pub(crate) user_label: EventLabel,
    /// When the erasure finished.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ErasureCompleted => crate::types::event_type::IdentityEvent::ErasureCompleted,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.user_label.as_str()))
    }
}

/// Erasing a user's data failed part way, so some of it may be gone.
///
/// The request moves to `Failed`, from which it can be started again.
#[derive(Debug)]
pub struct ErasureFailed {
    /// The user whose data was partly deleted.
    pub(crate) user_id: UserId,
    /// The user's label at the time of the failure.
    pub(crate) user_label: EventLabel,
    /// When it failed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ErasureFailed => crate::types::event_type::IdentityEvent::ErasureFailed,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.user_label.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::{FieldValue, Reference};
    use crate::shared::events::event::DomainEventCore;

    fn expect_reference(payload: &EventData, key: &str) -> Reference {
        let Some(FieldValue::Reference(reference)) = payload.value(key) else {
            panic!("expected a reference at {key}");
        };
        reference.clone()
    }

    /// The same published version for each kind of consent in this example.
    fn terms(consent_type: ConsentType) -> ConsentTerms {
        ConsentTerms {
            consent_type,
            version: crate::types::Label::new("version", "tos-2026-10").unwrap(),
        }
    }

    /// Erasure progress retains Ada's account id and label in the audit record.
    fn assert_erasure_account(event: &dyn DomainEventCore, user: UserId) {
        let kind = event.event_type();
        let reference = expect_reference(&event.payload(), "user");
        assert_eq!(reference.id(), user.to_string(), "{kind}");
        assert_eq!(reference.label(), "ada@acme.com", "{kind}");
    }

    /// Carol's data is erased. The completed event still refers to her by id
    /// and by the label "Carol (carol@example.com)", which the deletion
    /// removed everywhere else.
    #[test]
    fn erasure_completed_event_keeps_the_label_the_deletion_destroys() {
        let erased = UserId::new();
        let event = ErasureCompleted {
            user_id: erased,
            user_label: EventLabel::of("Carol (carol@example.com)"),
            occurred_at: crate::shared::clock::now(),
        };

        let reference = expect_reference(&event.payload(), "user");

        assert_eq!(reference.id(), erased.to_string());
        assert_eq!(reference.label(), "Carol (carol@example.com)");
    }

    /// Ann accepts terms of service "tos-2026-10" and later withdraws her
    /// marketing consent. Each record names her, the kind of consent and the
    /// version, and nothing of any OAuth client.
    #[test]
    fn the_consent_events_name_the_person_the_kind_and_the_version() {
        let ann = UserId::new();
        let granted = ConsentGranted {
            user_id: ann,
            user_label: EventLabel::of("ann@acme.com"),
            terms: terms(ConsentType::TermsOfService),
            occurred_at: crate::shared::clock::now(),
        };
        let revoked = ConsentRevoked {
            user_id: ann,
            user_label: EventLabel::of("ann@acme.com"),
            terms: terms(ConsentType::Marketing),
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(
            granted.payload().get("consent_type"),
            Some("terms_of_service")
        );
        assert_eq!(revoked.payload().get("consent_type"), Some("marketing"));
        for event in [&granted as &dyn DomainEventCore, &revoked] {
            let kind = event.event_type();
            let payload = event.payload();
            assert_eq!(payload.get("version"), Some("tos-2026-10"), "{kind}");
            assert_eq!(
                expect_reference(&payload, "user").id(),
                ann.to_string(),
                "{kind}"
            );
            assert_eq!(payload.get("client_id"), None, "{kind}");
        }
    }

    /// Ada asks for erasure due in 30 days. The request records that date.
    /// Cancelling has an empty payload. Starting and failing name her account
    /// with the label the deletion removes.
    #[test]
    fn the_erasure_events_carry_the_schedule_and_the_account() {
        let user = UserId::new();
        let scheduled_at = crate::shared::clock::now() + time::Duration::days(30);

        let requested = ErasureRequested {
            scheduled_at,
            occurred_at: crate::shared::clock::now(),
        };
        let cancelled = ErasureCancelled {
            occurred_at: crate::shared::clock::now(),
        };
        let started = ErasureStarted {
            user_id: user,
            user_label: EventLabel::of("ada@acme.com"),
            occurred_at: crate::shared::clock::now(),
        };
        let failed = ErasureFailed {
            user_id: user,
            user_label: EventLabel::of("ada@acme.com"),
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(
            requested.payload().get("scheduled_at"),
            Some(scheduled_at.to_string().as_str())
        );

        assert!(
            cancelled.payload().is_empty(),
            "the account is the actor; there is nothing else to record"
        );

        for event in [&started as &dyn DomainEventCore, &failed] {
            assert_erasure_account(event, user);
        }
    }
}
