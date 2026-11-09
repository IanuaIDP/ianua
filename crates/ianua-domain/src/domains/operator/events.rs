use time::OffsetDateTime;

use crate::domains::authentication::events::login::LoginFailureReason;
use crate::domains::scheduling::job_type::JobType;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{platform_event, tenant_event};
use crate::types::{
    Email, EventLabel, Fact, IpAddress, JobId, KeyPrefix, OperatorId, TenantId, Text,
    UntrustedText, UserId,
};

/// An operator was granted permission to impersonate a tenant user.
///
/// The grant is time-limited and requires a documented reason. It is filed
/// under the tenant the user is in.
#[derive(Debug)]
pub struct ImpersonationGranted {
    /// The user who will be impersonated.
    pub(crate) user_id: UserId,
    /// The impersonated user's human label, captured when the grant was made.
    pub(crate) user_label: EventLabel,
    /// Why the impersonation was granted, kept for audit.
    pub(crate) reason: Text,
    /// When the grant automatically expires.
    pub(crate) expires_at: OffsetDateTime,
    /// When the grant was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ImpersonationGranted => crate::types::event_type::OperatorEvent::ImpersonationGranted,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .field("reason", self.reason.to_string())
            .field("expires_at", self.expires_at.to_string())
    }
}

/// An impersonation grant was revoked before its expiry.
///
/// From now on the operator cannot act as the user. Listeners should end any
/// impersonation session still open. It is filed under the tenant the user
/// is in.
#[derive(Debug)]
pub struct ImpersonationRevoked {
    /// The user who was being impersonated.
    pub(crate) user_id: UserId,
    /// The impersonated user's human label, captured at revocation.
    pub(crate) user_label: EventLabel,
    /// When the revocation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ImpersonationRevoked => crate::types::event_type::OperatorEvent::ImpersonationRevoked,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "user",
            Reference::new(
                RefKind::USER,
                self.user_id.to_string(),
                self.user_label.as_str(),
            ),
        )
    }
}

/// A new operator account was created on the platform.
///
/// This is a platform event. It belongs to no tenant or organization.
#[derive(Debug)]
pub struct OperatorCreated {
    /// The newly created operator.
    pub(crate) operator_id: OperatorId,
    /// The operator's login email.
    pub(crate) email: Email,
    /// When the account was created.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    OperatorCreated => crate::types::event_type::OperatorEvent::OperatorCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "operator",
            Reference::new(
                RefKind::OPERATOR,
                self.operator_id.to_string(),
                self.email.to_string(),
            ),
        )
    }
}

/// An operator account was disabled.
///
/// The operator cannot sign in or act on the platform until re-enabled.
#[derive(Debug)]
pub struct OperatorDisabled {
    /// The disabled operator.
    pub(crate) operator_id: OperatorId,
    /// The operator's human label, captured when the account was disabled.
    pub(crate) operator_label: EventLabel,
    /// When the account was disabled.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    OperatorDisabled => crate::types::event_type::OperatorEvent::OperatorDisabled,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "operator",
            Reference::new(
                RefKind::OPERATOR,
                self.operator_id.to_string(),
                self.operator_label.as_str(),
            ),
        )
    }
}

/// A disabled operator account was re-enabled.
///
/// The operator can log in and perform platform actions again.
#[derive(Debug)]
pub struct OperatorEnabled {
    /// The re-enabled operator.
    pub(crate) operator_id: OperatorId,
    /// The operator's human label, captured when the account was re-enabled.
    pub(crate) operator_label: EventLabel,
    /// When the account was re-enabled.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    OperatorEnabled => crate::types::event_type::OperatorEvent::OperatorEnabled,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "operator",
            Reference::new(
                RefKind::OPERATOR,
                self.operator_id.to_string(),
                self.operator_label.as_str(),
            ),
        )
    }
}

/// An operator API key was created.
#[derive(Debug)]
pub struct OperatorApiKeyCreated {
    /// The operator who owns the key.
    pub(crate) operator_id: OperatorId,
    /// The owning operator's human label, captured when the key was created.
    pub(crate) operator_label: EventLabel,
    /// The key prefix for identification.
    pub(crate) key_prefix: KeyPrefix,
    /// When the key was created.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    OperatorApiKeyCreated => crate::types::event_type::OperatorEvent::OperatorApiKeyCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "operator",
                Reference::new(
                    RefKind::OPERATOR,
                    self.operator_id.to_string(),
                    self.operator_label.as_str(),
                ),
            )
            .field("key_prefix", self.key_prefix.as_str())
    }
}

/// Someone tried to sign in as an operator and was refused: an address no
/// operator holds, a wrong password, a disabled account, or a network
/// locked out of the account. One record shape for all four, so the trail
/// shows the guessing without the answer telling the guesser which.
#[derive(Debug)]
pub struct OperatorSignInFailed {
    /// The address the caller typed, recorded as typed and made safe to
    /// store, since it need not be a real address.
    pub(crate) email: UntrustedText,
    /// Why the sign-in was refused.
    pub(crate) reason: LoginFailureReason,
    /// The caller's address, if it could be told.
    pub(crate) ip_address: Fact<IpAddress>,
    /// When the attempt was refused.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    OperatorSignInFailed => crate::types::event_type::OperatorEvent::OperatorSignInFailed,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("email", self.email.to_string())
            .field("reason", self.reason.as_str())
            .optional(
                "ip_address",
                self.ip_address.known().map(ToString::to_string),
            )
    }
}

/// An operator API key was revoked.
#[derive(Debug)]
pub struct OperatorApiKeyRevoked {
    /// The operator whose key was revoked.
    pub(crate) operator_id: OperatorId,
    /// The owning operator's human label, captured when the key was revoked.
    pub(crate) operator_label: EventLabel,
    /// The key revoked, or `None` when every key of the operator was. Recorded
    /// as `*` in the event's payload.
    pub(crate) key_prefix: Option<KeyPrefix>,
    /// When the key was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    OperatorApiKeyRevoked => crate::types::event_type::OperatorEvent::OperatorApiKeyRevoked,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "operator",
                Reference::new(
                    RefKind::OPERATOR,
                    self.operator_id.to_string(),
                    self.operator_label.as_str(),
                ),
            )
            .field(
                "key_prefix",
                self.key_prefix.as_ref().map_or("*", KeyPrefix::as_str),
            )
    }
}

/// An operator gave a job that had used up its attempts one more attempt,
/// putting it back on the queue.
///
/// The record names the job by its id and kind, the tenant it works for
/// and how often it had run, never what it carries: its payload is the
/// handler's and may name what only its tenant should see.
#[derive(Debug)]
pub struct DeadJobRetried {
    /// The job put back on the queue.
    pub(crate) job_id: JobId,
    /// What kind of work it is, such as `mail.send`.
    pub(crate) job_type: JobType,
    /// The tenant it works for, or `None` for the platform's own work.
    pub(crate) tenant_id: Option<TenantId>,
    /// How many times it had run before the retry.
    pub(crate) attempts: u32,
    /// The operator who put it back.
    pub(crate) retried_by: OperatorId,
    /// When it was put back.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    DeadJobRetried => crate::types::event_type::OperatorEvent::DeadJobRetried,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("job_id", self.job_id.to_string())
            .field("job_type", self.job_type.as_str())
            .optional("tenant_id", self.tenant_id.map(|tenant| tenant.to_string()))
            .field("attempts", self.attempts.to_string())
            .field("retried_by", self.retried_by.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::{DomainEventCore, PlatformDomainEvent};

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn entity(payload: &EventData, key: &str) -> (RefKind, String, String) {
        match payload.value(key) {
            Some(FieldValue::Reference(reference)) => (
                reference.kind(),
                reference.id().to_owned(),
                reference.label().to_owned(),
            ),
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    fn text(payload: &EventData, key: &str) -> String {
        match payload.value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// An operator is granted two hours as Ada for ticket 12345. The event
    /// names Ada, the reason and the expiry, which an auditor checks the
    /// impersonation against.
    #[test]
    fn granting_impersonation_records_the_user_the_reason_and_the_expiry() {
        let user = UserId::new();
        let expires_at = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);

        let event = ImpersonationGranted {
            user_id: user,
            user_label: EventLabel::of("ada@acme.com"),
            reason: Text::new("reason", "Customer ticket #12345").unwrap(),
            expires_at,
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            entity(&payload, "user"),
            (RefKind::USER, user.to_string(), "ada@acme.com".to_owned())
        );
        assert_eq!(text(&payload, "reason"), "Customer ticket #12345");
        assert_eq!(text(&payload, "expires_at"), expires_at.to_string());
    }

    /// An operator's grant to act as Ada is revoked. The event names Ada by
    /// id and label.
    #[test]
    fn revoking_impersonation_names_the_user_it_was_over() {
        let user = UserId::new();

        let event = ImpersonationRevoked {
            user_id: user,
            user_label: EventLabel::of("ada@acme.com"),
            occurred_at: now(),
        };

        assert_eq!(
            entity(&event.payload(), "user"),
            (RefKind::USER, user.to_string(), "ada@acme.com".to_owned())
        );
    }

    /// An operator account is created, disabled and enabled. Each event names
    /// the operator, since operators belong to no tenant and nothing else
    /// says whose account changed.
    #[test]
    fn every_operator_account_event_names_the_operator() {
        let operator = OperatorId::new();
        let label = "root@ianua.dev";

        let events: Vec<Box<dyn PlatformDomainEvent>> = vec![
            Box::new(OperatorCreated {
                operator_id: operator,
                email: Email::new(label).unwrap(),
                occurred_at: now(),
            }),
            Box::new(OperatorDisabled {
                operator_id: operator,
                operator_label: EventLabel::of(label),
                occurred_at: now(),
            }),
            Box::new(OperatorEnabled {
                operator_id: operator,
                operator_label: EventLabel::of(label),
                occurred_at: now(),
            }),
        ];

        for event in events {
            let kind = event.event_type();
            assert_eq!(
                entity(&event.payload(), "operator"),
                (RefKind::OPERATOR, operator.to_string(), label.to_owned()),
                "{kind}"
            );
        }
    }

    /// An operator creates key `opk_abc`, then revokes all keys. Both events
    /// name the operator, and the prefix reads `opk_abc` and then `*`.
    #[test]
    fn the_operator_key_events_name_the_operator_and_the_key_prefix() {
        let operator = OperatorId::new();

        let created = OperatorApiKeyCreated {
            operator_id: operator,
            operator_label: EventLabel::of("root@ianua.dev"),
            key_prefix: KeyPrefix::new("opk_abc").unwrap(),
            occurred_at: now(),
        };
        let revoked_all = OperatorApiKeyRevoked {
            operator_id: operator,
            operator_label: EventLabel::of("root@ianua.dev"),
            key_prefix: None,
            occurred_at: now(),
        };

        let expected = (
            RefKind::OPERATOR,
            operator.to_string(),
            "root@ianua.dev".to_owned(),
        );
        assert_eq!(entity(&created.payload(), "operator"), expected);
        assert_eq!(text(&created.payload(), "key_prefix"), "opk_abc");

        assert_eq!(entity(&revoked_all.payload(), "operator"), expected);
        assert_eq!(text(&revoked_all.payload(), "key_prefix"), "*");
    }

    /// Bob retries Acme's mail that bounced twice. The record names the
    /// job, its kind, Acme, the two runs and Bob, and nothing else: the
    /// mail itself is never in it.
    #[test]
    fn a_retried_dead_job_is_named_without_its_contents() {
        let job = JobId::new();
        let acme = TenantId::new();
        let bob = OperatorId::new();

        let retried = DeadJobRetried {
            job_id: job,
            job_type: JobType::new("mail.send").unwrap(),
            tenant_id: Some(acme),
            attempts: 2,
            retried_by: bob,
            occurred_at: now(),
        };

        let payload = retried.payload();
        assert_eq!(text(&payload, "job_id"), job.to_string());
        assert_eq!(text(&payload, "job_type"), "mail.send");
        assert_eq!(text(&payload, "tenant_id"), acme.to_string());
        assert_eq!(text(&payload, "attempts"), "2");
        assert_eq!(text(&payload, "retried_by"), bob.to_string());
        assert_eq!(payload.fields().len(), 5);
    }
}
