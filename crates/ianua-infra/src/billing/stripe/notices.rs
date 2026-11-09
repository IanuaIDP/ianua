//! What a verified Stripe event reports, read as the platform's payment
//! notice.
//!
//! Three events are acted on, each carrying the organization in the
//! metadata of the object it is about, which the platform wrote there:
//!
//! - `setup_intent.succeeded`: a checkout saved a payment method, written
//!   into the setup intent's metadata when the checkout was opened;
//! - `invoice.payment_failed`: a charge failed;
//! - `invoice.paid`: what was owed is paid.
//!
//! Every other event is acknowledged and changes nothing.
//!
//! Each notice also carries the event's id and the moment Stripe created
//! it. Stripe delivers an event again whenever an answer is lost, and in
//! no set order, so the id tells a repeat from a new event and the moment
//! tells a late event from a newer one.

use std::collections::HashMap;

use ianua_app::ports::organization::{PaymentEvent, PaymentNotice, ReceivedNotice};
use ianua_domain::domains::organization::billing::payment::{PaymentEventId, PaymentReference};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

/// The metadata key every object the platform makes carries its
/// organization under.
pub(crate) const ORGANIZATION_KEY: &str = "organization_id";

/// A Stripe event, as much of it as is read.
#[derive(Deserialize)]
struct Event {
    id: String,
    created: i64,
    #[serde(rename = "type")]
    kind: String,
    data: EventData,
}

#[derive(Deserialize)]
struct EventData {
    object: EventObject,
}

/// The object an event is about: a setup intent or an invoice.
#[derive(Deserialize)]
struct EventObject {
    #[serde(default)]
    metadata: HashMap<String, String>,
    #[serde(default)]
    payment_method: Option<Value>,
}

/// The event the platform acts on, by its type.
enum Acted {
    MethodSaved,
    ChargeFailed,
    Paid,
}

impl Acted {
    fn of(kind: &str) -> Option<Self> {
        match kind {
            "setup_intent.succeeded" => Some(Self::MethodSaved),
            "invoice.payment_failed" => Some(Self::ChargeFailed),
            "invoice.paid" => Some(Self::Paid),
            _ => None,
        }
    }
}

/// The notice `payload`, a verified event body, delivers: the event, and
/// what it reports.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the body is not an event, names
/// no id or a creation time out of range, or an event acted on names no
/// organization or no payment method.
pub(crate) fn notice_of(payload: &[u8]) -> Result<ReceivedNotice, DomainError> {
    let event: Event = serde_json::from_slice(payload).map_err(|_| {
        DomainError::invalid(message!(
            "infra-the-notice-is-not-a-payment",
            "the notice is not a payment provider event"
        ))
    })?;
    Ok(ReceivedNotice {
        event: event_of(&event)?,
        report: report_of(event)?,
    })
}

/// The event's id and the moment Stripe created it.
fn event_of(event: &Event) -> Result<PaymentEvent, DomainError> {
    let created_at = OffsetDateTime::from_unix_timestamp(event.created).map_err(|_| {
        DomainError::invalid(message!(
            "infra-the-notice-s-creation-time-is",
            "the notice's creation time is out of range"
        ))
    })?;
    Ok(PaymentEvent {
        id: PaymentEventId::new(event.id.as_str()).map_err(DomainError::from)?,
        created_at,
    })
}

/// What `event` reports.
fn report_of(event: Event) -> Result<PaymentNotice, DomainError> {
    let Some(acted) = Acted::of(&event.kind) else {
        return Ok(PaymentNotice::Ignored);
    };
    let object = event.data.object;
    let organization_id = organization_of(&object)?;
    match acted {
        Acted::MethodSaved => Ok(PaymentNotice::MethodRecorded {
            organization_id,
            reference: method_of(&object)?,
        }),
        Acted::ChargeFailed => Ok(PaymentNotice::PaymentFailed { organization_id }),
        Acted::Paid => Ok(PaymentNotice::PaymentSettled { organization_id }),
    }
}

/// The organization `object`'s metadata names.
fn organization_of(object: &EventObject) -> Result<OrganizationId, DomainError> {
    object
        .metadata
        .get(ORGANIZATION_KEY)
        .and_then(|id| Uuid::parse_str(id).ok())
        .map(OrganizationId::from_uuid)
        .ok_or_else(|| {
            DomainError::invalid(message!(
                "infra-the-notice-names-no-organization-the",
                "the notice names no organization the platform made"
            ))
        })
}

/// The payment method a setup intent saved: its id, written as a string
/// or as the expanded object.
fn method_of(object: &EventObject) -> Result<PaymentReference, DomainError> {
    let id = object.payment_method.as_ref().and_then(|method| {
        method
            .as_str()
            .or_else(|| method.get("id").and_then(Value::as_str))
    });
    let Some(id) = id else {
        return Err(DomainError::invalid(message!(
            "infra-the-notice-names-no-payment-method",
            "the notice names no payment method"
        )));
    };
    PaymentReference::new(id).map_err(DomainError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACME: &str = "0190f1a2-7b3c-7d4e-8f50-61728394a5b6";

    fn event(kind: &str, object: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": "evt_1",
            "created": 1_700_000_000,
            "type": kind,
            "data": { "object": object }
        }))
        .unwrap()
    }

    /// What `body` reports, without the event it came as.
    fn report(body: &[u8]) -> Result<PaymentNotice, DomainError> {
        notice_of(body).map(|notice| notice.report)
    }

    fn acme() -> OrganizationId {
        OrganizationId::from_uuid(Uuid::parse_str(ACME).unwrap())
    }

    /// A setup intent that succeeded reports the method it saved for the
    /// organization in its metadata.
    #[test]
    fn a_saved_method_is_recorded_for_its_organization() {
        let body = event(
            "setup_intent.succeeded",
            &serde_json::json!({"payment_method": "pm_1NvXyz", "metadata": {"organization_id": ACME}}),
        );

        let notice = report(&body).unwrap();

        assert_eq!(
            notice,
            PaymentNotice::MethodRecorded {
                organization_id: acme(),
                reference: PaymentReference::new("pm_1NvXyz").unwrap(),
            }
        );
    }

    /// A method given as the expanded object is read by its id.
    #[test]
    fn an_expanded_method_is_read_by_its_id() {
        let body = event(
            "setup_intent.succeeded",
            &serde_json::json!({"payment_method": {"id": "pm_2"}, "metadata": {"organization_id": ACME}}),
        );

        let notice = report(&body).unwrap();

        assert!(matches!(notice, PaymentNotice::MethodRecorded { .. }));
    }

    /// A failed invoice and a paid one report a failure and a settlement.
    #[test]
    fn invoices_report_failure_and_settlement() {
        let metadata = serde_json::json!({"metadata": {"organization_id": ACME}});

        let failed = report(&event("invoice.payment_failed", &metadata)).unwrap();
        let paid = report(&event("invoice.paid", &metadata)).unwrap();

        assert_eq!(
            failed,
            PaymentNotice::PaymentFailed {
                organization_id: acme()
            }
        );
        assert_eq!(
            paid,
            PaymentNotice::PaymentSettled {
                organization_id: acme()
            }
        );
    }

    /// An event the platform does not act on is acknowledged and ignored,
    /// whatever it carries.
    #[test]
    fn another_event_is_ignored() {
        let notice = report(&event("customer.created", &serde_json::json!({}))).unwrap();

        assert_eq!(notice, PaymentNotice::Ignored);
    }

    /// Parsing a payment notice preserves its event id and creation timestamp
    /// for downstream duplicate and ordering checks.
    #[test]
    fn a_notice_carries_its_event_id_and_creation_time() {
        let body = event(
            "invoice.paid",
            &serde_json::json!({"metadata": {"organization_id": ACME}}),
        );

        let notice = notice_of(&body).unwrap();

        assert_eq!(notice.event.id.as_str(), "evt_1");
        assert_eq!(notice.event.created_at.unix_timestamp(), 1_700_000_000);
    }

    /// An invoice notice missing its event id fails validation.
    #[test]
    fn a_notice_without_an_event_id_is_refused() {
        let body = br#"{"created":1700000000,"type":"invoice.paid","data":{"object":{}}}"#;

        assert!(matches!(notice_of(body), Err(DomainError::Validation(_))));
    }

    /// An invoice-paid notice fails validation when its organization id is missing or malformed.
    #[test]
    fn an_event_naming_no_organization_is_refused() {
        let unnamed = notice_of(&event("invoice.paid", &serde_json::json!({})));
        let malformed = notice_of(&event(
            "invoice.paid",
            &serde_json::json!({"metadata": {"organization_id": "acme"}}),
        ));

        assert!(matches!(unnamed, Err(DomainError::Validation(_))));
        assert!(matches!(malformed, Err(DomainError::Validation(_))));
    }

    /// A setup intent naming no payment method is refused.
    #[test]
    fn a_saved_method_without_its_id_is_refused() {
        let body = event(
            "setup_intent.succeeded",
            &serde_json::json!({"payment_method": null, "metadata": {"organization_id": ACME}}),
        );

        assert!(matches!(notice_of(&body), Err(DomainError::Validation(_))));
    }

    /// Non-JSON webhook bytes fail payment-event validation.
    #[test]
    fn a_body_that_is_not_an_event_is_refused() {
        assert!(matches!(
            notice_of(b"not json"),
            Err(DomainError::Validation(_))
        ));
    }
}
