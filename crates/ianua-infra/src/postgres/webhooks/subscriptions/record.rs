//! A webhook subscription as its row holds it: read back into the
//! aggregate, and written out from it. Its signing secrets are kept as the
//! sealer handed them over.

use ianua_domain::domains::webhooks::subscription::{WebhookSubscription, WebhookSubscriptionRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EventType, PublicHttpsUrl, SealedSecret, Text, WebhookSubscriptionId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{kind_word, principal_from};
use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::messaging::signing::{previous_columns, previous_from};

const WEBHOOK: Stored = Stored("webhook subscription");

/// A webhook as it is read. The store's checked queries fill it.
pub(super) struct WebhookRecord {
    pub(super) id: Uuid,
    pub(super) url: String,
    pub(super) signing_secret_sealed: String,
    pub(super) previous_secret_sealed: Option<String>,
    pub(super) previous_secret_until: Option<OffsetDateTime>,
    pub(super) event_types: Vec<String>,
    pub(super) status: String,
    pub(super) description: Option<String>,
    pub(super) retry: String,
    pub(super) created_by_kind: String,
    pub(super) created_by_id: Uuid,
    pub(super) consecutive_failures: i64,
    pub(super) last_delivered_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl WebhookRecord {
    /// The webhook the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word or an event type is unknown, or the row breaks a
    /// rule the webhook keeps.
    pub(super) fn into_webhook(self) -> Result<WebhookSubscription<ResolvedTenant>, DomainError> {
        let event_types = event_types_from(&self.event_types)?;
        WebhookSubscription::reconstitute(WebhookSubscriptionRow {
            id: WebhookSubscriptionId::from_uuid(self.id),
            url: WEBHOOK.value("url", PublicHttpsUrl::new(self.url))?,
            signing_secret: WEBHOOK.value(
                "signing secret",
                SealedSecret::new(self.signing_secret_sealed),
            )?,
            previous_secret: previous_from(
                WEBHOOK,
                self.previous_secret_sealed,
                self.previous_secret_until,
            )?,
            event_types,
            status: WEBHOOK.choice(&self.status)?,
            description: self
                .description
                .map(|text| WEBHOOK.value("description", Text::new("description", text)))
                .transpose()?,
            retry: WEBHOOK.choice(&self.retry)?,
            created_by: principal_from(WEBHOOK, &self.created_by_kind, self.created_by_id)?,
            consecutive_failures: u32::try_from(self.consecutive_failures)
                .map_err(|_| DomainError::corrupt_row(WEBHOOK.0, "a failure count out of range"))?,
            last_delivered_at: self.last_delivered_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Validates every stored subscription event before reconstructing the webhook.
fn event_types_from(values: &[String]) -> Result<Vec<EventType>, DomainError> {
    values
        .iter()
        .map(|text| event_type_from(WEBHOOK, text))
        .collect()
}

/// The event type `text` names, as a column of a row of `entity` holds it.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when no event has that type.
pub(super) fn event_type_from(entity: Stored, text: &str) -> Result<EventType, DomainError> {
    EventType::parse(text)
        .ok_or_else(|| DomainError::corrupt_row(entity.0, "an unknown event type"))
}

/// A webhook's columns, as they are written.
pub(super) struct WebhookColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) url: &'a str,
    pub(super) signing_secret_sealed: &'a str,
    pub(super) previous_secret_sealed: Option<&'a str>,
    pub(super) previous_secret_until: Option<OffsetDateTime>,
    pub(super) event_types: Vec<String>,
    pub(super) status: &'static str,
    pub(super) description: Option<&'a str>,
    pub(super) retry: &'static str,
    pub(super) created_by_kind: &'static str,
    pub(super) created_by_id: Uuid,
    pub(super) consecutive_failures: i64,
    pub(super) last_delivered_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> WebhookColumns<'a> {
    /// The columns `webhook` is written to.
    pub(super) fn of(webhook: &'a WebhookSubscription<ResolvedTenant>) -> Self {
        let (previous_secret_sealed, previous_secret_until) =
            previous_columns(webhook.previous_secret());
        Self {
            id: webhook.id().as_uuid(),
            url: webhook.url().as_str(),
            signing_secret_sealed: webhook.signing_secret().as_str(),
            previous_secret_sealed,
            previous_secret_until,
            event_types: webhook
                .event_types()
                .iter()
                .map(|event| event.as_str().to_owned())
                .collect(),
            status: webhook.status().word(),
            description: webhook.description().map(Text::as_str),
            retry: webhook.retry().word(),
            created_by_kind: kind_word(webhook.created_by()),
            created_by_id: webhook.created_by().id(),
            consecutive_failures: i64::from(webhook.consecutive_failures()),
            last_delivered_at: webhook.last_delivered_at(),
            created_at: webhook.created_at(),
            updated_at: webhook.updated_at(),
        }
    }
}
