//! A destination as its row holds it: read back into the aggregate, and
//! written out from it. A Slack or Teams address and a webhook's signing
//! secret are kept sealed, as they came; the store never opens them.

use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::destination::{
    DestinationEndpointRow, DestinationKind, EndpointDelivery, NotificationDestination,
    NotificationDestinationRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    Label, NotificationDestinationId, OrganizationId, PublicHttpsUrl, SealedSecret,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const DESTINATION: Stored = Stored("notification destination");

/// A destination as it is read. The store's checked queries fill it.
pub(super) struct DestinationRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) hook: Option<String>,
    pub(super) url: Option<String>,
    pub(super) signing_secret: Option<String>,
    pub(super) categories: Vec<String>,
    pub(super) minimum_severity: String,
    pub(super) state: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

/// Where a destination posts, as its columns hold it.
struct EndpointColumns {
    kind: DestinationKind,
    hook: Option<String>,
    url: Option<String>,
    signing_secret: Option<String>,
}

impl DestinationRecord {
    /// The destination the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, the endpoint's columns do not fit its
    /// kind, or the row breaks a rule the destination keeps.
    pub(super) fn into_destination(self) -> Result<NotificationDestination, DomainError> {
        let endpoint = endpoint_from(EndpointColumns {
            kind: DESTINATION.choice(&self.kind)?,
            hook: self.hook,
            url: self.url,
            signing_secret: self.signing_secret,
        })?;
        NotificationDestination::reconstitute(NotificationDestinationRow {
            id: NotificationDestinationId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            name: DESTINATION.value("name", Label::new("name", self.name))?,
            endpoint,
            categories: categories_of(&self.categories)?,
            minimum_severity: DESTINATION.choice(&self.minimum_severity)?,
            state: DESTINATION.choice(&self.state)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The endpoint `columns` hold: a sealed address for Slack and Teams, an
/// address and a sealed secret for a webhook, and nothing else beside.
fn endpoint_from(columns: EndpointColumns) -> Result<DestinationEndpointRow, DomainError> {
    match (
        columns.kind,
        columns.hook,
        columns.url,
        columns.signing_secret,
    ) {
        (DestinationKind::Slack, Some(hook), None, None) => Ok(DestinationEndpointRow::Slack {
            hook: sealed("Slack address", hook)?,
        }),
        (DestinationKind::Teams, Some(hook), None, None) => Ok(DestinationEndpointRow::Teams {
            hook: sealed("Teams address", hook)?,
        }),
        (DestinationKind::Webhook, None, Some(url), Some(secret)) => {
            Ok(DestinationEndpointRow::Webhook {
                url: DESTINATION.value("webhook address", PublicHttpsUrl::new(url))?,
                signing_secret: sealed("signing secret", secret)?,
            })
        }
        _ => Err(DomainError::corrupt_row(
            DESTINATION.0,
            "an endpoint whose columns do not fit its kind",
        )),
    }
}

/// A sealed value read back through its own rules.
fn sealed(what: &'static str, stored: String) -> Result<SealedSecret, DomainError> {
    DESTINATION.value(what, SealedSecret::new(stored))
}

/// The categories `words` name.
fn categories_of(words: &[String]) -> Result<Vec<NotificationCategory>, DomainError> {
    words.iter().map(|word| DESTINATION.choice(word)).collect()
}

/// A destination's columns, as they are written.
pub(super) struct DestinationColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) organization_id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) kind: &'static str,
    pub(super) hook: Option<&'a str>,
    pub(super) url: Option<&'a str>,
    pub(super) signing_secret: Option<&'a str>,
    pub(super) categories: Vec<String>,
    pub(super) minimum_severity: &'static str,
    pub(super) state: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> DestinationColumns<'a> {
    /// The columns `destination` is written to.
    pub(super) fn of(destination: &'a NotificationDestination) -> Self {
        let endpoint = destination.endpoint();
        let (hook, url, signing_secret) = match endpoint.delivery() {
            EndpointDelivery::Slack(hook) | EndpointDelivery::Teams(hook) => {
                (Some(hook.as_str()), None, None)
            }
            EndpointDelivery::Webhook {
                url,
                signing_secret,
            } => (None, Some(url.as_str()), Some(signing_secret.as_str())),
        };
        let filter = destination.filter();
        Self {
            id: destination.id().as_uuid(),
            organization_id: destination.organization_id().as_uuid(),
            name: destination.name().as_str(),
            kind: endpoint.kind().word(),
            hook,
            url,
            signing_secret,
            categories: filter
                .categories()
                .iter()
                .map(|category| category.word().to_owned())
                .collect(),
            minimum_severity: filter.minimum().word(),
            state: destination.state().word(),
            created_at: destination.created_at(),
            updated_at: destination.updated_at(),
        }
    }
}
