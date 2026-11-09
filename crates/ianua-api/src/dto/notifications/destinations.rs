//! Destination bodies: a place outside the app an organization's
//! notifications are posted to, as typed and as read back.

use ianua_app::use_cases::notifications::destinations::endpoint::{
    DestinationSettings, DestinationTarget, SigningSecret,
};
use ianua_app::use_cases::notifications::destinations::{AddedDestination, ReconfigureRequest};
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::destination::NotificationDestination;
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::types::{Label, NotificationDestinationId, PublicHttpsUrl};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ApiError;

/// A destination to add, or the whole of one to change. A Slack or Teams
/// address is itself the key that posts to the channel, so the body has
/// no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DestinationBody {
    /// What the organization calls it, such as "On-call Slack".
    pub name: String,
    /// Where it posts, by `kind`.
    pub target: DestinationTargetBody,
    /// The categories it receives, such as `Identity`; at least one, each
    /// once.
    #[schema(schema_with = crate::dto::schemas::notification_category_list)]
    pub categories: Vec<NotificationCategory>,
    /// The least severity it receives: `Info`, `Warning` or `Critical`.
    #[schema(schema_with = crate::dto::schemas::notification_severity)]
    pub minimum_severity: NotificationSeverity,
}

/// Where a destination posts, by `kind`.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum DestinationTargetBody {
    /// A Slack channel, through its incoming-webhook address on Slack's
    /// own host.
    Slack {
        /// The incoming-webhook address.
        url: String,
    },
    /// A Microsoft Teams channel, through its webhook address on
    /// Microsoft's own hosts.
    Teams {
        /// The webhook address.
        url: String,
    },
    /// A public HTTPS endpoint of the organization's own; its posts are
    /// signed with a secret shown once.
    Webhook {
        /// The endpoint.
        url: String,
    },
}

impl TryFrom<DestinationBody> for DestinationSettings {
    type Error = ApiError;

    fn try_from(body: DestinationBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            target: body.target.try_into()?,
            categories: body.categories,
            minimum: body.minimum_severity,
        })
    }
}

impl DestinationBody {
    /// The change this body makes to the destination `destination_id`.
    ///
    /// # Errors
    ///
    /// A validation error for a name or address that is not a valid one.
    pub(crate) fn into_reconfigure(
        self,
        destination_id: NotificationDestinationId,
    ) -> Result<ReconfigureRequest, ApiError> {
        Ok(ReconfigureRequest {
            destination_id,
            settings: self.try_into()?,
        })
    }
}

impl TryFrom<DestinationTargetBody> for DestinationTarget {
    type Error = ApiError;

    fn try_from(body: DestinationTargetBody) -> Result<Self, Self::Error> {
        match body {
            DestinationTargetBody::Slack { url } => public_url(url).map(Self::Slack),
            DestinationTargetBody::Teams { url } => public_url(url).map(Self::Teams),
            DestinationTargetBody::Webhook { url } => public_url(url).map(Self::Webhook),
        }
    }
}

/// `url` as a public HTTPS address.
fn public_url(url: String) -> Result<PublicHttpsUrl, ApiError> {
    PublicHttpsUrl::new(url).map_err(ApiError::validation)
}

/// A destination just added. A webhook's signing secret is shown this
/// once.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DestinationAddedResponse {
    /// The destination's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: NotificationDestinationId,
    /// The secret a webhook's posts are signed with, or `null` for Slack
    /// and Teams, whose address carries its own key. It is never shown
    /// again.
    pub signing_secret: Option<String>,
}

impl From<AddedDestination> for DestinationAddedResponse {
    fn from(added: AddedDestination) -> Self {
        Self {
            id: added.id,
            signing_secret: shown(&added.signing_secret),
        }
    }
}

/// A destination just changed. A webhook gets a new signing secret,
/// shown this once.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DestinationChangedResponse {
    /// The webhook's new signing secret, or `null` for Slack and Teams. It
    /// is never shown again.
    pub signing_secret: Option<String>,
}

impl From<SigningSecret> for DestinationChangedResponse {
    fn from(secret: SigningSecret) -> Self {
        Self {
            signing_secret: shown(&secret),
        }
    }
}

/// The raw signing secret, when there is one to show.
fn shown(secret: &SigningSecret) -> Option<String> {
    match secret {
        SigningSecret::NotSigned => None,
        SigningSecret::Shown(raw) => Some(raw.expose().to_owned()),
    }
}

/// An organization's destination as read back. Its address and secret are
/// never shown.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DestinationResponse {
    /// The destination's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: NotificationDestinationId,
    /// What the organization calls it.
    pub name: String,
    /// `slack`, `teams` or `webhook`.
    pub kind: &'static str,
    /// The categories it receives.
    #[schema(schema_with = crate::dto::schemas::notification_category_list)]
    pub categories: Vec<NotificationCategory>,
    /// The least severity it receives.
    #[schema(schema_with = crate::dto::schemas::notification_severity)]
    pub minimum_severity: NotificationSeverity,
    /// `active` or `paused`.
    pub state: &'static str,
    /// When it was added.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<&NotificationDestination> for DestinationResponse {
    fn from(destination: &NotificationDestination) -> Self {
        Self {
            id: *destination.id(),
            name: destination.name().as_str().to_owned(),
            kind: destination.endpoint().kind().as_str(),
            categories: destination.filter().categories().to_vec(),
            minimum_severity: destination.filter().minimum(),
            state: destination.state().as_str(),
            created_at: destination.created_at(),
            updated_at: destination.updated_at(),
        }
    }
}
