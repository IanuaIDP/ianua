//! Log target bodies: the places a tenant ships its request records to.
//!
//! A target's credential is taken once and never answered: a target read
//! back says only whether it holds one.

use ianua_app::use_cases::proxy::log_shipping::{
    ChangeLogTargetRequest, CreateLogTargetRequest, CredentialChange, CredentialState,
    LogTargetView,
};
use ianua_domain::domains::proxy::log_shipping::{
    LogDestination, LogFormat, LogTargetStatus, ShippedRecords,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Label, LogShippingTargetId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// Request body for creating a log shipping target.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateLogTargetBody {
    /// Its name, unique within the tenant.
    pub name: String,
    /// Where records go: `{"https": "<url>"}` for a collector,
    /// `{"bucket": {"endpoint": "<url>", "region": "<region>", "bucket":
    /// "<name>"}}` for an object store, or `{"datadog": "<site>"}` such as
    /// `eu1`. Every address must be public HTTPS. A bucket's region is the
    /// one its requests are signed for, such as `eu-central-1`, or `auto`
    /// for Cloudflare R2 and Google Cloud Storage.
    #[schema(value_type = Object)]
    pub destination: LogDestination,
    /// What the destination signs in with. For a collector, the whole
    /// `Authorization` value, such as `Bearer <token>` or `Splunk <token>`;
    /// for a bucket, `ACCESS_KEY_ID:SECRET`; for Datadog, its API key.
    /// Required for a bucket and Datadog. Kept sealed and never shown again.
    #[serde(default)]
    pub credential: Option<String>,
    /// Which records are sent: `all` (the default), `denied_only`, or
    /// `{"sampled": <1-100>}`, which sends every refusal and that share of
    /// the rest.
    #[serde(default = "every_record")]
    #[schema(value_type = Object)]
    pub records: ShippedRecords,
    /// The shape each record is written in: `json_lines` (the default) or
    /// `open_telemetry`.
    #[serde(default = "json_lines")]
    #[schema(schema_with = crate::dto::schemas::log_format)]
    pub format: LogFormat,
}

/// A new target ships every record unless it says otherwise.
fn every_record() -> ShippedRecords {
    ShippedRecords::All
}

/// A new target writes JSON lines unless it says otherwise.
fn json_lines() -> LogFormat {
    LogFormat::JsonLines
}

impl TryFrom<CreateLogTargetBody> for CreateLogTargetRequest {
    type Error = ApiError;

    fn try_from(body: CreateLogTargetBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: target_name(body.name)?,
            destination: body.destination,
            credential: body.credential.map(Secret::new),
            records: body.records,
            format: body.format,
        })
    }
}

/// Request body for changing a log shipping target. Where, what and how it
/// ships are given whole; the name and the credential may be left out to
/// keep them.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeLogTargetBody {
    /// Its new name; left out keeps it.
    #[serde(default)]
    pub name: Option<String>,
    /// Where records go from now on, in the shape a create takes.
    #[schema(value_type = Object)]
    pub destination: LogDestination,
    /// Its credential: left out keeps the one it has, `null` ships without
    /// one from now on, and a value replaces it.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    #[schema(value_type = Option<String>)]
    pub credential: Option<Option<String>>,
    /// Which records are sent from now on.
    #[schema(value_type = Object)]
    pub records: ShippedRecords,
    /// The shape each record is written in from now on.
    #[schema(schema_with = crate::dto::schemas::log_format)]
    pub format: LogFormat,
}

impl ChangeLogTargetBody {
    /// The change this body asks of `target`.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] for a name that is not a valid one.
    pub(crate) fn into_request(
        self,
        target: LogShippingTargetId,
    ) -> Result<ChangeLogTargetRequest, ApiError> {
        Ok(ChangeLogTargetRequest {
            target_id: target,
            name: self.name.map(target_name).transpose()?,
            destination: self.destination,
            credential: credential_change(self.credential),
            records: self.records,
            format: self.format,
        })
    }
}

/// What a change does to the credential, from the three wire states.
fn credential_change(field: Option<Option<String>>) -> CredentialChange {
    match field {
        None => CredentialChange::Keep,
        Some(None) => CredentialChange::Remove,
        Some(Some(secret)) => CredentialChange::Replace(Secret::new(secret)),
    }
}

/// Reads a target's name.
fn target_name(name: String) -> Result<Label, ApiError> {
    Label::new("name", name).map_err(ApiError::validation)
}

/// A log shipping target, without its credential.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LogTargetResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The label administrators use to distinguish this shipping destination.
    pub name: String,
    /// Where records go.
    #[schema(value_type = Object)]
    pub destination: LogDestination,
    /// Whether it ships with a credential. The credential itself is never
    /// shown.
    pub has_credential: bool,
    /// Which records are sent.
    #[schema(value_type = Object)]
    pub records: ShippedRecords,
    /// The shape each record is written in.
    #[schema(schema_with = crate::dto::schemas::log_format)]
    pub format: LogFormat,
    /// `Active` or `Paused`.
    #[schema(schema_with = crate::dto::schemas::log_target_status)]
    pub status: LogTargetStatus,
    /// When it was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<LogTargetView> for LogTargetResponse {
    fn from(view: LogTargetView) -> Self {
        Self {
            id: *view.id.as_uuid(),
            name: view.name.as_str().to_owned(),
            destination: view.destination,
            has_credential: view.credential == CredentialState::Set,
            records: view.records,
            format: view.format,
            status: view.status,
            created_at: view.created_at,
            updated_at: view.updated_at,
        }
    }
}
