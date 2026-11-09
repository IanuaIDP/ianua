//! Consumer bodies: a machine identity, the credential it signs in with,
//! its quota, and the changes made to it.

use ianua_app::use_cases::consumers::{
    ChangeClearanceRequest, ChangeCredentialExpiryRequest, ChangeQuotaRequest, CreateRequest,
    CreateResult, DescribeRequest, NewCredential, RenameRequest, RotateCredentialRequest,
    RotatedCredential,
};
use ianua_domain::domains::consumers::consumer::{Consumer, ConsumerStatus};
use ianua_domain::domains::consumers::credentials::PreviousCredential;
use ianua_domain::domains::consumers::quota::{ConsumerQuota, QuotaPeriod, RequestAllowance};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{
    CertificateFingerprint, ConsumerId, Expiry, FederatedSubject, HttpsUrl, Issuer, Label,
    Lifetime, RotationOverlap, Setting,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// The credential a consumer signs in with, as a create or rotate body
/// names it.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "credential_kind", rename_all = "snake_case")]
pub(crate) enum CredentialBody {
    /// An API key the platform makes. The answer carries it once as
    /// `api_key`; only its prefix and a keyed digest are kept.
    ApiKey,
    /// An X.509 client certificate, known by its fingerprint.
    ClientCert {
        /// Hex-encoded SHA-256 fingerprint.
        fingerprint: String,
    },
    /// A JWT the consumer signs itself, with a known issuer and subject.
    JwtBearer {
        /// The expected `iss` claim. Never the tenant's own issuer.
        issuer: String,
        /// The expected `sub` claim.
        subject: String,
        /// Where the consumer publishes the keys its tokens are signed with.
        jwks_uri: String,
    },
}

impl TryFrom<CredentialBody> for NewCredential {
    type Error = ApiError;

    fn try_from(body: CredentialBody) -> Result<Self, Self::Error> {
        match body {
            CredentialBody::ApiKey => Ok(Self::ApiKey),
            CredentialBody::ClientCert { fingerprint } => Ok(Self::ClientCert {
                fingerprint: CertificateFingerprint::parse(&fingerprint)
                    .map_err(ApiError::validation)?,
            }),
            CredentialBody::JwtBearer {
                issuer,
                subject,
                jwks_uri,
            } => Ok(Self::JwtBearer {
                issuer: Issuer::new(issuer).map_err(ApiError::validation)?,
                subject: FederatedSubject::new(subject).map_err(ApiError::validation)?,
                jwks_uri: HttpsUrl::new(jwks_uri).map_err(ApiError::validation)?,
            }),
        }
    }
}

/// The period a quota is counted over.
#[derive(Clone, Copy, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QuotaPeriodBody {
    /// A calendar minute.
    Minute,
    /// A calendar hour.
    Hour,
    /// A calendar day, in UTC.
    Day,
    /// A calendar month, in UTC.
    Month,
}

impl From<QuotaPeriodBody> for QuotaPeriod {
    fn from(body: QuotaPeriodBody) -> Self {
        match body {
            QuotaPeriodBody::Minute => Self::Minute,
            QuotaPeriodBody::Hour => Self::Hour,
            QuotaPeriodBody::Day => Self::Day,
            QuotaPeriodBody::Month => Self::Month,
        }
    }
}

impl From<QuotaPeriod> for QuotaPeriodBody {
    fn from(period: QuotaPeriod) -> Self {
        match period {
            QuotaPeriod::Minute => Self::Minute,
            QuotaPeriod::Hour => Self::Hour,
            QuotaPeriod::Day => Self::Day,
            QuotaPeriod::Month => Self::Month,
        }
    }
}

/// A consumer's own allowance: at most `requests` per `per`.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct QuotaBody {
    /// The most requests allowed in one period, from 1 to 1 000 000 000.
    pub requests: u64,
    /// The period they are counted over: `minute`, `hour`, `day` or
    /// `month` (calendar periods, in UTC).
    pub per: QuotaPeriodBody,
}

/// The quota `body` names, or none when it is left out or `null`.
pub(crate) fn quota(body: Option<QuotaBody>) -> Result<ConsumerQuota, ApiError> {
    let Some(body) = body else {
        return Ok(ConsumerQuota::Unlimited);
    };
    RequestAllowance::new(body.requests, body.per.into())
        .map(ConsumerQuota::Limited)
        .map_err(ApiError::validation)
}

/// When a credential stops working: never, when no instant is given.
pub(crate) fn expiry(expires_at: Option<OffsetDateTime>) -> Expiry {
    expires_at.map_or(Expiry::Never, Expiry::At)
}

/// How long a replaced credential keeps working: not at all, when no
/// length is given.
fn overlap(seconds: Option<i64>) -> Result<RotationOverlap, ApiError> {
    let Some(seconds) = seconds else {
        return Ok(RotationOverlap::Immediate);
    };
    Lifetime::seconds(seconds)
        .map(RotationOverlap::For)
        .map_err(ApiError::validation)
}

/// A description from what a body sent: cleared when `null` or left out.
fn description(text: Option<String>) -> Result<Option<Label>, ApiError> {
    text.map(|text| Label::new("description", text))
        .transpose()
        .map_err(ApiError::validation)
}

/// Request body for creating a consumer.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateConsumerBody {
    /// Display name (such as `"payment-processor"`).
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// The most sensitive data it may receive: `Public`, `Internal`,
    /// `Confidential` or `Restricted`. `Internal` when left out.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub clearance: Option<DataClassLevel>,
    /// When its first credential stops working (RFC 3339). Left out, it
    /// never does.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// Its own request allowance. Left out, it has none of its own; route
    /// rate limits still apply.
    #[serde(default)]
    pub quota: Option<QuotaBody>,
    /// Its first credential.
    #[serde(flatten)]
    pub credential: CredentialBody,
}

impl TryFrom<CreateConsumerBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateConsumerBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            description: description(body.description)?,
            credential: body.credential.try_into()?,
            credential_expiry: expiry(body.expires_at),
            quota: quota(body.quota)?,
            clearance: body.clearance.unwrap_or(DataClassLevel::Internal),
        })
    }
}

/// Request body for replacing a consumer's credential.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RotateCredentialBody {
    /// When the new credential stops working (RFC 3339). Left out, it never
    /// does.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// How many seconds the old credential keeps working beside the new
    /// one, at most seven days, so callers can move over. Left out, it
    /// stops at once, as after a leak.
    #[serde(default)]
    pub overlap_seconds: Option<i64>,
    /// The credential that replaces the current one, of any kind.
    #[serde(flatten)]
    pub credential: CredentialBody,
}

impl RotateCredentialBody {
    /// The rotation of `consumer_id`'s credential to this one.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the credential or the overlap is not a valid
    /// one.
    pub(crate) fn rotation_of(
        self,
        consumer_id: ConsumerId,
    ) -> Result<RotateCredentialRequest, ApiError> {
        Ok(RotateCredentialRequest {
            consumer_id,
            credential: self.credential.try_into()?,
            expiry: expiry(self.expires_at),
            overlap: overlap(self.overlap_seconds)?,
        })
    }
}

/// Request body for renaming a consumer.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RenameConsumerBody {
    /// The new display name.
    pub name: String,
}

impl RenameConsumerBody {
    /// The renaming of `consumer_id` to this name.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the name is not a valid one.
    pub(crate) fn renaming(self, consumer_id: ConsumerId) -> Result<RenameRequest, ApiError> {
        Ok(RenameRequest {
            consumer_id,
            name: Label::new("name", self.name).map_err(ApiError::validation)?,
        })
    }
}

/// Request body for changing or clearing a consumer's description.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DescribeConsumerBody {
    /// The new description; `null` or left out clears it.
    #[serde(default)]
    pub description: Option<String>,
}

impl DescribeConsumerBody {
    /// The description change for `consumer_id`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the description is not a valid one.
    pub(crate) fn description_of(
        self,
        consumer_id: ConsumerId,
    ) -> Result<DescribeRequest, ApiError> {
        Ok(DescribeRequest {
            consumer_id,
            description: Setting::from_stored(description(self.description)?),
        })
    }
}

/// Request body for changing what data a consumer is cleared for.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeClearanceBody {
    /// The most sensitive data it may receive from now on: `Public`,
    /// `Internal`, `Confidential` or `Restricted`.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub clearance: DataClassLevel,
}

impl ChangeClearanceBody {
    /// The clearance change for `consumer_id`.
    #[must_use]
    pub(crate) fn change_of(self, consumer_id: ConsumerId) -> ChangeClearanceRequest {
        ChangeClearanceRequest {
            consumer_id,
            clearance: self.clearance,
        }
    }
}

/// Request body for changing when a consumer's current credential stops
/// working.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeCredentialExpiryBody {
    /// The new expiry (RFC 3339); `null` or left out means it never
    /// expires.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

impl ChangeCredentialExpiryBody {
    /// The expiry change for `consumer_id`'s current credential.
    #[must_use]
    pub(crate) fn change_of(self, consumer_id: ConsumerId) -> ChangeCredentialExpiryRequest {
        ChangeCredentialExpiryRequest {
            consumer_id,
            expiry: expiry(self.expires_at),
        }
    }
}

/// Request body for changing a consumer's request allowance.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeQuotaBody {
    /// The new allowance; `null` or left out removes it.
    #[serde(default)]
    pub quota: Option<QuotaBody>,
}

impl ChangeQuotaBody {
    /// The quota change for `consumer_id`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the allowance is zero or too large.
    pub(crate) fn change_of(self, consumer_id: ConsumerId) -> Result<ChangeQuotaRequest, ApiError> {
        Ok(ChangeQuotaRequest {
            consumer_id,
            quota: quota(self.quota)?,
        })
    }
}

/// Identifies a newly created consumer, with its API key when it signs in
/// with one.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateConsumerResponse {
    /// The consumer's unique identifier.
    pub id: Uuid,
    /// The API key the platform made for it, shown this once and never
    /// again; `null` for a certificate or a token issuer.
    pub api_key: Option<String>,
}

impl From<CreateResult> for CreateConsumerResponse {
    fn from(created: CreateResult) -> Self {
        Self {
            id: *created.consumer_id.as_uuid(),
            api_key: created.api_key.map(|key| key.expose().to_owned()),
        }
    }
}

/// The answer to a rotation: the new API key when the new credential is
/// one.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RotatedCredentialResponse {
    /// The API key the platform made, shown this once and never again;
    /// `null` for a certificate or a token issuer.
    pub api_key: Option<String>,
}

impl From<RotatedCredential> for RotatedCredentialResponse {
    fn from(rotated: RotatedCredential) -> Self {
        Self {
            api_key: rotated.api_key.map(|key| key.expose().to_owned()),
        }
    }
}

/// The credential a consumer used before its last rotation, while it still
/// works beside the new one.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PreviousCredentialResponse {
    /// Safe hint for telling the old credential apart.
    pub credential_hint: String,
    /// When the overlap ends and the old credential is refused.
    #[serde(with = "time::serde::rfc3339")]
    pub until: OffsetDateTime,
}

/// A consumer. The key and its hash are never included, only a hint that
/// tells credentials apart (the prefix of a key, the fingerprint of a
/// certificate, the subject of a token).
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConsumerResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Safe hint for telling the credential apart without exposing it.
    pub credential_hint: String,
    /// When the current credential stops working; `null` when it never
    /// does.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub credential_expires_at: Option<OffsetDateTime>,
    /// The credential it replaced, while that one still works; `null`
    /// otherwise.
    pub previous_credential: Option<PreviousCredentialResponse>,
    /// Its own request allowance; `null` when it has none.
    pub quota: Option<QuotaBody>,
    /// `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::consumer_status)]
    pub status: ConsumerStatus,
    /// The most sensitive data it may receive.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub clearance: DataClassLevel,
    /// Who created the consumer, as `<kind>:<uuid>`: a tenant user, an org
    /// user, or an operator. The kind is part of the answer, since the same
    /// uuid means a different person on each plane.
    pub created_by: String,
    /// When the consumer was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<Consumer<ResolvedTenant>> for ConsumerResponse {
    fn from(consumer: Consumer<ResolvedTenant>) -> Self {
        let credentials = consumer.credentials();
        Self {
            id: *consumer.id().as_uuid(),
            name: consumer.name().as_str().to_owned(),
            description: consumer.description().map(|d| d.as_str().to_owned()),
            credential_hint: consumer.credential().display_hint(),
            credential_expires_at: credentials.current().expiry().instant(),
            previous_credential: PreviousCredentialResponse::of(credentials.previous()),
            quota: QuotaBody::of(consumer.quota()),
            status: consumer.status(),
            clearance: consumer.clearance(),
            created_by: consumer.created_by().audit_label(),
            created_at: consumer.created_at(),
        }
    }
}

impl PreviousCredentialResponse {
    /// The old credential `previous` keeps working, if any.
    fn of(previous: &PreviousCredential) -> Option<Self> {
        let PreviousCredential::Overlapping { credential, until } = previous else {
            return None;
        };
        Some(Self {
            credential_hint: credential.kind().display_hint(),
            until: *until,
        })
    }
}

impl QuotaBody {
    /// The allowance `quota` sets, if any.
    pub(crate) fn of(quota: ConsumerQuota) -> Option<Self> {
        let ConsumerQuota::Limited(allowance) = quota else {
            return None;
        };
        Some(Self {
            requests: allowance.requests(),
            per: allowance.per().into(),
        })
    }
}
