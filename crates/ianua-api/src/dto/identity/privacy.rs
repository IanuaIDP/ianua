//! Privacy bodies: a consent decision and an erasure request.

use ianua_app::email::LinkScope;
use ianua_app::use_cases::identity::privacy::{
    RequestErasureRequest, RequestExportRequest, RevokeConsentRequest,
};
use ianua_app::use_cases::identity::whose::Whose;
use ianua_domain::domains::identity::privacy::consent::{ConsentRecord, ConsentTerms, ConsentType};
use ianua_domain::domains::identity::privacy::export::{
    DataExportRequest, ExportAskedBy, ExportScope,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{DataExportId, ErasureRequestId, HttpsUrl, Label, Text};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// Gives or withdraws consent on one set of terms.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ConsentBody {
    /// The kind of consent, such as `DataProcessing` or `Marketing`.
    #[schema(schema_with = crate::dto::schemas::consent_type)]
    pub consent_type: ConsentType,
    /// Which version of the terms, such as `tos-2024-01`.
    pub version: String,
    /// `true` gives consent, `false` withdraws it.
    pub granted: bool,
}

/// What a consent body asks of the app.
pub enum ConsentDecision {
    /// The signed-in person gives their own consent on these terms.
    Grant(ConsentTerms),
    /// Consent on these terms is withdrawn, by the person or for them.
    Withdraw(RevokeConsentRequest),
}

impl ConsentBody {
    /// The decision asked for on `whose` account.
    ///
    /// Only the person gives their own consent, so a grant for someone else
    /// is refused here: no use case records one.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] for a version that is not a valid label.
    /// - `403` for consent given on someone else's behalf.
    pub(crate) fn decision(self, whose: Whose) -> Result<ConsentDecision, ApiError> {
        let terms = ConsentTerms {
            consent_type: self.consent_type,
            version: Label::new("version", self.version).map_err(ApiError::validation)?,
        };
        if !self.granted {
            return Ok(ConsentDecision::Withdraw(RevokeConsentRequest {
                whose,
                terms,
            }));
        }
        let Whose::Own = whose else {
            return Err(ApiError(ianua_app::error::AppError::Forbidden(message!(
                "api-only-the-person-gives-their-own",
                "only the person gives their own consent"
            ))));
        };
        Ok(ConsentDecision::Grant(terms))
    }
}

/// Asks for a person's data to be erased.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ErasureBody {
    /// Why, if a reason is given.
    pub reason: Option<String>,
}

impl ErasureBody {
    /// The erasure asked for on `whose` account, the cancel link landing on
    /// `scope`.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for a reason that is not valid text.
    pub(crate) fn request(
        self,
        whose: Whose,
        scope: LinkScope,
    ) -> Result<RequestErasureRequest, ApiError> {
        Ok(RequestErasureRequest {
            whose,
            reason: self
                .reason
                .map(|reason| Text::new("reason", reason))
                .transpose()
                .map_err(ApiError::validation)?,
            scope,
        })
    }
}

/// One consent decision a person made.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConsentRecordResponse {
    /// The kind of consent, such as `Marketing`.
    #[schema(schema_with = crate::dto::schemas::consent_type)]
    pub consent_type: ConsentType,
    /// Which version of the terms.
    pub version: String,
    /// `true` when consent was given, `false` when withdrawn.
    pub granted: bool,
    /// The address the decision came from, when it could be told.
    pub ip_address: Option<String>,
    /// When it was made.
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
}

impl From<&ConsentRecord<ResolvedTenant>> for ConsentRecordResponse {
    fn from(record: &ConsentRecord<ResolvedTenant>) -> Self {
        Self {
            consent_type: record.consent_type(),
            version: record.version().as_str().to_owned(),
            granted: record.granted(),
            ip_address: record.ip_address().known().map(|ip| ip.as_str().to_owned()),
            recorded_at: record.recorded_at(),
        }
    }
}

impl ConsentRecordResponse {
    /// Each of `records`, in the order the app gave them.
    #[must_use]
    pub(crate) fn history(records: &[ConsentRecord<ResolvedTenant>]) -> Vec<Self> {
        records.iter().map(Self::from).collect()
    }
}

/// What a copy of a person's data is to hold.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExportScopeBody {
    /// Everything kept about them, under the right of access (GDPR article
    /// 15).
    Access,
    /// What they gave the service themselves, in a form another service
    /// reads (GDPR article 20).
    Portability,
}

/// Asks for a copy of a person's data.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ExportBody {
    /// `access` or `portability`.
    pub scope: ExportScopeBody,
}

impl ExportBody {
    /// The export asked for on `whose` account.
    #[must_use]
    pub(crate) fn request(self, whose: Whose) -> RequestExportRequest {
        let scope = match self.scope {
            ExportScopeBody::Access => ExportScope::Access,
            ExportScopeBody::Portability => ExportScope::Portability,
        };
        RequestExportRequest { whose, scope }
    }
}

/// One request for a copy of a person's data.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ExportResponse {
    /// The export's id, to download it by.
    pub id: Uuid,
    /// `access` or `portability`.
    pub scope: &'static str,
    /// `requested` while it is gathered, `ready` to download, `expired`
    /// once its week is over.
    pub status: &'static str,
    /// Whether the person asked for it themselves (`holder`) or staff did
    /// for them (`staff`).
    pub asked_by: &'static str,
    /// When it was asked for.
    #[serde(with = "time::serde::rfc3339")]
    pub requested_at: OffsetDateTime,
}

impl From<&DataExportRequest<ResolvedTenant>> for ExportResponse {
    fn from(export: &DataExportRequest<ResolvedTenant>) -> Self {
        Self {
            id: *export.id().as_uuid(),
            scope: export.scope().as_str(),
            status: export.status().as_str(),
            asked_by: match export.asked_by() {
                ExportAskedBy::Holder => "holder",
                ExportAskedBy::Staff => "staff",
            },
            requested_at: export.requested_at(),
        }
    }
}

impl ExportResponse {
    /// Each of `exports`.
    #[must_use]
    pub(crate) fn listing(exports: &[DataExportRequest<ResolvedTenant>]) -> Vec<Self> {
        exports.iter().map(Self::from).collect()
    }
}

/// The export asked for.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ExportRequestedResponse {
    /// The export's id. It is mailed to the person once it is ready.
    pub id: Uuid,
}

impl From<DataExportId> for ExportRequestedResponse {
    fn from(id: DataExportId) -> Self {
        Self { id: *id.as_uuid() }
    }
}

/// Where a ready export is downloaded.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ExportDownloadResponse {
    /// A short-lived address of the file. Only the person it is about may
    /// ask for it.
    pub url: String,
}

impl From<HttpsUrl> for ExportDownloadResponse {
    fn from(url: HttpsUrl) -> Self {
        Self {
            url: url.as_str().to_owned(),
        }
    }
}

/// The erasure request made.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ErasureRequestResponse {
    /// The request's id, to cancel or hold it by.
    pub id: String,
}

impl From<ErasureRequestId> for ErasureRequestResponse {
    fn from(id: ErasureRequestId) -> Self {
        Self { id: id.to_string() }
    }
}
