//! Member privacy bodies: a consent decision, the consent history, and an
//! erasure request.

use ianua_app::error::AppError;
use ianua_app::use_cases::organization::privacy::whose::OrgWhose;
use ianua_app::use_cases::organization::privacy::{
    RequestOrgErasureRequest, RevokeOrgConsentRequest,
};
use ianua_domain::domains::identity::privacy::consent::{ConsentTerms, ConsentType};
use ianua_domain::domains::organization::members::privacy::consent::OrgConsentRecord;
use ianua_domain::message;
use ianua_domain::types::{Label, Text};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ApiError;

/// Gives or withdraws a member's consent on one set of terms.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgConsentBody {
    /// The kind of consent, such as `DataProcessing` or `Marketing`.
    #[schema(schema_with = crate::dto::schemas::consent_type)]
    pub consent_type: ConsentType,
    /// Which version of the terms, such as `tos-2024-01`.
    pub version: String,
    /// `true` gives consent, `false` withdraws it.
    pub granted: bool,
}

/// What a consent body asks of the app.
pub(crate) enum OrgConsentDecision {
    /// The signed-in member gives their own consent on these terms.
    Grant(ConsentTerms),
    /// Consent on these terms is withdrawn, by the member or for them.
    Withdraw(RevokeOrgConsentRequest),
}

impl OrgConsentBody {
    /// The decision asked for on `whose` account.
    ///
    /// Only the member gives their own consent, so a grant for someone else
    /// is refused here: no use case records one.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] for a version that is not a valid label.
    /// - `403` for consent given on someone else's behalf.
    pub(crate) fn decision(self, whose: OrgWhose) -> Result<OrgConsentDecision, ApiError> {
        let terms = ConsentTerms {
            consent_type: self.consent_type,
            version: Label::new("version", self.version).map_err(ApiError::validation)?,
        };
        if !self.granted {
            return Ok(OrgConsentDecision::Withdraw(RevokeOrgConsentRequest {
                whose,
                terms,
            }));
        }
        let OrgWhose::Own = whose else {
            return Err(ApiError(AppError::Forbidden(message!(
                "api-only-the-member-gives-their-own",
                "only the member gives their own consent"
            ))));
        };
        Ok(OrgConsentDecision::Grant(terms))
    }
}

/// One consent decision a member made.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgConsentResponse {
    /// The record's id.
    pub id: String,
    /// The kind of consent.
    #[schema(schema_with = crate::dto::schemas::consent_type)]
    pub consent_type: ConsentType,
    /// Which version of the terms.
    pub version: String,
    /// `true` when consent was given, `false` when it was withdrawn.
    pub granted: bool,
    /// When the decision was recorded.
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
}

impl From<OrgConsentRecord> for OrgConsentResponse {
    fn from(record: OrgConsentRecord) -> Self {
        Self {
            id: record.id().to_string(),
            consent_type: record.consent_type(),
            version: record.version().as_str().to_owned(),
            granted: record.decision().into(),
            recorded_at: record.recorded_at(),
        }
    }
}

/// Asks for a member's data to be erased.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgErasureBody {
    /// Why, if a reason is given.
    #[serde(default)]
    pub reason: Option<String>,
}

impl OrgErasureBody {
    /// The erasure asked for on `whose` account.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for a reason that is not valid text.
    pub(crate) fn request(self, whose: OrgWhose) -> Result<RequestOrgErasureRequest, ApiError> {
        Ok(RequestOrgErasureRequest {
            whose,
            reason: self
                .reason
                .map(|reason| Text::new("reason", reason))
                .transpose()
                .map_err(ApiError::validation)?,
        })
    }
}
