//! Support impersonation bodies: an admin asking to act as a user, the
//! requests a listing shows, and the caller an admin then acts through.

use ianua_app::error::AppError;
use ianua_app::use_cases::identity::impersonation::{
    ActingAs, ImpersonationListing, RequestRequest,
};
use ianua_domain::domains::identity::impersonation::SupportImpersonation;
use ianua_domain::domains::identity::impersonation::state::ImpersonationWindow;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{SupportImpersonationId, Text, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;
use crate::extractors::identity::impersonation::IMPERSONATION_HEADER;

/// An admin asking to act as a user for support.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ImpersonationBody {
    /// Why, kept in the audit trail and shown to the person.
    pub reason: String,
    /// How long the admin may act once it starts, in minutes: 5 to 60.
    pub minutes: u32,
}

impl ImpersonationBody {
    /// The request to act as `user`.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] for a reason that is not valid text.
    /// - `422` for a window outside 5 to 60 minutes.
    pub(crate) fn request(self, user: UserId) -> Result<RequestRequest, ApiError> {
        Ok(RequestRequest {
            user_id: user,
            reason: Text::new("reason", self.reason).map_err(ApiError::validation)?,
            window: ImpersonationWindow::minutes(self.minutes)
                .map_err(|e| ApiError(AppError::from_domain(e)))?,
        })
    }
}

/// The impersonation asked for.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ImpersonationRequestedResponse {
    /// Its id, to act through, end, or for the person to answer.
    pub id: Uuid,
}

impl From<SupportImpersonationId> for ImpersonationRequestedResponse {
    fn from(id: SupportImpersonationId) -> Self {
        Self { id: *id.as_uuid() }
    }
}

/// Which impersonations a listing shows.
#[derive(Deserialize, Default, Clone, Copy, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ImpersonationScope {
    /// Those naming the caller, as the admin or as the person.
    #[default]
    Mine,
    /// Every one in the tenant; needs full control of users.
    All,
}

/// The query of an impersonation listing.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ImpersonationListParams {
    /// `mine` (the default) or `all`.
    #[serde(default)]
    #[param(value_type = Option<String>)]
    pub scope: ImpersonationScope,
}

impl From<ImpersonationListParams> for ImpersonationListing {
    fn from(params: ImpersonationListParams) -> Self {
        match params.scope {
            ImpersonationScope::Mine => Self::Mine,
            ImpersonationScope::All => Self::All,
        }
    }
}

/// One support impersonation.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ImpersonationResponse {
    /// Identifies the grant used when acting as this person or ending support access.
    pub id: Uuid,
    /// The admin who asked.
    pub admin_id: Uuid,
    /// The person they act as.
    pub user_id: Uuid,
    /// Why.
    pub reason: String,
    /// How long the admin may act once it starts, in minutes.
    pub minutes: u32,
    /// Whether the person approves first (`holder_approves`) or the admin
    /// decided (`admin_decides`).
    pub consent: &'static str,
    /// `awaiting_consent`, `active`, `declined` or `ended`.
    pub status: &'static str,
    /// When it was asked for.
    #[serde(with = "time::serde::rfc3339")]
    pub requested_at: OffsetDateTime,
    /// When the admin's window closes, once it started.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub ends_at: Option<OffsetDateTime>,
}

impl From<&SupportImpersonation<ResolvedTenant>> for ImpersonationResponse {
    fn from(impersonation: &SupportImpersonation<ResolvedTenant>) -> Self {
        Self {
            id: *impersonation.id().as_uuid(),
            admin_id: *impersonation.admin().as_uuid(),
            user_id: *impersonation.user_id().as_uuid(),
            reason: impersonation.reason().as_str().to_owned(),
            minutes: impersonation.window().as_minutes(),
            consent: impersonation.consent().as_str(),
            status: impersonation.status().as_str(),
            requested_at: impersonation.requested_at(),
            ends_at: impersonation.ends_at(),
        }
    }
}

impl ImpersonationResponse {
    /// Each of `impersonations`.
    #[must_use]
    pub(crate) fn listing(impersonations: &[SupportImpersonation<ResolvedTenant>]) -> Vec<Self> {
        impersonations.iter().map(Self::from).collect()
    }
}

/// What the admin acts through, and until when.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ActingAsResponse {
    /// The impersonation to name on each request made as the person.
    pub impersonation_id: Uuid,
    /// The header that names it, beside the admin's own bearer.
    pub header: &'static str,
    /// When the window closes and requests through it stop counting.
    #[serde(with = "time::serde::rfc3339")]
    pub ends_at: OffsetDateTime,
}

impl ActingAsResponse {
    /// The answer for `id`, which `acting` grants.
    #[must_use]
    pub(crate) fn new(id: SupportImpersonationId, acting: &ActingAs) -> Self {
        Self {
            impersonation_id: *id.as_uuid(),
            header: IMPERSONATION_HEADER,
            ends_at: acting.ends_at,
        }
    }
}
