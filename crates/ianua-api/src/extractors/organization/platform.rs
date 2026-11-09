//! An operator acting on the organization the path names, for the actions
//! only the platform takes, such as moving it to another plan.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::OperatorCaller;
use ianua_app::error::AppError;
use ianua_app::use_cases::organization::steward::OrganizationSteward;
use ianua_domain::message;
use ianua_domain::types::OrganizationId;

use crate::error::ApiError;
use crate::extractors::organization::OrgSteward;
use crate::state::ApiState;

/// An operator, with their own key, and the organization the path names.
pub(crate) struct OrgOperator {
    /// The operator.
    pub caller: OperatorCaller,
    /// The organization the path names.
    pub organization: OrganizationId,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for OrgOperator {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let steward = OrgSteward::from_request_parts(parts, state).await?;
        let OrganizationSteward::Platform(caller) = steward.caller else {
            return Err(ApiError(AppError::Forbidden(message!(
                "api-this-credential-does-not-act-here",
                "this credential does not act here"
            ))));
        };
        Ok(Self {
            caller,
            organization: steward.organization,
            auditor: steward.auditor,
        })
    }
}
