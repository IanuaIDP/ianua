//! Who calls a messaging use case open to people and consumers alike.
//!
//! Over the HTTP API that is always a person acting in the tenant the path
//! names: a consumer's own credential is presented at the gateway, which
//! builds its caller there.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::CallerIdentity;
use ianua_app::use_cases::messaging::caller::MessagingCaller;
use uuid::Uuid;

use crate::error::ApiError;
use crate::extractors::callers::TenantCaller;
use crate::state::ApiState;

/// A person acting in the tenant the path names, as a messaging caller.
pub(crate) struct TenantMessenger {
    /// Who is calling, as the messaging use cases take them.
    pub caller: MessagingCaller,
    /// The person whose live streams this request counts against.
    pub stream_owner: Uuid,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for TenantMessenger {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let tenant = TenantCaller::from_request_parts(parts, state).await?;
        Ok(Self {
            stream_owner: person_of(tenant.caller.identity()),
            caller: MessagingCaller::Person(tenant.caller),
            auditor: tenant.auditor,
        })
    }
}

/// The person behind `identity`, by their id.
fn person_of(identity: &CallerIdentity) -> Uuid {
    match identity {
        CallerIdentity::TenantUser(id) => *id.as_uuid(),
        CallerIdentity::OrgUser(id) => *id.as_uuid(),
        CallerIdentity::Operator(id) => *id.as_uuid(),
    }
}
