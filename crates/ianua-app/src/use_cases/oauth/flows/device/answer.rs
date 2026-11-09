//! What approving and denying a device request share: naming the client in
//! the record, and the error a refused answer gives.

use ianua_domain::domains::oauth::grants::device_authorization::{
    DeviceAuthError, DeviceAuthorization,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::EventLabel;

use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::shared::AuditLabelResolver;

/// The name of the client behind `auth`, for the audit record, or its id
/// when it cannot be found.
pub(in crate::use_cases::oauth::flows) async fn client_label(
    resolver: &dyn AuditLabelResolver,
    caller: &CallerContext,
    auth: &DeviceAuthorization<ResolvedTenant>,
) -> EventLabel {
    resolver
        .oauth_client(&caller.tenant(), auth.client_id())
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| EventLabel::of(&auth.client_id().to_string()))
}

/// The error a person sees for an answer the request refused.
pub(in crate::use_cases::oauth::flows) fn refused_answer(refusal: DeviceAuthError) -> AppError {
    AppError::from_domain(DomainError::from(refusal))
}
