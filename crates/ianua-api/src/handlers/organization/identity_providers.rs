//! Identity provider handlers: the organization's own SAML or OIDC
//! provider, which signs its members in to the dashboard.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::organization::identity_providers::{AddOrgRequest, ChangeOrgRequest};
use ianua_assembly::organization::OrganizationState;

use crate::dto::organization::identity_providers::{
    AddOrgProviderBody, ChangeOrgProviderBody, OrgIdentityProviderResponse, SwitchOrgProviderBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::OrgMember;
use crate::extractors::json::Json;
use crate::response::{Created, NoContent};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/identity-provider",
    tag = "Organizations",
    responses(
        (status = 200, description = "The provider", body = OrgIdentityProviderResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "The organization has no provider", body = ErrorBody)
    )
)]
/// Get the identity provider
///
/// The organization's own identity provider: its name, protocol, whether it
/// is switched on, and how far its word is taken. Its configuration and
/// secrets are never shown. Read-only. The app decides whether the caller
/// may read the organization's sign-in settings.
pub(crate) async fn get_identity_provider(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<OrgIdentityProviderResponse>, ApiError> {
    let provider = organization
        .identity_provider
        .get
        .execute(&member.caller, ())
        .await?;
    Ok(Json(OrgIdentityProviderResponse::from(provider)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/identity-provider",
    tag = "Organizations",
    request_body = AddOrgProviderBody,
    responses(
        (status = 201, description = "Added, switched off", body = OrgIdentityProviderResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "The organization has a provider already", body = ErrorBody),
        (status = 422, description = "Validation error, an OIDC issuer with no usable configuration, or SAML settings asking for signed requests", body = ErrorBody)
    )
)]
/// Add the identity provider
///
/// Adds the provider the organization's members sign in to the dashboard
/// through, over SAML or OIDC, configured as a tenant's connection is. An
/// organization has one. It starts switched off and untrusted: switch it on
/// with `PUT …/identity-provider/status` once it is tested. An OIDC client
/// secret is kept sealed and never shown or recorded. Records
/// `organization.org_identity_provider_added`. The app decides whether the
/// caller may change the organization's sign-in settings.
pub(crate) async fn add_identity_provider(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<AddOrgProviderBody>,
) -> Result<Created<OrgIdentityProviderResponse>, ApiError> {
    let provider = organization
        .identity_provider
        .add
        .execute(
            &member.caller,
            &member.auditor,
            AddOrgRequest::try_from(body)?,
        )
        .await?;
    Ok(Created(OrgIdentityProviderResponse::from(provider)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/identity-provider",
    tag = "Organizations",
    request_body = ChangeOrgProviderBody,
    responses(
        (status = 200, description = "The provider as changed", body = OrgIdentityProviderResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the proof is wrong", body = ErrorBody),
        (status = 404, description = "The organization has no provider", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change the identity provider
///
/// Changes the provider's `name`, its `config`, whether its addresses are
/// taken as proven (`email_trust`) and whether its report of factors is
/// believed (`assurance_trust`), all together; a field left out keeps its
/// value. The provider decides who reaches the dashboard, so the caller
/// sends `proof`, their password typed again with a code from their second
/// factor (`403 step_up_required` without it). Records one
/// `organization.org_identity_provider_changed`; a change of nothing
/// records nothing.
pub(crate) async fn change_identity_provider(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<ChangeOrgProviderBody>,
) -> Result<Json<OrgIdentityProviderResponse>, ApiError> {
    let provider = organization
        .identity_provider
        .change
        .execute(
            &member.caller,
            &member.auditor,
            ChangeOrgRequest::try_from(body)?,
        )
        .await?;
    Ok(Json(OrgIdentityProviderResponse::from(provider)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/identity-provider/status",
    tag = "Organizations",
    request_body = SwitchOrgProviderBody,
    responses(
        (status = 200, description = "The provider as switched", body = OrgIdentityProviderResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the proof is wrong", body = ErrorBody),
        (status = 404, description = "The organization has no provider", body = ErrorBody),
        (status = 422, description = "The provider already stands so", body = ErrorBody)
    )
)]
/// Switch the identity provider on or off
///
/// Sets the provider's `status` to `Active` or `Disabled`. Members sign in
/// through it only while it is `Active`. Send `proof`, the caller's
/// password typed again with a code from their second factor. Records
/// `organization.org_identity_provider_changed`.
pub(crate) async fn switch_identity_provider(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<SwitchOrgProviderBody>,
) -> Result<Json<OrgIdentityProviderResponse>, ApiError> {
    let provider = organization
        .identity_provider
        .switch
        .execute(&member.caller, &member.auditor, body.into())
        .await?;
    Ok(Json(OrgIdentityProviderResponse::from(provider)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/identity-provider",
    tag = "Organizations",
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "The organization has no provider", body = ErrorBody)
    )
)]
/// Remove the identity provider
///
/// Deletes the organization's provider. A sign-in already sent to it is
/// refused when it comes back. Records
/// `organization.org_identity_provider_removed`.
pub(crate) async fn remove_identity_provider(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<NoContent, ApiError> {
    organization
        .identity_provider
        .remove
        .execute(&member.caller, &member.auditor, ())
        .await?;
    Ok(NoContent)
}
