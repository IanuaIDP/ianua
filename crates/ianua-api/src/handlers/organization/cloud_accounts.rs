//! Cloud account handlers: connecting an organization's own cloud account,
//! proving it, listing its networks and disconnecting it.
//!
//! Credentials arrive here and stop here. Nothing returns one, and
//! [`CloudAccountResponse`] has no field that could hold one.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::organization::cloud_accounts::{
    BeginCloudConnectionRequest, ListCloudNetworksRequest, VerifyRequest,
};
use ianua_assembly::organization::OrganizationState;
use ianua_domain::shared::clock;

use crate::dto::organization::cloud_accounts::{
    CloudAccountResponse, CloudNetworkResponse, ConnectionInstructionsResponse, CredentialBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::OrgMember;
use crate::extractors::json::Json;
use crate::extractors::organization::cloud::RegionQuery;
use crate::extractors::paths::organization::CloudProviderPath;
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/cloud-accounts",
    tag = "Cloud accounts",
    responses(
        (status = 200, description = "Every cloud this organization has connected", body = [CloudAccountResponse]),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List connected cloud accounts
///
/// Every cloud this organization has begun connecting, whether or not the
/// connection is finished. Never returns a credential. Seeing that a
/// connection exists is a read of the organization.
pub(crate) async fn list_cloud_accounts(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<Vec<CloudAccountResponse>>, ApiError> {
    let accounts = organization
        .cloud_accounts
        .list
        .execute(&member.caller, ())
        .await?;
    Ok(Json(
        accounts.iter().map(CloudAccountResponse::from).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/cloud-accounts/{provider}",
    tag = "Cloud accounts",
    responses(
        (status = 200, description = "What to do next, and the external id where that cloud uses one", body = ConnectionInstructionsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "This deployment cannot drive that cloud", body = ErrorBody)
    )
)]
/// Begin connecting a cloud account
///
/// Returns the steps to follow, and for AWS the external id to place in the
/// role's trust policy. Safe to call again: the same external id comes
/// back, because replacing it would break a trust policy already built.
/// Connecting a cloud is a change to the organization.
pub(crate) async fn begin_cloud_connection(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<CloudProviderPath>,
) -> Result<Json<ConnectionInstructionsResponse>, ApiError> {
    let request = BeginCloudConnectionRequest {
        provider: path.provider()?,
        now: clock::now(),
    };
    let instructions = organization
        .cloud_accounts
        .begin
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(Json(ConnectionInstructionsResponse::of(
        &instructions,
        organization.cloud_accounts.console_template.as_deref(),
    )))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/cloud-accounts/{provider}/credential",
    tag = "Cloud accounts",
    request_body = CredentialBody,
    responses(
        (status = 200, description = "The connection, with the result of proving it", body = CloudAccountResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "This connection was never begun", body = ErrorBody),
        (status = 422, description = "The credential is malformed, for another cloud, or names a cluster nobody can reach", body = ErrorBody)
    )
)]
/// Submit and verify a cloud credential
///
/// Stores the grant, then uses it once against a harmless endpoint and
/// records what happened.
///
/// A credential the cloud **rejects** is not an error: it comes back as a
/// connection in the `failed` state with a reason, because that is the
/// answer to "does this work". Only being unable to ask (our own outage) is
/// a `500`, and that leaves the connection retryable.
///
/// Submitting again is how rotation works, and returns the connection to
/// unverified until the new secret has proved itself.
pub(crate) async fn submit_cloud_credential(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<CloudProviderPath>,
    Json(body): Json<CredentialBody>,
) -> Result<Json<CloudAccountResponse>, ApiError> {
    let provider = path.provider()?;
    let external_id = organization
        .cloud_accounts
        .external_id
        .execute(&member.caller, provider)
        .await?;
    let attach = body.attachment(provider, external_id)?;
    organization
        .cloud_accounts
        .attach
        .execute(&member.caller, &member.auditor, attach)
        .await?;
    let verify = VerifyRequest {
        provider,
        now: clock::now(),
    };
    let account = organization
        .cloud_accounts
        .verify
        .execute(&member.caller, &member.auditor, verify)
        .await?;
    Ok(Json(CloudAccountResponse::from(&account)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/cloud-accounts/{provider}/verify",
    tag = "Cloud accounts",
    responses(
        (status = 200, description = "The connection, with the result of proving it", body = CloudAccountResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "This connection was never begun", body = ErrorBody),
        (status = 409, description = "No credential has been submitted yet", body = ErrorBody),
        (status = 422, description = "The credential needs correcting, such as a cluster address nobody can reach", body = ErrorBody)
    )
)]
/// Re-verify a cloud connection
///
/// Uses the stored credential again. Worth calling before relying on a
/// connection made weeks ago: a role can be deleted and an Azure client
/// secret expires.
pub(crate) async fn verify_cloud_account(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<CloudProviderPath>,
) -> Result<Json<CloudAccountResponse>, ApiError> {
    let request = VerifyRequest {
        provider: path.provider()?,
        now: clock::now(),
    };
    let account = organization
        .cloud_accounts
        .verify
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(Json(CloudAccountResponse::from(&account)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/cloud-accounts/{provider}/networks",
    tag = "Cloud accounts",
    params(("region" = String, Query, description = "Region to list networks in, e.g. eu-central-1")),
    responses(
        (status = 200, description = "Networks a database could be placed in", body = [CloudNetworkResponse]),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the connection is not verified", body = ErrorBody),
        (status = 404, description = "This connection was never begun", body = ErrorBody),
        (status = 422, description = "Unknown region, or one this cloud cannot serve", body = ErrorBody)
    )
)]
/// List networks in a connected cloud account
///
/// What the customer already has in that region, named the way they named
/// it, so a tenant is placed against something they recognise. An empty
/// list is a real answer: the account has nothing suitable there, which is
/// exactly when building a network is offered instead.
pub(crate) async fn list_cloud_networks(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<CloudProviderPath>,
    RegionQuery(region): RegionQuery,
) -> Result<Json<Vec<CloudNetworkResponse>>, ApiError> {
    let request = ListCloudNetworksRequest {
        provider: path.provider()?,
        region,
    };
    let networks = organization
        .cloud_accounts
        .networks
        .execute(&member.caller, request)
        .await?;
    Ok(Json(
        networks.iter().map(CloudNetworkResponse::from).collect(),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/cloud-accounts/{provider}",
    tag = "Cloud accounts",
    responses(
        (status = 204, description = "Disconnected"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Tenants still run in this account", body = ErrorBody)
    )
)]
/// Disconnect a cloud account
///
/// Forgets the credential. Refused while any tenant still has a database in
/// that account: dropping the grant would leave infrastructure we can no
/// longer reach, running and billing. Records
/// `organization.cloud_account_disconnected`.
pub(crate) async fn disconnect_cloud_account(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<CloudProviderPath>,
) -> Result<NoContent, ApiError> {
    organization
        .cloud_accounts
        .disconnect
        .execute(&member.caller, &member.auditor, path.provider()?)
        .await?;
    Ok(NoContent)
}
