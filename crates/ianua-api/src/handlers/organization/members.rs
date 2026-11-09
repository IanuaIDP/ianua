//! Organization member handlers: the member listing, adding and removing
//! members, their status, role, address, password, second factor and
//! tenant access, the caller's own profile, and linked identities.

use axum::extract::{Path, State};
use ianua_app::ports::organization::OrgUserSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::organization::members::{
    ListGrantableRolesRequest, TransferOwnershipRequest, UnlinkIdentityRequest, Unlinker,
    WhoseReach,
};
use ianua_assembly::organization::OrganizationState;
use ianua_domain::shared::config::DomainLimits;

use crate::dto::organization::members::{
    ChangeOrgUserEmailBody, ChangeOrgUserRoleBody, ChangePasswordBody, CreateOrgUserBody,
    CreateOrgUserResponse, GrantableRoleResponse, OrgMeResponse, OrgUserAccessResponse,
    OrgUserFilterParams, OrgUserResponse, ResetOrgUserPasswordBody, ResetOrgUserPasswordResponse,
    SetOrgUserTenantAccessBody, UnlinkIdentityBody, UpdateOrgUserProfileBody,
    UpdateOrgUserStatusBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{OrgMember, TenantCaller};
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::organization::members::LinkingCaller;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::organization::{OrgTenantPath, OrgUserPath, OrgUserTenantPath};
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/users",
    tag = "Organizations",
    params(OrgUserFilterParams, SortQuery<OrgUserSortField>, PaginationParams),
    responses(
        (status = 200, description = "Org users", body = PageResponse<OrgUserResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List org users (team members)
///
/// The organization's team members, optionally filtered by `status`
/// (`Invited` / `PendingVerification` / `Active` / `Locked` /
/// `Deactivated`, or the invitation-derived `PendingInvitation` /
/// `InvitationExpired`) and/or `email` substring, sortable and paginated.
/// Each entry carries the email, display name, lifecycle `status`, role and
/// timestamps. Read-only. The app decides whether the caller may view
/// members.
pub(crate) async fn list_org_users(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<OrgUserFilterParams, OrgUserSortField>,
) -> Result<Json<PageResponse<OrgUserResponse>>, ApiError> {
    let page = organization
        .members
        .list
        .execute(&member.caller, filter.listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(page, OrgUserResponse::from)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/create",
    tag = "Organizations",
    request_body = CreateOrgUserBody,
    responses(
        (status = 201, description = "User created", body = CreateOrgUserResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create an org user directly
///
/// Creates a team member with a password the owner chose, bypassing the
/// invite flow, for accounts the owner provisions. The member is active at
/// once, but their address counts as unverified until they follow the
/// confirmation link mailed there: nobody adding an account vouches for a
/// mailbox they do not hold. The `password` is checked against the
/// organization's password rules.
///
/// Returns `409` if the address belongs to another account, or `422` for an
/// invalid email, display name or weak password. Only an owner makes an
/// owner. Records `organization.org_user_created` and, once the mail is
/// accepted, `organization.org_verification_email_sent`.
pub(crate) async fn create_org_user(
    State(organization): State<OrganizationState>,
    State(limits): State<DomainLimits>,
    member: OrgMember,
    Json(body): Json<CreateOrgUserBody>,
) -> Result<Created<CreateOrgUserResponse>, ApiError> {
    let request = body.into_request(&limits)?;
    let created = organization
        .members
        .create
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(Created(CreateOrgUserResponse::from(created.id)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}",
    tag = "Organizations",
    responses(
        (status = 204, description = "User permanently deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Would leave the organization without an owner", body = ErrorBody)
    )
)]
/// Delete an org user
///
/// Permanently deletes a team member: every session of theirs ends and
/// every delegation they granted, in any tenant of the organization, is
/// revoked before the record goes. Irreversible. Nobody removes themselves,
/// and the organization always keeps an active owner. Records
/// `organization.org_user_deleted`.
pub(crate) async fn delete_org_user(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
) -> Result<NoContent, ApiError> {
    organization
        .members
        .delete
        .execute(&member.caller, &member.auditor, path.member())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/status",
    tag = "Organizations",
    request_body = UpdateOrgUserStatusBody,
    responses(
        (status = 204, description = "Status updated"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Would shut out the last active owner", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update an org user's status
///
/// Moves a team member between `Active`, `Locked` and `Deactivated`. Only
/// the transitions the lifecycle allows are accepted. A member locked or
/// deactivated is signed out everywhere at once, and every delegation they
/// granted is revoked with them.
///
/// Returns `404` if the user does not exist, `409` if it would shut out the
/// last active owner, and `422` for an unknown status or an illegal
/// transition. Records `organization.org_user_status_changed`.
pub(crate) async fn update_org_user_status(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
    Json(body): Json<UpdateOrgUserStatusBody>,
) -> Result<NoContent, ApiError> {
    let request = body.for_member(path.member())?;
    organization
        .members
        .update_status
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/role",
    tag = "Organizations",
    request_body = ChangeOrgUserRoleBody,
    responses(
        (status = 204, description = "Role updated"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Would leave the organization without an owner", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change an org user's role
///
/// Moves a member to another org role. `Owner` governs the organization and
/// inherits every permission in every tenant under it; `Admin` runs it day
/// to day with every tenant, but does not close it or change what it pays;
/// `Member` carries no org-level authority on its own, tenant access coming
/// from per-tenant roles; `Billing` runs the subscription and `Viewer`
/// reads the organization, and neither reaches any tenant. Only an owner
/// makes or unmakes one; handing ownership on in one step is
/// `…/users/{user_id}/transfer-ownership`.
///
/// The change takes effect immediately: the member's sessions end, so
/// their next sign-in carries the new role. Returns `404` if the user is
/// not a member of this organization, and `409` if the change would leave
/// the organization with no owner. Records
/// `organization.org_user_role_changed`.
pub(crate) async fn change_org_user_role(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
    Json(body): Json<ChangeOrgUserRoleBody>,
) -> Result<NoContent, ApiError> {
    organization
        .members
        .change_role
        .execute(
            &member.caller,
            &member.auditor,
            body.for_member(path.member()),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/transfer-ownership",
    tag = "Organizations",
    responses(
        (status = 204, description = "Ownership handed on"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The member is not active, or already an owner", body = ErrorBody),
        (status = 422, description = "The member is the caller", body = ErrorBody)
    )
)]
/// Hand on ownership
///
/// The calling owner makes the member `{user_id}` an owner in their place,
/// in one step, and steps down to `Admin`: the organization is never left
/// without an owner along the way. The heir must be an active member who
/// is not an owner yet. Both members' sessions end, so their next sign-in
/// carries the new roles. Records `organization.org_user_role_changed` for
/// each and `organization.ownership_transferred`. Requires the owner's own
/// session.
pub(crate) async fn transfer_ownership(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
) -> Result<NoContent, ApiError> {
    organization
        .members
        .transfer_ownership
        .execute(
            &member.caller,
            &member.auditor,
            TransferOwnershipRequest {
                heir: path.member(),
            },
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/email",
    tag = "Organizations",
    request_body = ChangeOrgUserEmailBody,
    responses(
        (status = 204, description = "Address changed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Another account holds the address", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Correct another member's address
///
/// An owner moves another member to a new `email`. The address changes at
/// once and counts as unverified until the member confirms it through the
/// link mailed there; links mailed to the old address stop working. A
/// member moving their own address goes through the email change flow,
/// which proves them first. Records `organization.org_user_email_changed`
/// and `organization.org_verification_email_sent`.
pub(crate) async fn change_org_user_email(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
    Json(body): Json<ChangeOrgUserEmailBody>,
) -> Result<NoContent, ApiError> {
    let request = body.for_member(path.member())?;
    organization
        .members
        .change_email
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/me",
    tag = "Organizations",
    responses(
        (status = 200, description = "My account and reach", body = OrgMeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get my account
///
/// The calling member's own account (`id`, `email`, `display_name`,
/// `status`, `role` and preferences) and `access`: the tenants they reach
/// and their permissions in each. Every member reads their own account,
/// whatever their role. Read-only.
pub(crate) async fn get_current_org_user(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<OrgMeResponse>, ApiError> {
    let me = organization.members.me.execute(&member.caller, ()).await?;
    Ok(Json(OrgMeResponse::from(me)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/me",
    tag = "Organizations",
    request_body = UpdateOrgUserProfileBody,
    responses(
        (status = 204, description = "Profile updated"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update my profile
///
/// Self-service update of the calling member's own `display_name`,
/// `locale` and `timezone` (email and password have their own endpoints).
/// Each field is applied when present and left unchanged when omitted or
/// `null`. `locale` and `timezone` override the organization defaults.
/// Returns `422` for an invalid display name, locale or timezone. Records
/// `organization.org_user_display_name_changed` and
/// `organization.org_user_preferences_updated` for what changed.
pub(crate) async fn update_current_org_user(
    State(organization): State<OrganizationState>,
    State(limits): State<DomainLimits>,
    member: OrgMember,
    Json(body): Json<UpdateOrgUserProfileBody>,
) -> Result<NoContent, ApiError> {
    let change = body.for_member(*member.caller.member(), &limits)?;
    if let Some(rename) = change.display_name {
        organization
            .members
            .change_display_name
            .execute(&member.caller, &member.auditor, rename)
            .await?;
    }
    if let Some(preferences) = change.preferences {
        organization
            .members
            .update_preferences
            .execute(&member.caller, &member.auditor, preferences)
            .await?;
    }
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/password/change",
    tag = "Organizations",
    request_body = ChangePasswordBody,
    responses(
        (status = 204, description = "Password changed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change my password
///
/// Self-service password change for the calling member: proves them with
/// the `old_password` and sets `new_password`, checked against the
/// organization's rules. Every session the member has ends, the one they
/// asked from included, so whoever else held one is out. Returns `422` if
/// the new password is too weak. Records
/// `organization.org_user_password_changed`.
pub(crate) async fn change_org_user_password(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<ChangePasswordBody>,
) -> Result<NoContent, ApiError> {
    organization
        .members
        .change_password
        .execute(&member.caller, &member.auditor, body.into())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/reset-password",
    tag = "Organizations",
    request_body = ResetOrgUserPasswordBody,
    responses(
        (status = 200, description = "Password reset", body = ResetOrgUserPasswordResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Reset an org user's password
///
/// An owner sets a new password for another team member: the one sent, or
/// one drawn to the organization's rules when omitted, returned for the
/// owner to relay. Every session the member has ends. Use the password
/// change endpoint for your own account. Returns `404` if the user does not
/// exist. Records `organization.org_user_password_reset`.
pub(crate) async fn reset_org_user_password(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
    Json(body): Json<ResetOrgUserPasswordBody>,
) -> Result<Json<ResetOrgUserPasswordResponse>, ApiError> {
    let result = organization
        .members
        .reset_password
        .execute(
            &member.caller,
            &member.auditor,
            body.for_member(path.member()),
        )
        .await?;
    Ok(Json(ResetOrgUserPasswordResponse::from(result)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/mfa/reset",
    tag = "Organizations",
    responses(
        (status = 204, description = "Second factor reset"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Reset a member's second factor
///
/// For a member who lost both their authenticator and their recovery codes.
/// Turns their second factor off, ends every session and remembered device
/// they have, and emails them, so they sign in with their password and set
/// up a new one. You cannot reset your own: turn it off from your account
/// settings, with a code. Returns `404` if the member does not exist or has
/// no second factor. Records `organization.org_member_mfa_reset`.
pub(crate) async fn reset_org_member_mfa(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
) -> Result<NoContent, ApiError> {
    organization
        .members
        .reset_mfa
        .execute(&member.caller, &member.auditor, path.member())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/access",
    tag = "Organizations",
    responses(
        (status = 200, description = "The user's reach", body = OrgUserAccessResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a member's reach
///
/// The org role plus every tenant the member can reach and the permissions
/// they hold in each. An `Owner` lists every tenant in the organization
/// with the full permission set; a `Member` lists only granted tenants.
/// Any member reads their own; another member's needs the right to view
/// members.
pub(crate) async fn get_org_user_access(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserPath>,
) -> Result<Json<OrgUserAccessResponse>, ApiError> {
    let access = organization
        .members
        .access
        .execute(&member.caller, WhoseReach::Member(path.member()))
        .await?;
    Ok(Json(OrgUserAccessResponse::from(access)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/me/access",
    tag = "Organizations",
    responses(
        (status = 200, description = "My reach", body = OrgUserAccessResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// Get my reach
///
/// The calling member's own role, reachable tenants, and permissions per
/// tenant. This is what a dashboard is built from: call it after a grant
/// change to refresh without signing in again. Every member may read it,
/// whatever their role, a `Billing` contact or a `Viewer` too.
pub(crate) async fn get_current_org_user_access(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<OrgUserAccessResponse>, ApiError> {
    let access = organization
        .members
        .access
        .execute(&member.caller, WhoseReach::Own)
        .await?;
    Ok(Json(OrgUserAccessResponse::from(access)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/users/{user_id}/tenants/{tenant_slug}",
    tag = "Organizations",
    request_body = SetOrgUserTenantAccessBody,
    responses(
        (status = 204, description = "Access set"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Set a member's roles in one tenant
///
/// Replaces the tenant roles an org `Member` holds in `{tenant_slug}` with
/// exactly the ones named, so narrowing `["Editor","Viewer"]` to
/// `["Viewer"]` removes Editor. An empty list withdraws access to the
/// tenant entirely. Roles are named the way they appear in that tenant.
/// Owners are refused with `422`: their access is implicit in the org role.
///
/// Returns `404` if the user or tenant is not in this organization, `422`
/// for an unknown role name. Records
/// `organization.org_user_tenant_access_granted`, or
/// `organization.org_user_tenant_access_revoked` for an empty list.
pub(crate) async fn set_org_user_tenant_access(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgUserTenantPath>,
    Json(body): Json<SetOrgUserTenantAccessBody>,
) -> Result<NoContent, ApiError> {
    let request = body.for_member(path.member(), path.tenant()?)?;
    organization
        .members
        .set_tenant_access
        .execute(&member.caller, &member.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/grantable-roles",
    tag = "Organizations",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<GrantableRoleResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List the roles a member can be given in one tenant
///
/// The names of the tenant's roles, in name order, for choosing what to
/// pass to `PUT .../users/{user_id}/tenants/{tenant_slug}`. Works from an
/// organization session in any tenant or in none, and needs the right to
/// manage tenant access rather than a right inside the tenant.
///
/// Returns `404` if the tenant is not in this organization.
pub(crate) async fn list_grantable_roles(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Path(path): Path<OrgTenantPath>,
    Paging(page): Paging,
) -> Result<Json<PageResponse<GrantableRoleResponse>>, ApiError> {
    let request = ListGrantableRolesRequest {
        tenant_slug: path.tenant()?,
        page,
    };
    let roles = organization
        .members
        .grantable_roles
        .execute(&member.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(
        roles,
        GrantableRoleResponse::from,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/identities",
    tag = "Organizations",
    params(
        ("X-Linked-Session" = Option<String>, Header, description = "Bearer token of your session in an account already in the group; omit to start a new group")
    ),
    responses(
        (status = 204, description = "Linked"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody)
    )
)]
/// Link my accounts across tenants
///
/// Links the account you are signed in to in this tenant with your other
/// accounts in the organization, so you can switch between them without
/// signing in again. A link lets someone signed in to one account become
/// another, so you prove both ends with your own sign-in: this request's
/// session for the account joining, and, to join an existing group, your
/// session in one of its accounts in `X-Linked-Session`. Without it a new
/// group starts with this account. Nobody links accounts on someone else's
/// behalf. Records `organization.identity_linked`.
pub(crate) async fn link_identity(
    State(organization): State<OrganizationState>,
    linking: LinkingCaller,
) -> Result<NoContent, ApiError> {
    organization
        .members
        .link_identity
        .execute(&linking.person, &linking.auditor, ())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/identities",
    tag = "Organizations",
    request_body = UnlinkIdentityBody,
    responses(
        (status = 204, description = "Unlinked"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Take one of my accounts out of its group
///
/// The person signed in to one of the group's accounts takes the account in
/// `tenant_id` out of the group the `email` names. A group left with no
/// account goes. Returns `404` if no such link exists. Records
/// `organization.identity_unlinked`.
pub(crate) async fn unlink_own_identity(
    State(organization): State<OrganizationState>,
    tenant: TenantCaller,
    Json(body): Json<UnlinkIdentityBody>,
) -> Result<NoContent, ApiError> {
    let request = UnlinkIdentityRequest::try_from(body)?;
    organization
        .members
        .unlink_identity
        .execute(&Unlinker::Holder(tenant.caller), &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/identities",
    tag = "Organizations",
    request_body = UnlinkIdentityBody,
    responses(
        (status = 204, description = "Unlinked"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Remove a cross-tenant identity link
///
/// A member who may update members takes the account in `tenant_id` out of
/// the group of linked accounts the `email` names. A group left with no
/// account goes. Returns `404` if no such link exists, or `422` for an
/// invalid email. Records `organization.identity_unlinked`.
pub(crate) async fn unlink_identity(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<UnlinkIdentityBody>,
) -> Result<NoContent, ApiError> {
    let request = UnlinkIdentityRequest::try_from(body)?;
    organization
        .members
        .unlink_identity
        .execute(&Unlinker::Member(member.caller), &member.auditor, request)
        .await?;
    Ok(NoContent)
}
