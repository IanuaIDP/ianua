//! Organization sign-in handlers: password login, mailed sign-in links, the
//! emailed confirmation, sessions, remembered devices and moving between
//! tenants.

use axum::extract::{Path, State};
use ianua_app::ports::organization::OrgSessionSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::organization::sign_in::{
    ListActiveSessionsRequest, RevokeMemberSessionRequest,
};
use ianua_assembly::organization::OrganizationState;
use ianua_domain::types::{Email, SessionId, TenantId, TrustedDeviceId};

use crate::dto::organization::sign_in::{
    ActiveSessionResponse, LinkedTenantSwitchBody, LinkedTenantSwitchResponse,
    MovedOrgSessionResponse, OrgConfirmSignInBody, OrgConfirmedSignInResponse,
    OrgDeviceListResponse, OrgLoginBody, OrgLoginResponse, OrgLogoutBody, OrgMagicLinkBody,
    OrgMagicLinkConfirmBody, OrgRevokeDeviceBody, OrgTrustDeviceBody, OrgTrustDeviceResponse,
    SwitchOrgTenantBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::{OrgMember, RequestMeta, TenantCaller, Visitor};
use crate::extractors::json::Json;
use crate::extractors::organization::OrgSteward;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::organization::OrgSessionPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/login",
    tag = "Authentication",
    request_body = OrgLoginBody,
    responses(
        (status = 200, description = "Success", body = OrgLoginResponse),
        (status = 401, description = "Sign-in is under pressure and this device must pass a challenge first (`challenge_required`, naming it in `challenge`)", body = ErrorBody),
        (status = 403, description = "Forbidden (e.g. organization not active, address not confirmed)", body = ErrorBody),
        (status = 404, description = "Invalid credentials (unknown email or wrong password)", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests, or the server is busy checking passwords (with `Retry-After`)", body = ErrorBody)
    )
)]
/// Log in as an organization user
///
/// Public dashboard sign-in by email/password, without organization or tenant path slugs.
/// Returns `session_id`, bearer `refresh_token`, organization and the requested `tenant_slug`
/// or first reachable active tenant. With no tenant access, tenant fields are `null`;
/// `…/switch-tenant` can enter one granted later.
/// Unknown addresses, wrong passwords and locked/deactivated/invited accounts all give `404`.
/// Correct passwords can reveal `403 email_not_verified`, or a password/network policy refusal.
/// `mfa_required` limits the session to completing sign-in: `…/mfa/verify`, enrollment when
/// `mfa_enrollment_required`, or a mailed link when `email_confirmation_required`.
/// If the password matches several organizations, no session opens: `status: "choose_organization"`
/// lists them. Repeat credentials with `organization`. Records `organization.org_login_succeeded`
/// or, for known-account refusals, `organization.org_login_failed`.
/// Under sign-in pressure, an unremembered `fingerprint_hash` gets `401 challenge_required`
/// before password checking. Solve `challenge` (absent if unavailable) and send `challenge_proof`.
/// Counts are per named organization or shared if unnamed, with identical answers for all addresses; capacity gives `429`/`Retry-After`.
pub(crate) async fn password_login(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgLoginBody>,
) -> Result<Json<OrgLoginResponse>, ApiError> {
    let outcome = organization
        .sign_in
        .password_login
        .execute(&(), &visitor.auditor, body.into_request(visitor.meta)?)
        .await?;
    Ok(Json(OrgLoginResponse::from(outcome)))
}

#[utoipa::path(
    post,
    path = "/api/v1/login/magic-link",
    tag = "Authentication",
    request_body = OrgMagicLinkBody,
    responses(
        (status = 204, description = "A link went to the address, if a member could use one"),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Ask for a sign-in link
///
/// Mails a link that signs a member in to the dashboard without a
/// password. An address may hold an account in several organizations: each
/// account that may sign in by mail gets its own link, naming its
/// organization, so following one is the choice. Each link replaces the
/// ones sent before it and works once, for a few minutes.
///
/// Always answers `204`, whether or not the address has an account and
/// whether or not a link went, no sooner than a fixed floor, so the answer
/// tells nobody which addresses have accounts. An organization that signs
/// its members in through single sign-on, or does not allow mailed links,
/// gets no link. Records `organization.org_magic_link_requested` for each
/// link sent. Public, limited per address.
pub(crate) async fn request_magic_link(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgMagicLinkBody>,
) -> Result<NoContent, ApiError> {
    organization
        .sign_in
        .magic_link_request
        .execute(&(), &visitor.auditor, Email::try_from(body)?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/login/magic-link/verify",
    tag = "Authentication",
    request_body = OrgMagicLinkConfirmBody,
    responses(
        (status = 200, description = "Signed in", body = OrgLoginResponse),
        (status = 403, description = "The organization does not take a mailed link from here, or signs in through single sign-on", body = ErrorBody),
        (status = 404, description = "The link is unknown, used or replaced", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Sign in with a mailed link
///
/// Spends the `token` from a link `…/login/magic-link` mailed and opens a
/// session for its member, as a password sign-in does: in the tenant named
/// by `tenant_slug`, or the first they reach. Following the link proves the
/// mailbox; a member with a second factor still owes it (`mfa_required`).
/// A link refused for the organization's settings stays unspent. Records
/// `organization.org_login_succeeded`, or `organization.org_login_failed`
/// for a refused link of a known member. Public.
pub(crate) async fn confirm_magic_link(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgMagicLinkConfirmBody>,
) -> Result<Json<OrgLoginResponse>, ApiError> {
    let success = organization
        .sign_in
        .magic_link
        .execute(&(), &visitor.auditor, body.into_request(visitor.meta)?)
        .await?;
    Ok(Json(OrgLoginResponse::from(success)))
}

#[utoipa::path(
    post,
    path = "/api/v1/login/confirm",
    tag = "Authentication",
    request_body = OrgConfirmSignInBody,
    responses(
        (status = 200, description = "Sign-in confirmed", body = OrgConfirmedSignInResponse),
        (status = 403, description = "The link is unknown, used or another member's", body = ErrorBody),
        (status = 404, description = "No live sign-in holds the refresh token", body = ErrorBody),
        (status = 409, description = "The sign-in owes nothing", body = ErrorBody),
        (status = 410, description = "The link expired", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Confirm a sign-in from the mailbox
///
/// Finishes a member's sign-in that waits for them to confirm it from
/// their mailbox (`email_confirmation_required` at login). Send the
/// `token` from the mailed link and the `refresh_token` of the waiting
/// sign-in, which the browser that began it holds. Neither alone finishes
/// anything: the link proves the mailbox, the refresh token names the
/// sign-in it confirms.
///
/// When the organization requires a second factor the member has not set
/// up, `mfa_enrollment_required` is `true` and they set one up next.
/// Records `organization.org_mfa_verified`. Public.
pub(crate) async fn confirm_sign_in(
    State(organization): State<OrganizationState>,
    visitor: Visitor,
    Json(body): Json<OrgConfirmSignInBody>,
) -> Result<Json<OrgConfirmedSignInResponse>, ApiError> {
    let confirmed = organization
        .sign_in
        .confirm_by_email
        .execute(&(), &visitor.auditor, body.into())
        .await?;
    Ok(Json(OrgConfirmedSignInResponse::from(confirmed)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/logout",
    tag = "Organizations",
    request_body = OrgLogoutBody,
    responses(
        (status = 204, description = "Logged out"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not one of the caller's sessions", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
    )
)]
/// Log out of the organization
///
/// Revokes one of the caller's own org sessions by its `session_id`,
/// invalidating its refresh token immediately. Send the session id you want
/// to end (typically the current one). Returns `404` for a session that is
/// not the caller's and `422` for a malformed session id. Ending another
/// member's session is `…/sessions/{session_id}/revoke`. Records
/// `organization.org_session_revoked`. Requires the member's own session.
pub(crate) async fn logout(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<OrgLogoutBody>,
) -> Result<NoContent, ApiError> {
    organization
        .sign_in
        .logout
        .execute(&member.caller, &member.auditor, SessionId::try_from(body)?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/sessions/active",
    tag = "Organizations",
    params(SortQuery<OrgSessionSortField>, PaginationParams),
    responses(
        (status = 200, description = "Active sessions", body = PageResponse<ActiveSessionResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
    )
)]
/// List active sessions
///
/// Returns the organization's currently live sessions (across all org
/// users), sortable and paginated, each with geo coordinates and client
/// info for the "where am I logged in" security view. Read-only. Requires
/// a member who may view the organization's sessions.
pub(crate) async fn list_active_sessions(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    SortQuery(sort): SortQuery<OrgSessionSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<ActiveSessionResponse>>, ApiError> {
    let page = organization
        .sign_in
        .active_sessions
        .execute(
            &member.caller,
            ListActiveSessionsRequest {
                sort,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        ActiveSessionResponse::from,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/sessions/{session_id}/revoke",
    tag = "Organizations",
    responses(
        (status = 204, description = "Session ended"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such session in this organization", body = ErrorBody),
        (status = 422, description = "The session already ended", body = ErrorBody),
    )
)]
/// End a member's session
///
/// Signs another member out of one session, invalidating its refresh token
/// immediately: for a lost laptop or a session that looks unfamiliar in
/// the active-session list. A platform action: taken by a member who may
/// update members, or by an operator for the platform. Records
/// `organization.org_session_revoked`.
pub(crate) async fn revoke_session(
    State(organization): State<OrganizationState>,
    steward: OrgSteward,
    Path(path): Path<OrgSessionPath>,
) -> Result<NoContent, ApiError> {
    organization
        .sign_in
        .revoke_session
        .execute(
            &steward.caller,
            &steward.auditor,
            RevokeMemberSessionRequest {
                organization_id: steward.organization,
                session_id: path.session(),
            },
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/devices",
    tag = "Organizations",
    responses(
        (status = 200, description = "Success", body = OrgDeviceListResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List trusted devices
///
/// Returns the signed-in org user's own devices, in the order they were
/// trusted. Revoked ones are kept for history and still listed: read
/// `status` to tell them apart, since only a `trusted` device skips MFA.
/// Requires the member's own session.
pub(crate) async fn list_devices(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<OrgDeviceListResponse>, ApiError> {
    let devices = organization
        .sign_in
        .list_devices
        .execute(&member.caller, ())
        .await?;
    Ok(Json(OrgDeviceListResponse::of(&devices)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/devices",
    tag = "Organizations",
    request_body = OrgTrustDeviceBody,
    responses(
        (status = 201, description = "Created", body = OrgTrustDeviceResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The sign-in proved no second factor", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Trust this device
///
/// Remembers the device the caller is signing in from, so later sign-ins
/// from it can skip MFA step-up. Only a sign-in that proved a second factor
/// may remember a device. Send the secret the browser made for itself
/// (`fingerprint_hash`, 64 hex digits); only its digest is kept.
///
/// The IP and User-Agent recorded come from this request, not from the
/// body: the list is a security surface, and a client that could name its
/// own IP could make a strange device look familiar.
///
/// **State.** Registers the device as `Trusted`. Returns `409` once the
/// caller holds the maximum number of trusted devices: revoke one to free a
/// slot. Records `organization.org_device_trusted`.
pub(crate) async fn trust_device(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    meta: RequestMeta,
    Json(body): Json<OrgTrustDeviceBody>,
) -> Result<Created<OrgTrustDeviceResponse>, ApiError> {
    let device = organization
        .sign_in
        .trust_device
        .execute(&member.caller, &member.auditor, body.into_request(meta)?)
        .await?;
    Ok(Created(OrgTrustDeviceResponse::from(device)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/devices/revoke",
    tag = "Organizations",
    request_body = OrgRevokeDeviceBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Revoke a trusted device
///
/// Drops the MFA skip for one of the caller's own devices. Use it the
/// moment a laptop is lost, sold, or looks unfamiliar in the list.
///
/// **State.** Moves the device `Trusted → Revoked`, which is terminal: it
/// must be trusted again from scratch. Returns `404` for a device belonging
/// to anyone else, so the endpoint cannot be used to probe for device ids,
/// and `409` for one already revoked. Records
/// `organization.org_device_revoked`.
pub(crate) async fn revoke_device(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<OrgRevokeDeviceBody>,
) -> Result<NoContent, ApiError> {
    organization
        .sign_in
        .revoke_device
        .execute(
            &member.caller,
            &member.auditor,
            TrustedDeviceId::try_from(body)?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/switch-tenant",
    tag = "Organizations",
    request_body = SwitchOrgTenantBody,
    responses(
        (status = 200, description = "The session that replaced the old one", body = MovedOrgSessionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "The member may not reach that tenant", body = ErrorBody),
        (status = 404, description = "No such tenant in this organization", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
    )
)]
/// Move to another tenant
///
/// Swaps the caller's organization session for a new one working in
/// `tenant_id`, without signing in again. An organization session works in
/// one tenant, or on the organization alone; moving is checked against the
/// member's grants as signing in is: an owner reaches every tenant of the
/// organization, a plain member only those they were let into. A member
/// who signed in before they were granted a tenant moves into it here.
///
/// The new session carries the sign-in on and ends when the old one would
/// have, so moving never extends a sign-in. The old session and its refresh
/// token stop working in the same step: use the `refresh_token` returned.
/// Records `organization.org_session_moved`. Requires the member's own
/// finished session.
pub(crate) async fn switch_tenant(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<SwitchOrgTenantBody>,
) -> Result<Json<MovedOrgSessionResponse>, ApiError> {
    let moved = organization
        .sign_in
        .switch_tenant
        .execute(&member.caller, &member.auditor, TenantId::from(body))
        .await?;
    Ok(Json(MovedOrgSessionResponse::from(moved)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/tenant/switch",
    tag = "Authentication",
    request_body = LinkedTenantSwitchBody,
    responses(
        (status = 200, description = "Success", body = LinkedTenantSwitchResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Switch tenant
///
/// Moves a tenant user to a linked account in the same organization without
/// password re-entry, for the tenant switcher.
///
/// Who switches comes from the caller's own session, never from the body:
/// their account names its linked identity by address, and the link must
/// lead back to that very account, both accounts must still hold the
/// group's verified address, and the target tenant must admit the sign-in
/// carried over. A sign-in that proved no second factor owes what a
/// sign-in to the target account would, shown by `mfa_required` and its
/// companions.
///
/// **Session status.** Opens an **`Active`** session for the linked account
/// in the target tenant. Records `organization.tenant_switched`.
pub(crate) async fn linked_switch(
    State(organization): State<OrganizationState>,
    tenant: TenantCaller,
    Json(body): Json<LinkedTenantSwitchBody>,
) -> Result<Json<LinkedTenantSwitchResponse>, ApiError> {
    let switched = organization
        .sign_in
        .linked_switch
        .execute(&tenant.caller, &tenant.auditor, TenantId::try_from(body)?)
        .await?;
    Ok(Json(LinkedTenantSwitchResponse::from(switched)))
}
