//! User handlers: a tenant's users and their profiles, importing them, an
//! admin's reset of their password or factors, a person's own account and
//! preferences, and signing oneself up.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::identity::users::SendResetLinkRequest;
use ianua_assembly::identity::IdentityState;
use ianua_domain::shared::config::DomainLimits;

use crate::dto::identity::users::{
    FactorsClearedResponse, ImportResponse, ImportStartedResponse, ImportUsersBody,
    RegisterUserBody, RegisterUserResponse, ResetPasswordBody, ResetPasswordResponse, SignUpBody,
    SignUpRulesResponse, UpdateCurrentUserBody, UpdateDetailsBody, UpdateRecordsBody,
    UpdateStatusBody, UpdateUserBody, UserFilterParams, UserResponse, listed_values_of,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::identity::user_listing::{AttributeConditions, UserListing, UserOrder};
use crate::extractors::identity::visitors::TenantVisitor;
use crate::extractors::input_state::InputState;
use crate::extractors::json::Json;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::identity::{ImportPath, TenantPath, UserPath};
use crate::response::{Accepted, Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users",
    tag = "Users",
    request_body = RegisterUserBody,
    responses(
        (status = 201, description = "Created", body = RegisterUserResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan allows no more users", body = ErrorBody),
        (status = 404, description = "A named role does not exist", body = ErrorBody),
        (status = 409, description = "The address is taken", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Register a new user in the tenant
///
/// Creates an end user and mails a link to confirm their address. Without
/// `auto_verify` the account waits in `PendingVerification` and cannot sign
/// in until its holder follows the link. With `auto_verify: true` it is
/// `Active` at once, which needs the right to let accounts in; the address
/// still stays unconfirmed until the link is followed, since nobody vouches
/// for an address.
///
/// Supply a `password`, or omit it and the platform generates one, returned
/// as `generated_password`, the only time it is ever shown. A supplied
/// password is held to the tenant's password policy.
///
/// `role_ids` (or the older `role_id`) grants roles at creation, beside the
/// tenant's defaults; a role carrying something you cannot hand out is
/// refused. The tenant's user limit is checked before anything is made.
/// Records `identity.user_registered`. Requires the right to create users.
pub(crate) async fn register_user(
    InputState {
        use_cases: identity,
        limits,
    }: InputState<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<TenantPath>,
    Json(body): Json<RegisterUserBody>,
) -> Result<Created<RegisterUserResponse>, ApiError> {
    let new_user = body.new_user(&limits.display_name, path.link_scope())?;
    let registered = identity
        .users
        .register
        .execute(&tenant.caller, &tenant.auditor, new_user)
        .await?;
    Ok(Created(registered.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users",
    tag = "Users",
    params(UserFilterParams, AttributeConditions, UserOrder, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<UserResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or a sensitive attribute named without clearance", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "A filter or order the schema refuses", body = ErrorBody)
    )
)]
/// List users in the tenant
///
/// Returns a paginated, sortable page of users, optionally filtered by
/// `status` (an account status, or `PendingInvitation` /
/// `InvitationExpired` for an open invitation), an `email` or `name`
/// substring, a directly held `role_id`, a `group_id`, and when they last
/// signed in or were created (`last_login_from`/`last_login_until`,
/// `created_from`/`created_until`, RFC 3339).
/// Custom attributes filter with `attr=<namespace>.<key>:<operator>[:<value>]`
/// and order with `sort=attr:<namespace>.<key>`, each only as far as the
/// attribute was opened for it and the caller is cleared to see it.
///
/// Each entry carries its directly assigned roles, an invited user's
/// invitation state and the role accepting grants, and the custom fields
/// declared as listed that the caller may read. Read-only. Requires the
/// right to view users.
pub(crate) async fn list_users(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    UserListing {
        filter,
        attributes,
        order,
        page: pagination,
    }: UserListing,
) -> Result<Json<PageResponse<UserResponse>>, ApiError> {
    let request = filter.listing(attributes, order, pagination)?;
    let schema = identity
        .attributes
        .schema
        .execute(&tenant.caller, ())
        .await?;
    let page = identity.users.list.execute(&tenant.caller, request).await?;
    let values = identity
        .attributes
        .page_values
        .execute(&tenant.caller, listed_values_of(&page, &schema))
        .await?;
    Ok(Json(UserResponse::page(page, values)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}",
    tag = "Users",
    responses(
        (status = 200, description = "Success", body = UserResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a single user by id
///
/// Returns one user. Role assignments are not filled in here; use the list
/// endpoint when you need them. `404` when the id is unknown. Read-only.
/// Requires the right to view users.
pub(crate) async fn get_user(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<Json<UserResponse>, ApiError> {
    let user = identity
        .users
        .get
        .execute(&tenant.caller, path.user())
        .await?;
    Ok(Json(user.into()))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}",
    tag = "Users",
    request_body = UpdateUserBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The new address is taken", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update a user's profile
///
/// Patch any of `display_name`, `email` and `email_verified`, each applied
/// when present. A new display name renames the user (records
/// `identity.user_renamed`). A new email starts a pending change: a link is
/// mailed to it, and the user's current address stays in use until it is
/// followed. `email_verified: true` mails the current address a link that
/// confirms it: nobody vouches for an address, only the link marks it
/// verified.
///
/// Requires the right to edit the user's profile, or to change their
/// sign-in for an address, and holding at least everything the user holds.
pub(crate) async fn update_user(
    InputState {
        use_cases: identity,
        limits,
    }: InputState<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
    Json(body): Json<UpdateUserBody>,
) -> Result<NoContent, ApiError> {
    let edits = body.edits(path.user(), &limits.display_name, path.link_scope())?;
    let (caller, auditor) = (&tenant.caller, &tenant.auditor);
    if let Some(rename) = edits.rename {
        identity
            .users
            .rename
            .execute(caller, auditor, rename)
            .await?;
    }
    if let Some(change) = edits.change_email {
        identity
            .email
            .change
            .execute(caller, auditor, change)
            .await?;
    }
    if let Some(verification) = edits.verification {
        identity
            .email
            .send_verification
            .execute(caller, auditor, verification)
            .await?;
    }
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/deactivate",
    tag = "Users",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The tenant's last administrator", body = ErrorBody),
        (status = 422, description = "Already deactivated", body = ErrorBody)
    )
)]
/// Deactivate a user
///
/// Switches the account off: every delegation the user granted is revoked
/// and their sessions end. A deactivated user can be let in again through
/// the status endpoint. The tenant's last administrator cannot be shut out
/// (`409`). Records `identity.user_status_changed`. Requires the right to shut
/// users out, and holding at least everything the user holds.
pub(crate) async fn deactivate_user(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<NoContent, ApiError> {
    identity
        .users
        .deactivate
        .execute(&tenant.caller, &tenant.auditor, path.user())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}",
    tag = "Users",
    responses(
        (status = 204, description = "User permanently deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The tenant's last administrator", body = ErrorBody)
    )
)]
/// Delete a user
///
/// Removes the account for good, after revoking every delegation the user
/// granted and ending their sessions. Irreversible. `404` when the user does
/// not exist; the tenant's last administrator cannot be deleted (`409`).
/// Records `identity.user_deleted`. Requires the right to delete users, and
/// holding at least everything the user holds.
pub(crate) async fn delete_user(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<NoContent, ApiError> {
    identity
        .users
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.user())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/reset-password",
    tag = "Users",
    request_body = ResetPasswordBody,
    responses(
        (status = 200, description = "Password reset", body = ResetPasswordResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The user is deactivated", body = ErrorBody),
        (status = 422, description = "The password breaks the tenant's policy", body = ErrorBody)
    )
)]
/// Reset a user's password
///
/// Admin reset: sets a new password for another member and returns it once
/// for the admin to relay. Omit `password` and one meeting the tenant's
/// policy is generated. `password_breach` says what the breach lookup found;
/// a tenant that blocks breached passwords refuses one with `422`. The user
/// must change the password at their next sign-in. Every session the user holds ends, and devices they
/// remembered stop skipping the second factor. Records
/// `identity.password_reset`. Requires the right to change the
/// user's sign-in, and holding at least everything the user holds.
pub(crate) async fn reset_password(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
    Json(body): Json<ResetPasswordBody>,
) -> Result<Json<ResetPasswordResponse>, ApiError> {
    let reset = identity
        .users
        .reset_password
        .execute(&tenant.caller, &tenant.auditor, body.request(path.user()))
        .await?;
    Ok(Json(reset.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/status",
    tag = "Users",
    request_body = UpdateStatusBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or a status no admin moves a user into", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Shutting out the tenant's last administrator", body = ErrorBody),
        (status = 422, description = "The status rules refuse the move", body = ErrorBody)
    )
)]
/// Change a user's status
///
/// `Active` unlocks a locked account and lets any other one in, a
/// deactivated one included. `Locked` and `Deactivated` first revoke every
/// delegation the user granted and end their sessions. `Invited`,
/// `PendingVerification` and `Closing` are reached only through their own
/// flows (`403`). Records `identity.user_status_changed`. Requires the right to let
/// users in or shut them out, and holding at least everything the user
/// holds.
pub(crate) async fn update_status(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
    Json(body): Json<UpdateStatusBody>,
) -> Result<NoContent, ApiError> {
    identity
        .users
        .update_status
        .execute(&tenant.caller, &tenant.auditor, body.request(path.user()))
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me",
    tag = "Users",
    request_body = UpdateCurrentUserBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update my preferences
///
/// Sets the calling user's own `locale` and `timezone`. Each is applied
/// when present and left unchanged when omitted or `null`, and overrides
/// the tenant default. `422` for an unrecognized locale or timezone.
/// Records `identity.user_preferences_updated`. Requires a tenant user's own
/// session.
pub(crate) async fn update_current_user(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Json(body): Json<UpdateCurrentUserBody>,
) -> Result<NoContent, ApiError> {
    identity
        .users
        .update_preferences
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me",
    tag = "Users",
    responses(
        (status = 200, description = "The signed-in person's own account", body = UserResponse),
        (status = 401, description = "Unauthenticated, or not a tenant user's own session", body = ErrorBody),
        (status = 403, description = "The tenant is not available", body = ErrorBody)
    )
)]
/// Get my account
///
/// The signed-in tenant user's own account: name, address, status,
/// preferences and profile. Needs no right to view users. Roles are not
/// filled in. Read-only. Requires a tenant user's own session.
pub(crate) async fn get_current_user(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
) -> Result<Json<UserResponse>, ApiError> {
    let user = identity.users.get_me.execute(&tenant.caller, ()).await?;
    Ok(Json(user.into()))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/details",
    tag = "Users",
    request_body = UpdateDetailsBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the user holds more than the caller", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Replace a user's personal details
///
/// Sets the given and family name, the name they go by, their picture and
/// their phone number, all at once: a field left out is cleared. A person
/// changes their own with their session; anyone else needs the right to
/// edit the user's profile and to hold at least everything the user holds.
/// A phone number here is the person's word and nothing sends codes to it.
/// Records `identity.user_profile_updated`, naming the fields that changed.
pub(crate) async fn update_details(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
    Json(body): Json<UpdateDetailsBody>,
) -> Result<NoContent, ApiError> {
    let request = body.request(path.whose(&tenant.caller))?;
    identity
        .users
        .update_details
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/records",
    tag = "Users",
    request_body = UpdateRecordsBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the user holds more than the caller", body = ErrorBody),
        (status = 404, description = "The user, or the manager named, is not in the tenant", body = ErrorBody),
        (status = 422, description = "Validation error, or the user named as their own manager", body = ErrorBody)
    )
)]
/// Replace a user's directory records
///
/// Sets what the company's directory records about a user: the id another
/// directory knows them by, their department, their manager and their
/// employee number, all at once: a field left out is cleared. These are the
/// company's records, so the person alone never changes them. Records
/// `identity.user_profile_updated`. Requires the right to update users, and
/// holding at least everything the user holds.
pub(crate) async fn update_records(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
    Json(body): Json<UpdateRecordsBody>,
) -> Result<NoContent, ApiError> {
    identity
        .users
        .update_records
        .execute(&tenant.caller, &tenant.auditor, body.request(path.user())?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/import",
    tag = "Users",
    request_body = ImportUsersBody,
    responses(
        (status = 202, description = "The import is kept and queued", body = ImportStartedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan has no room for every record", body = ErrorBody),
        (status = 422, description = "A record, a hash or the batch is refused", body = ErrorBody)
    )
)]
/// Import users from another system
///
/// Imports exported accounts with their existing password hashes
/// (Argon2id, bcrypt, scrypt or PBKDF2-SHA256). Every record is checked
/// first, and a batch with one that does not check out is refused whole.
/// The import is then kept and answered with its id; a worker opens the
/// accounts in chunks of 500, each chunk kept whole, and
/// `GET .../users/imports/{id}` says how far it got. A record whose
/// address has an account by the time it is reached is set aside and
/// listed there; the rest go on. Each account waits for its holder to
/// follow the link mailed to its address once its chunk is kept; the person
/// then signs in with the password they already have, and that sign-in
/// replaces the foreign hash. The plan's room for users must hold every
/// record when the import starts, and is checked again for each chunk as it
/// runs: a record past the room left by then, say after another import, is
/// set aside as `user_limit_reached`. Records `identity.user_imported` for each account and
/// `identity.users_imported` once the import ends. Requires the right to
/// create users.
pub(crate) async fn import_users(
    InputState {
        use_cases: identity,
        limits,
    }: InputState<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<TenantPath>,
    Json(body): Json<ImportUsersBody>,
) -> Result<Accepted<ImportStartedResponse>, ApiError> {
    let request = body.request(&limits.display_name, path.link_scope())?;
    let import_id = identity
        .users
        .import
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Accepted(import_id.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/imports/{id}",
    tag = "Users",
    responses(
        (status = 200, description = "Where the import stands", body = ImportResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Show how an import is going
///
/// Where an import of users stands (`pending`, `running`, `finished` or
/// `failed`), how many records it holds, opened and set aside, and for each
/// record set aside its line in the request and why. It never shows an
/// address or a password hash. Requires the right to view users.
pub(crate) async fn get_import(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<ImportPath>,
) -> Result<Json<ImportResponse>, ApiError> {
    let import = identity
        .users
        .get_import
        .execute(&tenant.caller, path.import())
        .await?;
    Ok(Json(ImportResponse::from(&import)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/send-reset-link",
    tag = "Users",
    responses(
        (status = 204, description = "The link is on its way"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the user holds more than the caller", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "A link went to this address moments ago", body = ErrorBody)
    )
)]
/// Mail a user a password reset link
///
/// The alternative to choosing a password for someone: the user is mailed a
/// link and sets their own, so the admin never learns it. Records
/// `authentication.password_reset_requested`. Requires the right to change
/// the user's sign-in, and holding at least everything the user holds.
pub(crate) async fn send_reset_link(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<NoContent, ApiError> {
    let request = SendResetLinkRequest {
        user_id: path.user(),
        scope: path.link_scope(),
    };
    identity
        .users
        .send_reset_link
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/reset-factors",
    tag = "Users",
    responses(
        (status = 200, description = "What was cleared", body = FactorsClearedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the user holds more than the caller", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Clear a user's second factor and passkeys
///
/// For someone who lost their device and their recovery codes: turns off
/// their second factor, in force or being set up, and removes their
/// passkeys, so they can sign in with their password and set up new ones.
/// Their sessions end. Records `authentication.factors_reset`. Requires the
/// right to change the user's sign-in, and holding at least everything the
/// user holds.
pub(crate) async fn reset_factors(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<Json<FactorsClearedResponse>, ApiError> {
    let cleared = identity
        .users
        .reset_factors
        .execute(&tenant.caller, &tenant.auditor, path.user())
        .await?;
    Ok(Json(cleared.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/sign-up",
    tag = "Authentication",
    responses(
        (status = 200, description = "Whether the tenant takes sign-ups, and its password rules", body = SignUpRulesResponse),
        (status = 404, description = "Unknown organization or tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Check whether a tenant takes sign-ups
///
/// Tells a sign-in page whether to offer sign-up, and which rules a
/// password must meet. It answers as a sign-up would be answered, so the
/// form never offers what the submit refuses. Public: no session required.
pub(crate) async fn sign_up_rules(
    State(identity): State<IdentityState>,
    visitor: TenantVisitor,
) -> Result<Json<SignUpRulesResponse>, ApiError> {
    let policy = identity
        .users
        .sign_up_rules
        .execute(&visitor.tenant, ())
        .await?;
    Ok(Json(policy.into()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/auth/sign-up",
    tag = "Authentication",
    request_body = SignUpBody,
    responses(
        (status = 204, description = "If the address is free, the account was created and a verification link sent"),
        (status = 403, description = "The tenant does not take sign-ups, or is at its user limit", body = ErrorBody),
        (status = 404, description = "Unknown organization or tenant", body = ErrorBody),
        (status = 422, description = "Validation error, including a password that breaks the tenant's rules", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Sign yourself up to a tenant
///
/// Creates an account in a tenant whose administrators turned sign-up on,
/// and mails its address a verification link. The account cannot sign in
/// until its owner follows it. Answers `204` whether or not the address
/// already has an account, so the form cannot tell anyone who is
/// registered. Records `identity.user_registered` for a new account.
/// Public: no session required.
pub(crate) async fn sign_up(
    State(identity): State<IdentityState>,
    State(limits): State<DomainLimits>,
    visitor: TenantVisitor,
    Json(body): Json<SignUpBody>,
) -> Result<NoContent, ApiError> {
    let request = body.request(&limits.display_name, visitor.plan_limits, visitor.scope)?;
    identity
        .users
        .sign_up
        .execute(&visitor.tenant, &visitor.auditor, request)
        .await?;
    Ok(NoContent)
}
