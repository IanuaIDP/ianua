//! Identity endpoints: a tenant's users, their profiles, sessions and
//! sign-in history, invitations, addresses, custom attributes, privacy
//! requests and support impersonations, signing up, and an organization
//! member's own address.

use std::time::Duration;

use axum::Router;
use utoipa::OpenApi;

use crate::dto::authentication::password::PasswordBreachResponse;
use crate::dto::identity::attributes::{
    AttributeDeletedResponse, AttributeKindResponse, AttributeResponse, AttributeStatusBody,
    DeclareAttributeBody, SetAttributeValueBody, UpdateAttributeBody, UserAttributeValuesResponse,
};
use crate::dto::identity::email::RequestEmailChangeBody;
use crate::dto::identity::impersonation::{
    ActingAsResponse, ImpersonationBody, ImpersonationRequestedResponse, ImpersonationResponse,
};
use crate::dto::identity::invitations::{
    AcceptInvitationBody, InvitationLinkResponse, InviteUserBody, InviteUserResponse,
};
use crate::dto::identity::links::{
    ConfirmEmailChangeBody, PasswordLinkStatusResponse, TokenResentResponse, TokenStatusBody,
    TokenStatusDto, TokenStatusResponse, VerificationResentResponse, VerificationTokenStatusDto,
    VerificationTokenStatusResponse, VerifyEmailBody,
};
use crate::dto::identity::privacy::{
    ConsentBody, ConsentRecordResponse, ErasureBody, ErasureRequestResponse, ExportBody,
    ExportDownloadResponse, ExportRequestedResponse, ExportResponse, ExportScopeBody,
};
use crate::dto::identity::sessions::{SessionResponse, SignedOutResponse};
use crate::dto::identity::users::{
    FactorsClearedResponse, ImportErrorResponse, ImportResponse, ImportStartedResponse,
    ImportUserBody, ImportUsersBody, MemberStatusFilter, ProfileResponse, RegisterUserBody,
    RegisterUserResponse, ResetPasswordBody, ResetPasswordResponse, SignUpBody,
    SignUpRulesResponse, UpdateCurrentUserBody, UpdateDetailsBody, UpdateRecordsBody,
    UpdateStatusBody, UpdateUserBody, UserResponse, UserRoleInfo,
};
use crate::handlers::identity::{
    attributes, email, impersonation, invitations, privacy, sessions, users,
};
use crate::method::{delete, get, patch, post, put, shared};
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::state::ApiState;

/// The identity endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let tenant = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";
    let org = "/api/v1/organizations/{org_slug}";
    Router::new()
        .merge(user_routes(tenant))
        .merge(user_profile_routes(&format!("{tenant}/users")))
        .merge(session_routes(tenant))
        .merge(invitation_routes(&format!("{tenant}/users")))
        .merge(tenant_email_routes(tenant))
        .merge(attribute_routes(tenant))
        .merge(privacy_routes(&format!("{tenant}/users")))
        .merge(impersonation_routes(tenant))
        .merge(org_email_routes(&format!("{org}/email")))
}

/// The identity endpoints reached before anyone is identified (signing up,
/// and following an emailed link), limited per client address: each can
/// hash a password, send mail or test a link token.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let tenant = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";
    let org = "/api/v1/organizations/{org_slug}";
    let limiter = per_address(
        state,
        state.http.rate.login_per_minute,
        Duration::from_secs(60),
    );
    public_invitation_routes(tenant)
        .merge(public_email_routes(tenant))
        .merge(public_org_email_routes(org))
        .route(
            &format!("{tenant}/users/erasure/cancel-by-link"),
            post(privacy::cancel_erasure_by_link),
        )
        .route(
            &format!("{tenant}/auth/sign-up"),
            get(users::sign_up_rules).post(shared(users::sign_up)),
        )
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// Registers invitation answers and recovery before a person signs in.
fn public_invitation_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/users/accept-invitation"),
            post(invitations::accept_invitation),
        )
        .route(
            &format!("{tenant}/users/decline-invitation"),
            post(invitations::decline_invitation),
        )
        .route(
            &format!("{tenant}/users/invitation-status"),
            post(invitations::invitation_status),
        )
        .route(
            &format!("{tenant}/users/invitation-resend"),
            post(invitations::invitation_resend),
        )
}

/// Registers mailed proofs and status reads for a tenant user's address.
fn public_email_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/users/email/confirm-change"),
            post(email::confirm_email_change),
        )
        .route(
            &format!("{tenant}/users/email/cancel-change"),
            post(email::cancel_email_change),
        )
        .route(
            &format!("{tenant}/users/email/change-status"),
            post(email::email_change_status),
        )
        .route(
            &format!("{tenant}/users/email/change-resend"),
            post(email::email_change_resend),
        )
        .route(
            &format!("{tenant}/users/verify-email"),
            post(email::verify_email),
        )
        .route(
            &format!("{tenant}/users/verify-email/status"),
            post(email::verification_status),
        )
        .route(
            &format!("{tenant}/users/verify-email/resend"),
            post(email::resend_verification),
        )
}

/// Registers mailed proofs and status reads for an organization member's address.
fn public_org_email_routes(org: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{org}/email/confirm-change"),
            post(email::org_confirm_email_change),
        )
        .route(
            &format!("{org}/email/cancel-change"),
            post(email::org_cancel_email_change),
        )
        .route(
            &format!("{org}/email/change-status"),
            post(email::org_email_change_status),
        )
        .route(
            &format!("{org}/email/change-resend"),
            post(email::org_email_change_resend),
        )
}

/// A tenant's users and the caller's own preferences.
fn user_routes(tenant: &str) -> Router<ApiState> {
    let users_path = format!("{tenant}/users");
    Router::new()
        .route(
            &users_path,
            post(users::register_user).get(shared(users::list_users)),
        )
        .route(
            &format!("{users_path}/{{id}}"),
            get(users::get_user)
                .patch(shared(users::update_user))
                .delete(shared(users::delete_user)),
        )
        .route(
            &format!("{users_path}/{{id}}/deactivate"),
            post(users::deactivate_user),
        )
        .route(
            &format!("{users_path}/{{id}}/reset-password"),
            post(users::reset_password),
        )
        .route(
            &format!("{users_path}/{{id}}/status"),
            post(users::update_status),
        )
        .route(
            &format!("{tenant}/me"),
            get(users::get_current_user).patch(shared(users::update_current_user)),
        )
}

/// A user's profile, their sign-in factors as an admin resets them, and
/// bringing users over from another system.
fn user_profile_routes(users_path: &str) -> Router<ApiState> {
    Router::new()
        .route(&format!("{users_path}/import"), post(users::import_users))
        .route(
            &format!("{users_path}/imports/{{id}}"),
            get(users::get_import),
        )
        .route(
            &format!("{users_path}/{{id}}/details"),
            put(users::update_details),
        )
        .route(
            &format!("{users_path}/{{id}}/records"),
            put(users::update_records),
        )
        .route(
            &format!("{users_path}/{{id}}/send-reset-link"),
            post(users::send_reset_link),
        )
        .route(
            &format!("{users_path}/{{id}}/reset-factors"),
            post(users::reset_factors),
        )
}

/// A user's sessions and sign-in history, the caller's own and another's.
fn session_routes(tenant: &str) -> Router<ApiState> {
    let me = format!("{tenant}/me");
    let user = format!("{tenant}/users/{{id}}");
    Router::new()
        .route(&format!("{me}/sessions"), get(sessions::list_my_sessions))
        .route(
            &format!("{me}/sessions/sign-out-others"),
            post(sessions::sign_out_other_sessions),
        )
        .route(
            &format!("{me}/sessions/{{session_id}}"),
            delete(sessions::revoke_my_session),
        )
        .route(&format!("{me}/sign-ins"), get(sessions::list_my_sign_ins))
        .route(
            &format!("{user}/sessions"),
            get(sessions::list_user_sessions),
        )
        .route(
            &format!("{user}/sessions/{{session_id}}"),
            delete(sessions::revoke_user_session),
        )
        .route(
            &format!("{user}/sign-ins"),
            get(sessions::list_user_sign_ins),
        )
}

/// A tenant admin acting as a user for support, and the person's answer.
fn impersonation_routes(tenant: &str) -> Router<ApiState> {
    let impersonations = format!("{tenant}/impersonations");
    Router::new()
        .route(
            &format!("{tenant}/users/{{id}}/impersonations"),
            post(impersonation::request_impersonation),
        )
        .route(&impersonations, get(impersonation::list_impersonations))
        .route(
            &format!("{impersonations}/{{id}}/approve"),
            post(impersonation::approve_impersonation),
        )
        .route(
            &format!("{impersonations}/{{id}}/decline"),
            post(impersonation::decline_impersonation),
        )
        .route(
            &format!("{impersonations}/{{id}}/end"),
            post(impersonation::end_impersonation),
        )
        .route(
            &format!("{impersonations}/{{id}}/act-as"),
            post(impersonation::act_as),
        )
}

/// Inviting people, and their answers.
fn invitation_routes(users_path: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{users_path}/invite"),
            post(invitations::invite_user),
        )
        .route(
            &format!("{users_path}/{{id}}/resend-invitation"),
            post(invitations::resend_invitation),
        )
        .route(
            &format!("{users_path}/{{id}}/revoke-invitation"),
            post(invitations::revoke_invitation),
        )
        .route(
            &format!("{users_path}/{{id}}/send-welcome"),
            post(invitations::send_welcome),
        )
}

/// A tenant user's address: confirming it and moving it.
fn tenant_email_routes(tenant: &str) -> Router<ApiState> {
    let users_path = format!("{tenant}/users");
    Router::new()
        .route(
            &format!("{tenant}/me/email/request-change"),
            post(email::request_email_change),
        )
        .route(
            &format!("{users_path}/{{id}}/send-verification"),
            post(email::send_verification),
        )
}

/// The tenant's declared custom fields and each user's values.
///
/// `kinds` is a literal segment, so it is read as itself rather than as a
/// namespace called "kinds".
fn attribute_routes(tenant: &str) -> Router<ApiState> {
    let declared = format!("{tenant}/user-attributes");
    let values = format!("{tenant}/users/{{id}}/attributes");
    Router::new()
        .route(
            &format!("{declared}/kinds"),
            get(attributes::list_attribute_kinds),
        )
        .route(
            &declared,
            get(attributes::list_user_attributes).post(shared(attributes::declare_user_attribute)),
        )
        .route(
            &format!("{declared}/{{namespace}}/{{key}}"),
            patch(attributes::update_user_attribute)
                .delete(shared(attributes::delete_user_attribute)),
        )
        .route(
            &format!("{declared}/{{namespace}}/{{key}}/status"),
            put(attributes::set_user_attribute_status),
        )
        .route(
            &values,
            get(attributes::get_user_attribute_values)
                .delete(shared(attributes::delete_user_attribute_values)),
        )
        .route(
            &format!("{values}/{{namespace}}/{{key}}"),
            put(attributes::set_user_attribute_value),
        )
}

/// Consent and erasure.
fn privacy_routes(users_path: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{users_path}/{{id}}/consent"),
            post(privacy::grant_or_revoke_consent).get(shared(privacy::consent_history)),
        )
        .route(
            &format!("{users_path}/{{id}}/exports"),
            post(privacy::request_export).get(shared(privacy::list_exports)),
        )
        .route(
            &format!("{users_path}/exports/{{id}}/download"),
            post(privacy::download_export),
        )
        .route(
            &format!("{users_path}/{{id}}/erasure"),
            post(privacy::request_erasure),
        )
        .route(
            &format!("{users_path}/erasure/{{id}}/cancel"),
            post(privacy::cancel_erasure),
        )
        .route(
            &format!("{users_path}/erasure/{{id}}/hold"),
            post(privacy::hold_erasure),
        )
        .route(
            &format!("{users_path}/erasure/{{id}}/release"),
            post(privacy::release_erasure),
        )
}

/// An organization member's own address.
fn org_email_routes(email_path: &str) -> Router<ApiState> {
    Router::new().route(
        &format!("{email_path}/request-change"),
        post(email::org_request_email_change),
    )
}

/// The identity part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        users::register_user,
        users::list_users,
        users::get_user,
        users::update_user,
        users::deactivate_user,
        users::delete_user,
        users::reset_password,
        users::update_status,
        users::update_current_user,
        users::get_current_user,
        users::update_details,
        users::update_records,
        users::import_users,
        users::get_import,
        users::send_reset_link,
        users::reset_factors,
        users::sign_up_rules,
        users::sign_up,
        sessions::list_my_sessions,
        sessions::revoke_my_session,
        sessions::sign_out_other_sessions,
        sessions::list_my_sign_ins,
        sessions::list_user_sessions,
        sessions::revoke_user_session,
        sessions::list_user_sign_ins,
        impersonation::request_impersonation,
        impersonation::list_impersonations,
        impersonation::approve_impersonation,
        impersonation::decline_impersonation,
        impersonation::end_impersonation,
        impersonation::act_as,
        invitations::invite_user,
        invitations::accept_invitation,
        invitations::decline_invitation,
        invitations::invitation_status,
        invitations::invitation_resend,
        invitations::resend_invitation,
        invitations::revoke_invitation,
        invitations::send_welcome,
        email::request_email_change,
        email::confirm_email_change,
        email::cancel_email_change,
        email::email_change_status,
        email::email_change_resend,
        email::send_verification,
        email::verify_email,
        email::verification_status,
        email::resend_verification,
        email::org_request_email_change,
        email::org_confirm_email_change,
        email::org_cancel_email_change,
        email::org_email_change_status,
        email::org_email_change_resend,
        attributes::list_attribute_kinds,
        attributes::list_user_attributes,
        attributes::declare_user_attribute,
        attributes::update_user_attribute,
        attributes::set_user_attribute_status,
        attributes::delete_user_attribute,
        attributes::get_user_attribute_values,
        attributes::set_user_attribute_value,
        attributes::delete_user_attribute_values,
        privacy::grant_or_revoke_consent,
        privacy::consent_history,
        privacy::request_export,
        privacy::list_exports,
        privacy::download_export,
        privacy::request_erasure,
        privacy::cancel_erasure,
        privacy::cancel_erasure_by_link,
        privacy::hold_erasure,
        privacy::release_erasure,
    ),
    components(schemas(
        RegisterUserBody,
        RegisterUserResponse,
        UpdateUserBody,
        UpdateStatusBody,
        ResetPasswordBody,
        ResetPasswordResponse,
        UpdateCurrentUserBody,
        MemberStatusFilter,
        UserResponse,
        UserRoleInfo,
        SignUpBody,
        SignUpRulesResponse,
        InviteUserBody,
        InviteUserResponse,
        InvitationLinkResponse,
        AcceptInvitationBody,
        RequestEmailChangeBody,
        TokenStatusBody,
        VerifyEmailBody,
        ConfirmEmailChangeBody,
        TokenStatusResponse,
        TokenStatusDto,
        PasswordLinkStatusResponse,
        VerificationTokenStatusResponse,
        VerificationTokenStatusDto,
        TokenResentResponse,
        VerificationResentResponse,
        DeclareAttributeBody,
        UpdateAttributeBody,
        AttributeStatusBody,
        SetAttributeValueBody,
        AttributeResponse,
        AttributeKindResponse,
        AttributeDeletedResponse,
        UserAttributeValuesResponse,
        ConsentBody,
        ErasureBody,
        ErasureRequestResponse,
        ConsentRecordResponse,
        ExportBody,
        ExportScopeBody,
        ExportResponse,
        ExportRequestedResponse,
        ExportDownloadResponse,
        PasswordBreachResponse,
        ProfileResponse,
        UpdateDetailsBody,
        UpdateRecordsBody,
        ImportUsersBody,
        ImportUserBody,
        ImportStartedResponse,
        ImportResponse,
        ImportErrorResponse,
        FactorsClearedResponse,
        SessionResponse,
        SignedOutResponse,
        ImpersonationBody,
        ImpersonationRequestedResponse,
        ImpersonationResponse,
        ActingAsResponse,
    ))
)]
pub(crate) struct Document;
