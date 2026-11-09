//! Organization endpoints: the organization itself, its plan and bill, its
//! members and invitations, their privacy, its identity provider, branding,
//! API keys and cloud accounts, and how members sign in.
//!
//! Signing in, recovering a password and following an emailed link happen
//! before anyone is identified, and most of them send mail, so they sit
//! behind a per-address limiter in [`public_routes`]. So do the pricing
//! page and the payment provider's notices, under a wider window.

use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn;
use utoipa::OpenApi;

use crate::dto::federation::connections::{AssuranceTrustBody, EmailTrustBody};
use crate::dto::identity::links::TokenResentResponse;
use crate::dto::identity::privacy::ErasureRequestResponse;
use crate::dto::metrics::{
    ApiUsageMetricsResponse, AuthenticationMetricsResponse, CountMetricResponse,
    FailedAttemptsResponse, LatencyMetricResponse, MetricsWindowResponse, RateMetricResponse,
    SuccessRatePointResponse, TrendDirectionResponse, TrendResponse,
};
use crate::dto::organization::api_keys::{
    CreateOrgApiKeyBody, CreatedOrgApiKeyResponse, OrgApiKeyResponse, PermissionEntryResponse,
    PermissionGroupResponse,
};
use crate::dto::organization::billing::{
    ArrangePlanBody, CallToAction, CheckoutResponse, ChoosePlanBody, CycleBody,
    PlanCatalogResponse, PlanPriceResponse, PlanTierResponse, PlanUsageResponse, StandingResponse,
    SubscriptionResponse, UsageResponse,
};
use crate::dto::organization::branding::{OrgBrandingResponse, UpdateOrgBrandingBody};
use crate::dto::organization::cloud_accounts::{
    CloudAccountResponse, CloudNetworkResponse, ConnectionInstructionsResponse, CredentialBody,
};
use crate::dto::organization::identity_providers::{
    AddOrgProviderBody, ChangeOrgProviderBody, OrgIdentityProviderResponse, SwitchOrgProviderBody,
};
use crate::dto::organization::invitations::{
    AcceptOrgInvitationBody, InviteOrgUserBody, InvitedOrgUserResponse, OrgEmailBody, OrgTokenBody,
    OrgUserIdResponse, PasswordLinkStatusResponse, TokenStatusDto, VerificationResentResponse,
    VerificationTokenStatusDto, VerificationTokenStatusResponse,
};
use crate::dto::organization::lifecycle::{
    OrgAuthConfigBody, OrgMetricsResponse, OrganizationResponse, SignInPolicyBody,
    UpdateOrgAuthConfigBody, UpdateOrganizationBody,
};
use crate::dto::organization::members::{
    ChangeOrgUserEmailBody, ChangeOrgUserRoleBody, ChangePasswordBody, CreateOrgUserBody,
    CreateOrgUserResponse, GrantableRoleResponse, OrgMeResponse, OrgMemberStatusFilter,
    OrgUserAccessResponse, OrgUserResponse, ResetOrgUserPasswordBody, ResetOrgUserPasswordResponse,
    SetOrgUserTenantAccessBody, TenantAccessResponse, UnlinkIdentityBody, UpdateOrgUserProfileBody,
    UpdateOrgUserStatusBody,
};
use crate::dto::organization::mfa::{
    OrgFactorSetupBody, OrgMfaBeginResponse, OrgMfaConfirmBody, OrgMfaConfirmResponse,
    OrgMfaDisableBody, OrgMfaStatusResponse, OrgMfaVerifyBody, OrgRecoveryCodeBody,
    OrgRecoveryCodeResponse, OrgRecoveryCodesResponse, OrgRegenerateCodesBody,
};
use crate::dto::organization::passkeys::{
    OrgPasskeyChallengeResponse, OrgPasskeyEntry, OrgPasskeyListResponse, OrgPasskeyLoginBeginBody,
    OrgPasskeyLoginConfirmBody, OrgPasskeyRegisterBeginBody, OrgPasskeyRegisterConfirmBody,
    OrgRenamePasskeyBody, PasskeySetupFrom,
};
use crate::dto::organization::password_reset::{
    OrgResetConfirmBody, OrgResetLinkState, OrgResetLinkStatusResponse, OrgResetRequestBody,
    OrgResetResentResponse, OrgResetTokenBody,
};
use crate::dto::organization::privacy::{OrgConsentBody, OrgConsentResponse, OrgErasureBody};
use crate::dto::organization::proof::ReenteredProofBody;
use crate::dto::organization::sign_in::{
    ActiveSessionResponse, LinkedTenantSwitchBody, LinkedTenantSwitchResponse,
    MovedOrgSessionResponse, OfferedOrganizationResponse, OrgConfirmSignInBody,
    OrgConfirmedSignInResponse, OrgDeviceEntry, OrgDeviceListResponse, OrgLoginBody,
    OrgLoginResponse, OrgLogoutBody, OrgMagicLinkBody, OrgMagicLinkConfirmBody,
    OrgRevokeDeviceBody, OrgTrustDeviceBody, OrgTrustDeviceResponse, SwitchOrgTenantBody,
};
use crate::dto::organization::sso::{
    OrgSsoAnswerBody, OrgSsoCallbackBody, OrgSsoStartBody, OrgSsoStartResponse,
};
use crate::handlers::organization::{
    api_keys, billing, branding, cloud_accounts, identity_providers, invitations, lifecycle,
    members, mfa, passkeys, password_reset, privacy, sign_in, sso,
};
use crate::method::{delete, get, patch, post, put, shared};
use crate::middleware::answer_floor::link_request_floor;
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::middleware::sign_in_admission::sign_in_admission;
use crate::state::ApiState;

/// The organization's own path, which every organization endpoint hangs
/// off.
const ORG: &str = "/api/v1/organizations/{org_slug}";

/// The organization endpoints for a caller the auth middleware identified.
pub(crate) fn routes() -> Router<ApiState> {
    Router::new()
        .merge(organization_routes())
        .merge(member_routes())
        .merge(key_and_cloud_routes())
        .merge(signed_in_routes())
}

/// The organization endpoints reached before anyone is identified, limited
/// per client address.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let limiter = per_address(
        state,
        state.http.rate.login_per_minute,
        Duration::from_secs(60),
    );
    login_routes()
        .merge(password_reset_routes())
        .merge(invitation_reply_routes())
        .merge(verification_routes())
        .merge(emailed_link_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.http.sign_ins.clone(),
            sign_in_admission,
        ))
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
        .merge(browser_routes(state))
}

/// Password and passkey proofs that start or complete a sign-in.
fn login_routes() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/login", post(sign_in::password_login))
        .route("/api/v1/login/confirm", post(sign_in::confirm_sign_in))
        .route("/api/v1/passkey/login", post(passkeys::login_begin))
        .route(
            "/api/v1/passkey/login/discover",
            post(passkeys::login_discover),
        )
        .route(
            "/api/v1/passkey/login/confirm",
            post(passkeys::login_confirm),
        )
}

/// Password reset requests and the links used to complete them.
fn password_reset_routes() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/password/reset-request",
            post(password_reset::request).layer(from_fn(link_request_floor)),
        )
        .route(
            "/api/v1/password/reset-confirm",
            post(password_reset::confirm),
        )
        .route(
            "/api/v1/password/reset-status",
            post(password_reset::status),
        )
        .route(
            "/api/v1/password/reset-resend",
            post(password_reset::resend),
        )
}

/// Invitation decisions and email proof within an organization.
fn invitation_reply_routes() -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{ORG}/users/accept-invitation"),
            post(invitations::accept_org_invitation),
        )
        .route(
            &format!("{ORG}/users/decline-invitation"),
            post(invitations::decline_org_invitation),
        )
        .route(
            &format!("{ORG}/users/invitation-status"),
            post(invitations::org_invitation_status),
        )
        .route(
            &format!("{ORG}/users/send-verification"),
            post(invitations::send_org_verification),
        )
        .route(
            &format!("{ORG}/users/verify-email"),
            post(invitations::verify_org_email),
        )
}

/// Email proof and installer confirmation without an organization in the path.
fn verification_routes() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/users/send-verification",
            post(invitations::send_verification_by_email),
        )
        .route(
            "/api/v1/users/verify-email",
            post(invitations::verify_email_by_token),
        )
        .route(
            "/api/v1/users/verify-email/status",
            post(invitations::verification_token_status),
        )
        .route(
            "/api/v1/users/verify-email/resend",
            post(invitations::resend_verification_by_token),
        )
        .route(
            "/api/v1/users/confirm-installer",
            post(invitations::confirm_installer),
        )
}

/// Invitation renewal, erasure cancellation, and sign-in links delivered by email.
fn emailed_link_routes() -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{ORG}/users/invitation-resend"),
            post(invitations::renew_org_invitation),
        )
        .route(
            &format!("{ORG}/users/erasure/cancel-by-link"),
            post(privacy::cancel_erasure_by_link),
        )
        .route(
            "/api/v1/login/magic-link",
            post(sign_in::request_magic_link).layer(from_fn(link_request_floor)),
        )
        .route(
            "/api/v1/login/magic-link/verify",
            post(sign_in::confirm_magic_link),
        )
}

/// What a browser passing through single sign-on, a pricing page and the
/// payment provider reach without signing in: generous enough for a busy
/// office, or a provider's burst of notices, behind one address.
fn browser_routes(state: &ApiState) -> Router<ApiState> {
    let window = state.http.rate.sso;
    let limiter = per_address(state, window.max, window.window);
    Router::new()
        .route("/api/v1/login/sso", post(sso::start))
        .route("/api/v1/login/sso/callback", post(sso::callback))
        .route("/api/v1/plans", get(billing::list_plans))
        .route(
            "/api/v1/billing/payment-notices",
            post(billing::receive_payment_notice),
        )
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The organization itself: listing, reading, changing, its status,
/// metrics, sign-in rules, identity provider and branding.
fn organization_routes() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/organizations", get(lifecycle::list_organizations))
        .route(
            ORG,
            get(lifecycle::get_organization).patch(shared(lifecycle::update_organization)),
        )
        .route(
            &format!("{ORG}/suspend"),
            post(lifecycle::suspend_organization),
        )
        .route(
            &format!("{ORG}/reactivate"),
            post(lifecycle::reactivate_organization),
        )
        .route(&format!("{ORG}/close"), post(lifecycle::close_organization))
        .route(&format!("{ORG}/metrics"), get(lifecycle::get_org_metrics))
        .route(
            &format!("{ORG}/auth-config"),
            get(lifecycle::get_auth_config).put(shared(lifecycle::update_auth_config)),
        )
        .merge(provider_and_branding_routes())
        .merge(billing_routes())
}

/// The organization's identity provider and visual branding.
fn provider_and_branding_routes() -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{ORG}/identity-provider"),
            get(identity_providers::get_identity_provider)
                .post(shared(identity_providers::add_identity_provider))
                .patch(shared(identity_providers::change_identity_provider))
                .delete(shared(identity_providers::remove_identity_provider)),
        )
        .route(
            &format!("{ORG}/identity-provider/status"),
            put(identity_providers::switch_identity_provider),
        )
        .route(
            &format!("{ORG}/branding"),
            get(branding::get_branding)
                .patch(shared(branding::update_branding))
                .delete(shared(branding::reset_branding)),
        )
}

/// What the organization pays for: its subscription, usage and checkout,
/// and the plan an operator arranges.
fn billing_routes() -> Router<ApiState> {
    Router::new()
        .route(&format!("{ORG}/plan"), post(billing::arrange_plan))
        .route(
            &format!("{ORG}/subscription"),
            get(billing::get_subscription).put(shared(billing::choose_plan)),
        )
        .route(
            &format!("{ORG}/subscription/checkout"),
            post(billing::start_checkout),
        )
        .route(&format!("{ORG}/usage"), get(billing::get_usage))
}

/// The organization's members, their invitations and their linked
/// identities.
fn member_routes() -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{ORG}/users"),
            get(members::list_org_users).post(shared(invitations::invite_org_user)),
        )
        .route(
            &format!("{ORG}/users/create"),
            post(members::create_org_user),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}"),
            delete(members::delete_org_user),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/status"),
            patch(members::update_org_user_status),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/role"),
            patch(members::change_org_user_role),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/email"),
            patch(members::change_org_user_email),
        )
        .merge(member_access_routes())
        .merge(member_invitation_routes())
        .merge(own_identity_routes())
        .merge(privacy_routes())
}

/// Administrative recovery of member factors and their tenant access.
fn member_access_routes() -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{ORG}/users/{{user_id}}/reset-password"),
            post(members::reset_org_user_password),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/mfa/reset"),
            post(members::reset_org_member_mfa),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/access"),
            get(members::get_org_user_access),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/tenants/{{tenant_slug}}"),
            put(members::set_org_user_tenant_access),
        )
        .route(
            &format!("{ORG}/tenants/{{tenant_slug}}/grantable-roles"),
            get(members::list_grantable_roles),
        )
}

/// Invitation delivery and transferring the organization's ownership.
fn member_invitation_routes() -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{ORG}/users/{{user_id}}/resend-invitation"),
            post(invitations::resend_org_invitation),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/revoke-invitation"),
            post(invitations::revoke_org_invitation),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/welcome"),
            post(invitations::send_org_welcome),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/transfer-ownership"),
            post(members::transfer_ownership),
        )
}

/// The caller's profile, password, and linked tenant identities.
fn own_identity_routes() -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{ORG}/me"),
            get(members::get_current_org_user).patch(shared(members::update_current_org_user)),
        )
        .route(
            &format!("{ORG}/me/access"),
            get(members::get_current_org_user_access),
        )
        .route(
            &format!("{ORG}/password/change"),
            post(members::change_org_user_password),
        )
        .route(
            &format!("{ORG}/identities"),
            delete(members::unlink_identity),
        )
        .route(
            &format!("{ORG}/tenants/{{tenant_slug}}/identities"),
            post(members::link_identity).delete(shared(members::unlink_own_identity)),
        )
}

/// Members' consent decisions and erasure requests.
fn privacy_routes() -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{ORG}/users/{{user_id}}/consent"),
            post(privacy::grant_or_revoke_consent),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/consents"),
            get(privacy::list_consents),
        )
        .route(
            &format!("{ORG}/users/{{user_id}}/erasure"),
            post(privacy::request_erasure),
        )
        .route(
            &format!("{ORG}/users/erasure/{{id}}/cancel"),
            post(privacy::cancel_erasure),
        )
        .route(
            &format!("{ORG}/users/erasure/{{id}}/hold"),
            post(privacy::hold_erasure),
        )
        .route(
            &format!("{ORG}/users/erasure/{{id}}/release"),
            post(privacy::release_erasure),
        )
}

/// The organization's API keys, the permissions they may name, and its
/// cloud accounts.
fn key_and_cloud_routes() -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{ORG}/permissions"),
            get(api_keys::list_org_permissions),
        )
        .route(
            &format!("{ORG}/api-keys"),
            get(api_keys::list_org_api_keys).post(shared(api_keys::create_org_api_key)),
        )
        .route(
            &format!("{ORG}/api-keys/{{key_id}}/revoke"),
            post(api_keys::revoke_org_api_key),
        )
        .merge(cloud_routes())
}

/// Cloud account connection proofs and available networks.
fn cloud_routes() -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{ORG}/cloud-accounts"),
            get(cloud_accounts::list_cloud_accounts),
        )
        .route(
            &format!("{ORG}/cloud-accounts/{{provider}}"),
            post(cloud_accounts::begin_cloud_connection)
                .delete(shared(cloud_accounts::disconnect_cloud_account)),
        )
        .route(
            &format!("{ORG}/cloud-accounts/{{provider}}/credential"),
            put(cloud_accounts::submit_cloud_credential),
        )
        .route(
            &format!("{ORG}/cloud-accounts/{{provider}}/verify"),
            post(cloud_accounts::verify_cloud_account),
        )
        .route(
            &format!("{ORG}/cloud-accounts/{{provider}}/networks"),
            get(cloud_accounts::list_cloud_networks),
        )
}

/// A member's own sessions, devices, tenants, second factor and passkeys.
fn signed_in_routes() -> Router<ApiState> {
    Router::new()
        .route(&format!("{ORG}/logout"), post(sign_in::logout))
        .route(
            &format!("{ORG}/sessions/active"),
            get(sign_in::list_active_sessions),
        )
        .route(
            &format!("{ORG}/sessions/{{session_id}}/revoke"),
            post(sign_in::revoke_session),
        )
        .route(
            &format!("{ORG}/devices"),
            get(sign_in::list_devices).post(shared(sign_in::trust_device)),
        )
        .route(
            &format!("{ORG}/devices/revoke"),
            post(sign_in::revoke_device),
        )
        .route(
            &format!("{ORG}/switch-tenant"),
            post(sign_in::switch_tenant),
        )
        .route(
            &format!("{ORG}/tenants/{{tenant_slug}}/auth/tenant/switch"),
            post(sign_in::linked_switch),
        )
        .merge(factor_routes())
}

/// A member's second factors, recovery codes, and registered passkeys.
fn factor_routes() -> Router<ApiState> {
    Router::new()
        .route(&format!("{ORG}/mfa/status"), get(mfa::status))
        .route(&format!("{ORG}/mfa"), delete(mfa::disable))
        .route(&format!("{ORG}/mfa/begin"), post(mfa::begin))
        .route(&format!("{ORG}/mfa/abandon"), post(mfa::abandon))
        .route(&format!("{ORG}/mfa/confirm"), post(mfa::confirm))
        .route(&format!("{ORG}/mfa/verify"), post(mfa::verify))
        .route(&format!("{ORG}/mfa/recovery"), post(mfa::recovery_sign_in))
        .route(
            &format!("{ORG}/mfa/recovery-codes"),
            post(mfa::regenerate_recovery_codes),
        )
        .route(
            &format!("{ORG}/passkeys/register"),
            post(passkeys::register_begin),
        )
        .route(
            &format!("{ORG}/passkeys/register/confirm"),
            post(passkeys::register_confirm),
        )
        .route(&format!("{ORG}/passkeys"), get(passkeys::list))
        .route(
            &format!("{ORG}/passkeys/{{passkey_id}}"),
            patch(passkeys::rename).delete(shared(passkeys::delete)),
        )
}

/// The organization part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        lifecycle::list_organizations,
        lifecycle::get_organization,
        lifecycle::update_organization,
        lifecycle::suspend_organization,
        lifecycle::reactivate_organization,
        lifecycle::close_organization,
        lifecycle::get_org_metrics,
        lifecycle::get_auth_config,
        lifecycle::update_auth_config,
        billing::list_plans,
        billing::get_subscription,
        billing::choose_plan,
        billing::get_usage,
        billing::start_checkout,
        billing::receive_payment_notice,
        billing::arrange_plan,
        identity_providers::get_identity_provider,
        identity_providers::add_identity_provider,
        identity_providers::change_identity_provider,
        identity_providers::switch_identity_provider,
        identity_providers::remove_identity_provider,
        branding::get_branding,
        branding::update_branding,
        branding::reset_branding,
        privacy::grant_or_revoke_consent,
        privacy::list_consents,
        privacy::request_erasure,
        privacy::cancel_erasure,
        privacy::hold_erasure,
        privacy::release_erasure,
        privacy::cancel_erasure_by_link,
        members::get_current_org_user,
        members::transfer_ownership,
        members::list_org_users,
        members::create_org_user,
        members::delete_org_user,
        members::update_org_user_status,
        members::change_org_user_role,
        members::change_org_user_email,
        members::update_current_org_user,
        members::change_org_user_password,
        members::reset_org_user_password,
        members::reset_org_member_mfa,
        members::get_org_user_access,
        members::list_grantable_roles,
        members::get_current_org_user_access,
        members::set_org_user_tenant_access,
        members::link_identity,
        members::unlink_own_identity,
        members::unlink_identity,
        invitations::invite_org_user,
        invitations::resend_org_invitation,
        invitations::renew_org_invitation,
        invitations::revoke_org_invitation,
        invitations::send_org_welcome,
        invitations::accept_org_invitation,
        invitations::decline_org_invitation,
        invitations::org_invitation_status,
        invitations::send_org_verification,
        invitations::verify_org_email,
        invitations::send_verification_by_email,
        invitations::verify_email_by_token,
        invitations::verification_token_status,
        invitations::resend_verification_by_token,
        invitations::confirm_installer,
        api_keys::list_org_api_keys,
        api_keys::create_org_api_key,
        api_keys::revoke_org_api_key,
        api_keys::list_org_permissions,
        cloud_accounts::list_cloud_accounts,
        cloud_accounts::begin_cloud_connection,
        cloud_accounts::submit_cloud_credential,
        cloud_accounts::verify_cloud_account,
        cloud_accounts::list_cloud_networks,
        cloud_accounts::disconnect_cloud_account,
        sign_in::password_login,
        sign_in::request_magic_link,
        sign_in::confirm_magic_link,
        sso::start,
        sso::callback,
        sign_in::confirm_sign_in,
        sign_in::logout,
        sign_in::list_active_sessions,
        sign_in::revoke_session,
        sign_in::list_devices,
        sign_in::trust_device,
        sign_in::revoke_device,
        sign_in::switch_tenant,
        sign_in::linked_switch,
        mfa::status,
        mfa::begin,
        mfa::abandon,
        mfa::confirm,
        mfa::verify,
        mfa::recovery_sign_in,
        mfa::regenerate_recovery_codes,
        mfa::disable,
        passkeys::register_begin,
        passkeys::register_confirm,
        passkeys::list,
        passkeys::rename,
        passkeys::delete,
        passkeys::login_begin,
        passkeys::login_discover,
        passkeys::login_confirm,
        password_reset::request,
        password_reset::confirm,
        password_reset::status,
        password_reset::resend,
    ),
    components(schemas(
        OrganizationResponse,
        UpdateOrganizationBody,
        OrgMetricsResponse,
        PlanCatalogResponse,
        PlanTierResponse,
        PlanPriceResponse,
        CallToAction,
        CycleBody,
        SubscriptionResponse,
        StandingResponse,
        ChoosePlanBody,
        PlanUsageResponse,
        UsageResponse,
        CheckoutResponse,
        ArrangePlanBody,
        OrgIdentityProviderResponse,
        EmailTrustBody,
        AssuranceTrustBody,
        AddOrgProviderBody,
        ChangeOrgProviderBody,
        SwitchOrgProviderBody,
        OrgBrandingResponse,
        UpdateOrgBrandingBody,
        OrgConsentBody,
        OrgConsentResponse,
        OrgErasureBody,
        ErasureRequestResponse,
        TokenResentResponse,
        OrgMeResponse,
        OfferedOrganizationResponse,
        OrgMagicLinkBody,
        OrgMagicLinkConfirmBody,
        OrgSsoStartBody,
        OrgSsoStartResponse,
        OrgSsoCallbackBody,
        OrgSsoAnswerBody,
        OrgRecoveryCodeBody,
        OrgRecoveryCodeResponse,
        OrgRegenerateCodesBody,
        OrgRecoveryCodesResponse,
        OrgAuthConfigBody,
        UpdateOrgAuthConfigBody,
        SignInPolicyBody,
        ReenteredProofBody,
        MetricsWindowResponse,
        AuthenticationMetricsResponse,
        CountMetricResponse,
        RateMetricResponse,
        LatencyMetricResponse,
        FailedAttemptsResponse,
        SuccessRatePointResponse,
        TrendResponse,
        TrendDirectionResponse,
        ApiUsageMetricsResponse,
        OrgUserResponse,
        OrgMemberStatusFilter,
        CreateOrgUserBody,
        CreateOrgUserResponse,
        UpdateOrgUserStatusBody,
        ChangeOrgUserRoleBody,
        ChangeOrgUserEmailBody,
        UpdateOrgUserProfileBody,
        ChangePasswordBody,
        ResetOrgUserPasswordBody,
        ResetOrgUserPasswordResponse,
        SetOrgUserTenantAccessBody,
        OrgUserAccessResponse,
        GrantableRoleResponse,
        TenantAccessResponse,
        UnlinkIdentityBody,
        InviteOrgUserBody,
        InvitedOrgUserResponse,
        OrgUserIdResponse,
        AcceptOrgInvitationBody,
        OrgEmailBody,
        OrgTokenBody,
        PasswordLinkStatusResponse,
        TokenStatusDto,
        VerificationTokenStatusResponse,
        VerificationTokenStatusDto,
        VerificationResentResponse,
        OrgApiKeyResponse,
        CreateOrgApiKeyBody,
        CreatedOrgApiKeyResponse,
        PermissionGroupResponse,
        PermissionEntryResponse,
        ConnectionInstructionsResponse,
        CredentialBody,
        CloudAccountResponse,
        CloudNetworkResponse,
        OrgLoginBody,
        OrgLoginResponse,
        OrgConfirmSignInBody,
        OrgConfirmedSignInResponse,
        OrgLogoutBody,
        ActiveSessionResponse,
        OrgDeviceListResponse,
        OrgDeviceEntry,
        OrgTrustDeviceBody,
        OrgTrustDeviceResponse,
        OrgRevokeDeviceBody,
        SwitchOrgTenantBody,
        MovedOrgSessionResponse,
        LinkedTenantSwitchBody,
        LinkedTenantSwitchResponse,
        OrgMfaStatusResponse,
        OrgFactorSetupBody,
        OrgMfaBeginResponse,
        OrgMfaConfirmBody,
        OrgMfaConfirmResponse,
        OrgMfaVerifyBody,
        OrgMfaDisableBody,
        OrgPasskeyChallengeResponse,
        OrgPasskeyRegisterBeginBody,
        PasskeySetupFrom,
        OrgPasskeyRegisterConfirmBody,
        OrgPasskeyListResponse,
        OrgPasskeyEntry,
        OrgRenamePasskeyBody,
        OrgPasskeyLoginBeginBody,
        OrgPasskeyLoginConfirmBody,
        OrgResetRequestBody,
        OrgResetConfirmBody,
        OrgResetTokenBody,
        OrgResetLinkStatusResponse,
        OrgResetLinkState,
        OrgResetResentResponse,
    ))
)]
pub(crate) struct Document;
