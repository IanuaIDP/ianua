//! Authentication endpoints: signing in and out, second factors, passkeys,
//! sessions and trusted devices, break-glass grants, single sign-on, and the
//! gateway's internal app sign-in relay.
//!
//! Most of these run before anyone is identified, where the API's per-caller
//! rate limit does not reach, so they carry per-address limits of their own:
//! sign-ins, the public link and passkey steps, and the browser's single
//! sign-on pages. The security-sensitive changes a signed-in person makes
//! carry a per-person limit.

use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn;
use ianua_app::ports::authentication::RELAY_PATH;
use utoipa::OpenApi;

use crate::dto::authentication::federation::{SamlAcsForm, SsoExchangeBody, SsoExchangeResponse};
use crate::dto::authentication::mfa::{
    CodeFactorBody, CodeSentResponse, FactorOptionsResponse, HeldFactorResponse, MfaCodeBody,
    MfaConfirmBody, MfaConfirmResponse, MfaEnrollResponse, MfaSetupBody, MfaStatusResponse,
    RegenerateRecoveryCodesBody, SentFactorKind, SessionCodeBody, WaitingSignInParams,
};
use crate::dto::authentication::passkeys::{
    PasskeyChallengeResponse, PasskeyEntry, PasskeyListResponse, PasskeyLoginBeginBody,
    PasskeyLoginResponse, PasskeyRegisterConfirmBody, RenamePasskeyBody,
};
use crate::dto::authentication::password::{
    ConfirmSignInBody, ConfirmedSignInResponse, ConsumeMagicLinkBody, DuePasswordChangeBody,
    MagicLinkLoginResponse, PasswordBreachResponse, PasswordChangeBody,
    PasswordChangeRequiredResponse, PasswordLinkStatusResponse, PasswordResetConfirmBody,
    PasswordResetRequestBody, PasswordSetResponse, RequestMagicLinkBody, SignInPuzzleResponse,
    TenantLoginAnswer, TenantLoginBody, TenantLoginResponse, TokenResentResponse, TokenStatusBody,
};
use crate::dto::authentication::sessions::{
    BreakGlassBody, BreakGlassGrantResponse, BreakGlassRevokeBody, DeviceEntry, DeviceListResponse,
    RevokeDeviceBody, SignInConnectionResponse, SignInOptionsResponse, TokenRefreshBody,
    TokenRefreshResponse, TrustDeviceBody, TrustDeviceResponse,
};
use crate::dto::authentication::sign_in::{OwedFactors, PasskeyAnswerBody, ReenteredProofBody};
use crate::handlers::authentication::{app_sign_in, federation, mfa, passkeys, password, sessions};
use crate::method::{delete, get, patch, post, shared};
use crate::middleware::answer_floor::{link_request_floor, marked_link_request_floor};
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::middleware::sign_in_admission::sign_in_admission;
use crate::middleware::user_rate_limit::{
    UserRateLimitConfig, UserRateLimitState, user_rate_limit,
};
use crate::state::ApiState;

/// Where a tenant's endpoints live.
const TENANT: &str = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";

/// The authentication endpoints a session signs: refreshing and ending it,
/// answering its second factor, adding passkeys, and reading the caller's
/// own factors and devices. The API's per-caller limit covers them.
pub(crate) fn routes() -> Router<ApiState> {
    let auth = format!("{TENANT}/auth");
    Router::new()
        .route(&format!("{auth}/logout"), post(sessions::logout))
        .route(
            &format!("{auth}/token/refresh"),
            post(sessions::refresh_token),
        )
        .route(&format!("{auth}/device/trust"), get(sessions::list_devices))
        .route(&format!("{auth}/mfa/verify"), post(mfa::verify))
        .route(&format!("{auth}/mfa/status"), get(mfa::status))
        .route(&format!("{auth}/mfa/options"), get(mfa::options))
        .route(
            &format!("{auth}/recovery-code"),
            post(mfa::redeem_recovery_code),
        )
        .merge(passkey_registration_routes(&auth))
}

/// Passkey enrollment during a session or a waiting sign-in, and the caller's keys.
fn passkey_registration_routes(auth: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{auth}/passkey/register"),
            post(passkeys::begin_registration),
        )
        .route(
            &format!("{auth}/passkey/register/confirm"),
            post(passkeys::confirm_registration),
        )
        .route(
            &format!("{auth}/sign-in/passkey/register"),
            post(passkeys::begin_sign_in_registration),
        )
        .route(
            &format!("{auth}/sign-in/passkey/register/confirm"),
            post(passkeys::confirm_sign_in_registration),
        )
        .route(&format!("{auth}/passkeys"), get(passkeys::list))
}

/// The authentication endpoints that carry limits of their own, built with
/// the deployment's windows and trusted proxies from `state`.
pub(crate) fn limited_routes(state: &ApiState) -> Router<ApiState> {
    Router::new()
        .merge(sign_in_routes(state))
        .merge(public_routes(state))
        .merge(sensitive_routes(state))
        .merge(sign_in_page_routes(state))
        .merge(single_sign_on_routes(state))
}

/// The internal listener's one endpoint: the sign-ins the gateway relays,
/// admitted like every other sign-in.
pub(crate) fn internal_routes(state: &ApiState) -> Router<ApiState> {
    Router::new().route(
        RELAY_PATH,
        post(app_sign_in::relay)
            .layer(from_fn(marked_link_request_floor))
            .layer(axum::middleware::from_fn_with_state(
                state.http.sign_ins.clone(),
                sign_in_admission,
            )),
    )
}

/// Signing in with a password or a magic link: so many a minute from one
/// address.
fn sign_in_routes(state: &ApiState) -> Router<ApiState> {
    let limiter = per_address(
        state,
        state.http.rate.login_per_minute,
        Duration::from_secs(60),
    );
    let auth = format!("{TENANT}/auth");
    Router::new()
        .route(&format!("{TENANT}/login"), post(password::tenant_login))
        .route(
            &format!("{TENANT}/login/password-change"),
            post(password::change_due_password),
        )
        .route("/api/v1/sign-in/puzzle", post(password::sign_in_puzzle))
        .route(
            &format!("{auth}/magic-link"),
            post(password::request_magic_link).layer(from_fn(link_request_floor)),
        )
        .route(
            &format!("{auth}/magic-link/verify"),
            post(password::consume_magic_link),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.http.sign_ins.clone(),
            sign_in_admission,
        ))
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The public steps that check a link, a code or a passkey: the sensitive
/// window, per address.
fn public_routes(state: &ApiState) -> Router<ApiState> {
    let window = state.http.rate.sensitive;
    let limiter = per_address(state, window.max, window.window);
    let auth = format!("{TENANT}/auth");
    password_reset_routes(&auth)
        .merge(public_proof_routes(&auth))
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// Mailbox sign-in confirmation and password reset delivery, proof, and link status.
fn password_reset_routes(auth: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{auth}/sign-in/confirm"),
            post(password::confirm_sign_in),
        )
        .route(
            &format!("{auth}/password/reset-request"),
            post(password::request_password_reset).layer(from_fn(link_request_floor)),
        )
        .route(
            &format!("{auth}/password/reset-confirm"),
            post(password::confirm_password_reset),
        )
        .route(
            &format!("{auth}/password/reset-code"),
            post(password::send_password_reset_code).layer(from_fn(link_request_floor)),
        )
        .route(
            &format!("{auth}/password/reset-status"),
            post(password::password_reset_status),
        )
        .route(
            &format!("{auth}/password/reset-resend"),
            post(password::resend_password_reset),
        )
}

/// Passkey and federated proofs, followed by session resumption.
fn public_proof_routes(auth: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{auth}/passkey/login"),
            post(passkeys::begin_login),
        )
        .route(
            &format!("{auth}/passkey/login/discover"),
            post(passkeys::begin_discoverable_login),
        )
        .route(
            &format!("{auth}/passkey/login/confirm"),
            post(passkeys::confirm_login),
        )
        .route(
            &format!("{auth}/sso/exchange"),
            post(federation::exchange_sign_in_code),
        )
        .route(&format!("{auth}/session/resume"), post(mfa::resume_session))
}

/// The changes a signed-in person makes to how they sign in, to their
/// devices and to emergency access: the per-person window.
fn sensitive_routes(state: &ApiState) -> Router<ApiState> {
    let window = state.http.rate.user;
    let limiter = UserRateLimitState::new(UserRateLimitConfig {
        max_requests: window.max,
        window: window.window,
    });
    let auth = format!("{TENANT}/auth");
    factor_change_routes(&auth)
        .merge(session_access_routes(&auth))
        .layer(axum::middleware::from_fn_with_state(
            limiter,
            user_rate_limit,
        ))
}

/// Password changes and enrollment or removal of second factors.
fn factor_change_routes(auth: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{auth}/password/change"),
            post(password::change_password),
        )
        .route(&format!("{auth}/mfa/enroll"), post(mfa::enroll))
        .route(
            &format!("{auth}/mfa/enroll/code"),
            post(mfa::enroll_code_factor),
        )
        .route(&format!("{auth}/mfa/send-code"), post(mfa::send_code))
        .route(
            &format!("{auth}/recovery-codes/regenerate"),
            post(mfa::regenerate_recovery_codes),
        )
        .route(
            &format!("{auth}/mfa/enroll/confirm"),
            post(mfa::confirm_enrollment),
        )
        .route(
            &format!("{auth}/mfa/enroll/abandon"),
            post(mfa::abandon_enrollment),
        )
        .route(&format!("{auth}/mfa"), delete(mfa::disable))
}

/// Emergency grants, trusted devices, and passkey changes for a signed-in caller.
fn session_access_routes(auth: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{auth}/break-glass"),
            post(sessions::grant_break_glass),
        )
        .route(
            &format!("{auth}/break-glass/revoke"),
            post(sessions::revoke_break_glass),
        )
        .route(
            &format!("{auth}/device/trust/add"),
            post(sessions::trust_device),
        )
        .route(
            &format!("{auth}/device/trust/revoke"),
            post(sessions::revoke_device),
        )
        .route(
            &format!("{auth}/passkeys/{{passkey_id}}"),
            patch(passkeys::rename).delete(shared(passkeys::delete)),
        )
}

/// What a sign-in page offers: the sign-in page window, per address.
fn sign_in_page_routes(state: &ApiState) -> Router<ApiState> {
    let window = state.http.rate.sso;
    let limiter = per_address(state, window.max, window.window);
    Router::new()
        .route(
            &format!("{TENANT}/auth/sign-in-options"),
            get(sessions::sign_in_options),
        )
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The pages a browser passes through during single sign-on: generous
/// enough for a busy office behind one address.
fn single_sign_on_routes(state: &ApiState) -> Router<ApiState> {
    let window = state.http.rate.sso;
    let limiter = per_address(state, window.max, window.window);
    let federation_path = format!("{TENANT}/federation");
    Router::new()
        .route(
            &format!("{federation_path}/connections/{{id}}/login"),
            get(federation::begin_single_sign_on),
        )
        .route(
            &format!("{federation_path}/oidc/callback"),
            get(federation::oidc_callback),
        )
        .route(
            &format!("{federation_path}/saml/acs"),
            post(federation::saml_acs),
        )
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The authentication part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        password::tenant_login,
        password::change_due_password,
        password::sign_in_puzzle,
        password::confirm_sign_in,
        password::request_magic_link,
        password::consume_magic_link,
        password::change_password,
        password::request_password_reset,
        password::confirm_password_reset,
        password::send_password_reset_code,
        password::password_reset_status,
        password::resend_password_reset,
        mfa::enroll,
        mfa::enroll_code_factor,
        mfa::options,
        mfa::send_code,
        mfa::regenerate_recovery_codes,
        mfa::confirm_enrollment,
        mfa::abandon_enrollment,
        mfa::disable,
        mfa::status,
        mfa::verify,
        mfa::redeem_recovery_code,
        mfa::resume_session,
        passkeys::begin_registration,
        passkeys::confirm_registration,
        passkeys::begin_sign_in_registration,
        passkeys::confirm_sign_in_registration,
        passkeys::begin_login,
        passkeys::begin_discoverable_login,
        passkeys::confirm_login,
        passkeys::list,
        passkeys::rename,
        passkeys::delete,
        sessions::logout,
        sessions::refresh_token,
        sessions::sign_in_options,
        sessions::list_devices,
        sessions::trust_device,
        sessions::revoke_device,
        sessions::grant_break_glass,
        sessions::revoke_break_glass,
        federation::begin_single_sign_on,
        federation::oidc_callback,
        federation::saml_acs,
        federation::exchange_sign_in_code,
    ),
    components(schemas(
        TenantLoginBody,
        TenantLoginResponse,
        TenantLoginAnswer,
        PasswordChangeRequiredResponse,
        DuePasswordChangeBody,
        OwedFactors,
        ConfirmSignInBody,
        ConfirmedSignInResponse,
        RequestMagicLinkBody,
        ConsumeMagicLinkBody,
        MagicLinkLoginResponse,
        PasswordChangeBody,
        PasswordResetRequestBody,
        PasswordResetConfirmBody,
        TokenStatusBody,
        PasswordLinkStatusResponse,
        TokenResentResponse,
        SignInPuzzleResponse,
        ReenteredProofBody,
        PasskeyAnswerBody,
        MfaSetupBody,
        MfaEnrollResponse,
        MfaConfirmBody,
        MfaConfirmResponse,
        MfaCodeBody,
        MfaStatusResponse,
        SessionCodeBody,
        CodeFactorBody,
        SentFactorKind,
        CodeSentResponse,
        FactorOptionsResponse,
        HeldFactorResponse,
        WaitingSignInParams,
        RegenerateRecoveryCodesBody,
        PasswordSetResponse,
        PasswordBreachResponse,
        PasskeyChallengeResponse,
        PasskeyRegisterConfirmBody,
        PasskeyLoginBeginBody,
        PasskeyLoginResponse,
        PasskeyListResponse,
        PasskeyEntry,
        RenamePasskeyBody,
        TokenRefreshBody,
        TokenRefreshResponse,
        SignInOptionsResponse,
        SignInConnectionResponse,
        DeviceListResponse,
        DeviceEntry,
        TrustDeviceBody,
        TrustDeviceResponse,
        RevokeDeviceBody,
        BreakGlassBody,
        BreakGlassGrantResponse,
        BreakGlassRevokeBody,
        SamlAcsForm,
        SsoExchangeBody,
        SsoExchangeResponse,
    ))
)]
pub(crate) struct Document;

/// The internal listener's part of the OpenAPI document, kept out of the
/// public one: no ingress routes to it, and only the gateway calls it.
#[derive(OpenApi)]
#[openapi(paths(app_sign_in::relay))]
pub(crate) struct InternalDocument;
