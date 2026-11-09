//! The authentication use cases the API serves: password and mailbox
//! sign-in, second factors, passkeys, sessions and trusted devices,
//! break-glass grants, single sign-on, and the gateway's app sign-in.

use std::sync::Arc;

use ianua_app::ports::pages::PageRenderer;
use ianua_app::services::authentication::flood_gate::FloodGatePorts;
use ianua_app::services::authentication::new_password::NewPasswordPorts;
use ianua_app::services::authentication::password_hashing::PasswordHashing;
use ianua_app::services::authentication::reset_mail::{ResetMailPorts, ResetRequestPolicy};
use ianua_app::services::authentication::sign_in_counts::SignInCounts;
use ianua_app::use_cases::authentication::app_sign_in::{
    AcrossHosts, AcrossHostsPorts, AppPasskeyBeginFlows, AppPasskeyFlows, AppPasswordResetFlows,
    AppSignInActions, AppSignInFlows, AppSsoFinishFlows, AppSsoFlows, HandOverAppSessionUseCase,
    ReceivePorts, ReceiveUseCase, SignInPorts, TargetPorts,
};
use ianua_app::use_cases::authentication::federation::completion::{
    SsoAccountPorts, SsoCompletionPorts, SsoFactorPorts, SsoSessionPorts,
};
use ianua_app::use_cases::authentication::federation::single_sign_on::SsoPolicy;
use ianua_app::use_cases::authentication::federation::{
    BeginSingleSignOnPorts, BeginSingleSignOnUseCase, ExchangeSignInCodePorts,
    ExchangeSignInCodeUseCase, OidcLoginPorts, OidcLoginUseCase, SamlLoginPorts, SamlLoginUseCase,
};
use ianua_app::use_cases::authentication::passkeys::registrant::RegistrantPorts;
use ianua_app::use_cases::authentication::sessions::{break_glass, device_trust};
use ianua_app::use_cases::authentication::{mfa, passkeys, password, sessions};
use ianua_domain::types::HttpsUrl;

use crate::deps::{Adapters, Settings};
use crate::identity::IdentityState;

/// The authentication use cases, by area.
#[derive(Clone)]
pub struct AuthenticationState {
    /// The deployment's public address, which single sign-on's callbacks
    /// and the dashboard it returns to are built on.
    pub app_base_url: HttpsUrl,
    /// Password and mailbox sign-in, and changing or resetting a password.
    pub password: PasswordUseCases,
    /// Second factors and recovery codes.
    pub mfa: MfaUseCases,
    /// WebAuthn registration, sign-in and credential administration.
    pub passkeys: PasskeyUseCases,
    /// Sessions, trusted devices and break-glass grants.
    pub sessions: SessionUseCases,
    /// Single sign-on through a tenant's identity providers.
    pub federation: FederationUseCases,
    /// Sign-in requests the gateway relays from an app's host.
    pub app_sign_in: Arc<ReceiveUseCase>,
    /// Draws the sign-in pages handed to the gateway.
    pub pages: Arc<dyn PageRenderer>,
}

/// Password and mailbox sign-in, and changing or resetting a password.
#[derive(Clone)]
pub struct PasswordUseCases {
    pub tenant_login: Arc<password::TenantLoginUseCase>,
    pub change_due_password: Arc<password::TenantChangeDueUseCase>,
    pub confirm_sign_in: Arc<password::ConfirmSignInByEmailUseCase>,
    pub request_magic_link: Arc<password::RequestMagicLinkUseCase>,
    pub consume_magic_link: Arc<password::ConsumeMagicLinkUseCase>,
    pub change: Arc<password::ChangeUseCase>,
    pub reset_request: Arc<password::ResetRequestUseCase>,
    pub reset_resend: Arc<password::ResendResetUseCase>,
    pub reset_status: Arc<password::ResetStatusUseCase>,
    pub reset_confirm: Arc<password::ResetConfirmUseCase>,
    pub reset_code: Arc<password::ResetCodeUseCase>,
    pub sign_in_puzzle: Arc<password::IssueSignInPuzzleUseCase>,
}

/// Second factors and recovery codes.
#[derive(Clone)]
pub struct MfaUseCases {
    pub begin: Arc<mfa::BeginUseCase>,
    pub begin_code_factor: Arc<mfa::CodeFactorBeginUseCase>,
    pub confirm: Arc<mfa::ConfirmUseCase>,
    pub abandon: Arc<mfa::AbandonUseCase>,
    pub disable: Arc<mfa::DisableUseCase>,
    pub status: Arc<mfa::GetStatusUseCase>,
    pub options: Arc<mfa::FactorOptionsUseCase>,
    pub send_code: Arc<mfa::SendFactorCodeUseCase>,
    pub verify: Arc<mfa::VerificationUseCase>,
    pub recovery_code: Arc<mfa::RecoveryCodeLoginUseCase>,
    pub regenerate_recovery_codes: Arc<mfa::RegenerateRecoveryCodesUseCase>,
    pub resume_session: Arc<mfa::ResumeSessionUseCase>,
}

/// Passkeys: adding, signing in with and managing them.
#[derive(Clone)]
pub struct PasskeyUseCases {
    pub register_begin: Arc<passkeys::RegistrationBeginUseCase>,
    pub register_confirm: Arc<passkeys::RegistrationConfirmUseCase>,
    pub login_begin: Arc<passkeys::LoginBeginUseCase>,
    pub discover_begin: Arc<passkeys::DiscoverableBeginUseCase>,
    pub login_confirm: Arc<passkeys::LoginConfirmUseCase>,
    pub list: Arc<passkeys::ListUseCase>,
    pub rename: Arc<passkeys::RenameUseCase>,
    pub delete: Arc<passkeys::DeleteUseCase>,
}

/// Sessions, trusted devices and break-glass grants.
#[derive(Clone)]
pub struct SessionUseCases {
    pub logout: Arc<sessions::LogoutUseCase>,
    pub refresh: Arc<sessions::TokenRefreshUseCase>,
    pub sign_in_options: Arc<sessions::SignInOptionsUseCase>,
    pub list_devices: Arc<device_trust::ListDevicesUseCase>,
    pub trust_device: Arc<device_trust::TrustDeviceUseCase>,
    pub remember_device: Arc<device_trust::RememberSignedInDeviceUseCase>,
    pub revoke_device: Arc<device_trust::RevokeDeviceUseCase>,
    pub break_glass_grant: Arc<break_glass::GrantUseCase>,
    pub break_glass_revoke: Arc<break_glass::RevokeUseCase>,
    pub watch_use: Arc<sessions::WatchUseUseCase>,
}

/// Single sign-on through a tenant's identity providers.
#[derive(Clone)]
pub struct FederationUseCases {
    pub begin: Arc<BeginSingleSignOnUseCase>,
    pub oidc_login: Arc<OidcLoginUseCase>,
    pub saml_login: Arc<SamlLoginUseCase>,
    pub exchange: Arc<ExchangeSignInCodeUseCase>,
}

/// Builds the authentication use cases over `a`, under `s`.
///
/// App sign-in drives the same sign-in, second-factor, sign-up and sign-out
/// use cases as the dashboard, so it is built from the instances made here
/// and in `identity` rather than a second copy of each.
pub fn build(a: &Adapters, s: &Settings, identity: &IdentityState) -> AuthenticationState {
    let password = password(a, s);
    let mfa = mfa(a, s);
    let sessions = sessions(a, s);
    let passkeys = passkeys(a, s);
    let federation = federation(a, s);
    let app_sign_in = app_sign_in(
        a,
        s,
        app_flows(&DashboardSignIn {
            password: &password,
            mfa: &mfa,
            sessions: &sessions,
            identity,
            federation: &federation,
            passkeys: &passkeys,
        }),
    );
    AuthenticationState {
        app_base_url: s.app_base_url.clone(),
        password,
        mfa,
        passkeys,
        sessions,
        federation,
        app_sign_in,
        pages: a.page_renderer.clone(),
    }
}

/// The dashboard's existing use cases shared with sign-in at an app's host.
struct DashboardSignIn<'a> {
    password: &'a PasswordUseCases,
    mfa: &'a MfaUseCases,
    sessions: &'a SessionUseCases,
    identity: &'a IdentityState,
    federation: &'a FederationUseCases,
    passkeys: &'a PasskeyUseCases,
}

/// Selects the dashboard's existing sign-in and account actions for app hosts.
fn app_flows(dashboard: &DashboardSignIn<'_>) -> AppSignInFlows {
    AppSignInFlows {
        tenant_login: dashboard.password.tenant_login.clone(),
        mfa: dashboard.mfa.verify.clone(),
        remember_device: dashboard.sessions.remember_device.clone(),
        confirm_by_email: dashboard.password.confirm_sign_in.clone(),
        sign_up: dashboard.identity.users.sign_up.clone(),
        verify_email: dashboard.identity.email.verify.clone(),
        logout: dashboard.sessions.logout.clone(),
        sso: app_sso(dashboard.federation),
        passkeys: app_passkeys(dashboard.passkeys),
        password_reset: AppPasswordResetFlows {
            request: dashboard.password.reset_request.clone(),
            confirm: dashboard.password.reset_confirm.clone(),
        },
        change_due_password: dashboard.password.change_due_password.clone(),
    }
}

/// The dashboard's own single sign-on, which an app's host goes through.
fn app_sso(federation: &FederationUseCases) -> AppSsoFlows {
    AppSsoFlows {
        begin: federation.begin.clone(),
        finish: AppSsoFinishFlows {
            oidc: federation.oidc_login.clone(),
            saml: federation.saml_login.clone(),
            exchange: federation.exchange.clone(),
        },
    }
}

/// The dashboard's own passkey sign-in, which an app's host goes through.
fn app_passkeys(passkeys: &PasskeyUseCases) -> AppPasskeyFlows {
    AppPasskeyFlows {
        begin: AppPasskeyBeginFlows {
            for_address: passkeys.login_begin.clone(),
            discoverable: passkeys.discover_begin.clone(),
        },
        confirm: passkeys.login_confirm.clone(),
    }
}

/// The password use cases: tenant sign-in, sign-in confirmation by mail,
/// magic links, password changes and resets.
fn password(a: &Adapters, s: &Settings) -> PasswordUseCases {
    let reset_request = Arc::new(reset_request(a, s));
    let (tenant_login, change_due_password) = tenant_sign_in(a, s);
    PasswordUseCases {
        sign_in_puzzle: Arc::new(sign_in_puzzle(a)),
        tenant_login,
        change_due_password,
        confirm_sign_in: Arc::new(confirm_sign_in(a)),
        request_magic_link: Arc::new(magic_link_request(a, s)),
        consume_magic_link: Arc::new(magic_link_sign_in(a)),
        change: Arc::new(password_change(a, s)),
        reset_resend: Arc::new(password::ResendResetUseCase::new(
            s.tunables.resend_cooldown,
            reset_request.clone(),
            password::ResendResetPorts {
                reset_store: a.reset_request_store.clone(),
                user_store: a.user_store.clone(),
                token_generator: a.refresh_token_generator.clone(),
            },
        )),
        reset_request,
        reset_status: Arc::new(reset_status(a)),
        reset_confirm: Arc::new(reset_confirm(a, s)),
        reset_code: Arc::new(reset_code(a, s)),
    }
}

/// Requests a password reset through throttled mail under the configured link policy.
fn reset_request(a: &Adapters, s: &Settings) -> password::ResetRequestUseCase {
    password::ResetRequestUseCase::new(
        reset_policy(s),
        password::ResetRequestPorts {
            user_store: a.user_store.clone(),
            mail_throttle: a.mail_throttle.clone(),
            mail: reset_mail(a),
        },
    )
}

/// Issues sign-in puzzles through the configured challenge issuer.
fn sign_in_puzzle(a: &Adapters) -> password::IssueSignInPuzzleUseCase {
    password::IssueSignInPuzzleUseCase::new(password::IssueSignInPuzzlePorts {
        issuer: a.challenge_issuer.clone(),
    })
}

/// Confirms tenant sign-ins through stored sessions and emailed links.
fn confirm_sign_in(a: &Adapters) -> password::ConfirmSignInByEmailUseCase {
    password::ConfirmSignInByEmailUseCase::new(password::ConfirmSignInByEmailPorts {
        tenants: a.tenant_store.clone(),
        sessions: a.session_store.clone(),
        users: a.user_store.clone(),
        links: a.sign_in_link_store_sign_in_confirmation.clone(),
        token_hasher: a.refresh_token_generator.clone(),
    })
}

/// Reads password reset status with its tenant and account.
fn reset_status(a: &Adapters) -> password::ResetStatusUseCase {
    password::ResetStatusUseCase::new(password::ResetStatusPorts {
        reset_store: a.reset_request_store.clone(),
        user_store: a.user_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
        tenant_store: a.tenant_store.clone(),
    })
}

/// Checks a reset's second-factor code through the configured code sender.
fn reset_code(a: &Adapters, s: &Settings) -> password::ResetCodeUseCase {
    password::ResetCodeUseCase::new(
        s.tunables.sent_code,
        password::ResetCodePorts {
            reset_store: a.reset_request_store.clone(),
            user_store: a.user_store.clone(),
            token_generator: a.refresh_token_generator.clone(),
            mfa_store: a.mfa_enrollment_store.clone(),
            codes: sent_codes(a),
        },
    )
}

/// How long a reset link works, and where it lands.
pub(crate) fn reset_policy(s: &Settings) -> ResetRequestPolicy {
    ResetRequestPolicy {
        lifetime: s.tunables.password_reset_ttl,
        base_url: s.app_base_url.clone(),
    }
}

/// What keeps and mails a reset link.
pub(crate) fn reset_mail(a: &Adapters) -> ResetMailPorts {
    ResetMailPorts {
        reset_store: a.reset_request_store.clone(),
        mailer: a.mailer.clone(),
        token_generator: a.refresh_token_generator.clone(),
        mail: a.mail_setup.clone(),
    }
}

/// The password hasher, reachable only through one of the node's permits.
pub(crate) fn password_hashing(a: &Adapters) -> PasswordHashing {
    PasswordHashing::new(a.password_hasher.clone(), a.password_hash_permits.clone())
}

/// The failed passwords counted per account and network, and the wait an
/// account being guessed at asks.
pub(crate) fn sign_in_counts(a: &Adapters) -> SignInCounts {
    SignInCounts::new(a.sign_in_attempt_counts.clone(), a.pause.clone())
}

/// The counts of failed password sign-ins, and the challenge a device
/// nobody trusted passes while one is high.
pub(crate) fn flood_gate(a: &Adapters) -> FloodGatePorts {
    FloodGatePorts {
        failures: a.sign_in_failure_budget.clone(),
        challenges: a.challenge_verifier.clone(),
    }
}

/// What a password someone chooses is checked against beyond its rules:
/// known breaches, common passwords and the account's earlier ones.
pub(crate) fn new_password(a: &Adapters) -> NewPasswordPorts {
    NewPasswordPorts {
        breaches: a.credential_breach_checker.clone(),
        common_passwords: a.common_password_list.clone(),
        history: a.password_history.clone(),
    }
}

/// A tenant user's password sign-in, finding the tenant by its slugs, and
/// the new password such a sign-in may owe, finished by the same sign-in.
fn tenant_sign_in(
    a: &Adapters,
    s: &Settings,
) -> (
    Arc<password::TenantLoginUseCase>,
    Arc<password::TenantChangeDueUseCase>,
) {
    let login = Arc::new(login(a, s));
    let tenant_login = Arc::new(password::TenantLoginUseCase::new(
        Arc::clone(&login),
        password::TenantLoginPorts {
            org_store: a.organization_store.clone(),
            tenant_store: a.tenant_store.clone(),
            user_store: a.user_store.clone(),
        },
    ));
    let change = Arc::new(password::ChangeDueUseCase::new(
        s.tunables.mfa_lockout,
        password::ChangeDuePorts {
            reset_store: a.reset_request_store.clone(),
            replacement: password_replacement(a),
            token_generator: a.refresh_token_generator.clone(),
            attempts: sign_in_counts(a),
            due: due_password(a),
            encryptor: a.secret_encryptor.clone(),
            verifier: a.mfa_verifier.clone(),
            sent_codes: a.sent_code_store.clone(),
            sent_code_generator: a.sent_code_generator.clone(),
        },
        login,
    ));
    let change_due = Arc::new(password::TenantChangeDueUseCase::new(
        change,
        Arc::clone(&tenant_login),
    ));
    (tenant_login, change_due)
}

/// Whether a sign-in's password must change, and what the change asks
/// besides it.
fn due_password(a: &Adapters) -> password::DuePorts {
    password::DuePorts {
        credentials: a.credential_store.clone(),
        hash_format: a.password_hash_format.clone(),
        reset_store: a.reset_request_store.clone(),
        enrollments: a.mfa_enrollment_store.clone(),
        text_messaging: a.text_messaging.clone(),
        mail: a.mail_setup.clone(),
        mailer: a.mailer.clone(),
    }
}

/// Mailing a magic sign-in link.
fn magic_link_request(a: &Adapters, s: &Settings) -> password::RequestMagicLinkUseCase {
    password::RequestMagicLinkUseCase::new(
        password::MagicLinkPolicy {
            lifetime: s.tunables.magic_link_ttl,
            base_url: s.app_base_url.clone(),
        },
        password::RequestMagicLinkPorts {
            user_store: a.user_store.clone(),
            magic_link_store: a.sign_in_link_store_magic_link.clone(),
            mailer: a.mailer.clone(),
            tenant_store: a.tenant_store.clone(),
            mail_throttle: a.mail_throttle.clone(),
            token_generator: a.refresh_token_generator.clone(),
            mail: a.mail_setup.clone(),
        },
    )
}

/// Signing in by following a magic link.
fn magic_link_sign_in(a: &Adapters) -> password::ConsumeMagicLinkUseCase {
    password::ConsumeMagicLinkUseCase::new(password::ConsumeMagicLinkPorts {
        magic_link_store: a.sign_in_link_store_magic_link.clone(),
        user_store: a.user_store.clone(),
        mfa_store: a.mfa_enrollment_store.clone(),
        passkey_store: a.passkey_store.clone(),
        session_store: a.session_store.clone(),
        tenant_store: a.tenant_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Setting a new password from a reset link, with a code when the account
/// has a second factor.
fn reset_confirm(a: &Adapters, s: &Settings) -> password::ResetConfirmUseCase {
    password::ResetConfirmUseCase::new(
        s.tunables.mfa_lockout,
        password::ResetConfirmPorts {
            reset_store: a.reset_request_store.clone(),
            replacement: password_replacement(a),
            mfa_store: a.mfa_enrollment_store.clone(),
            encryptor: a.secret_encryptor.clone(),
            verifier: a.mfa_verifier.clone(),
            sent_codes: a.sent_code_store.clone(),
            sent_code_generator: a.sent_code_generator.clone(),
            token_generator: a.refresh_token_generator.clone(),
        },
    )
}

/// Where a password chosen in place of the current one is checked, kept
/// and put in force, by a reset and by a sign-in that owes a new one.
fn password_replacement(a: &Adapters) -> password::ReplacementPorts {
    password::ReplacementPorts {
        tenant_store: a.tenant_store.clone(),
        hashing: password_hashing(a),
        new_password: new_password(a),
        credential_store: a.credential_store.clone(),
        user_store: a.user_store.clone(),
        session_store: a.session_store.clone(),
    }
}

/// The password sign-in every way into a tenant with a password shares.
fn login(a: &Adapters, s: &Settings) -> password::LoginUseCase {
    let t = &s.tunables;
    password::LoginUseCase::new(
        password::LoginPorts {
            tenants: a.tenant_store.clone(),
            user_lookup: a.user_lookup.clone(),
            attempts: sign_in_counts(a),
            sessions: a.session_store.clone(),
            hashing: password_hashing(a),
            flood: flood_gate(a),
            token_generator: a.refresh_token_generator.clone(),
            security: login_security(a),
            confirmation: password::ConfirmationMailPorts {
                links: a.sign_in_link_store_sign_in_confirmation.clone(),
                link_tokens: a.refresh_token_generator.clone(),
                mailer: a.mailer.clone(),
                mail: a.mail_setup.clone(),
            },
            password_due: due_password(a),
        },
        password::LoginSettings {
            security: password::SecurityRules {
                breach_policy: t.breach_policy,
                device_trust: t.device_trust,
            },
            confirmation: password::ConfirmationLinkPolicy {
                lifetime: t.sign_in_confirmation_ttl,
                base_url: s.app_base_url.clone(),
            },
        },
    )
}

/// What a password sign-in weighs besides the password: breaches, where it
/// comes from, the device and the person's history.
fn login_security(a: &Adapters) -> password::LoginSecurityPorts {
    password::LoginSecurityPorts {
        breach_checker: a.credential_breach_checker.clone(),
        geolocator: a.geolocator.clone(),
        devices: a.trusted_device_store.clone(),
        device_secret_hasher: a.code_hasher.clone(),
        sign_in_history: a.sign_in_history_store.clone(),
        users: a.user_store.clone(),
    }
}

/// Changing a password, under the tenant's history and minimum age rules.
fn password_change(a: &Adapters, s: &Settings) -> password::ChangeUseCase {
    let t = &s.tunables;
    password::ChangeUseCase::new(
        password::ChangePolicy {
            history_check_count: t.password_history_count,
            min_age_seconds: t.password_min_age_seconds,
        },
        password::ChangePorts {
            tenant_authorities: a.tenant_authorities.clone(),
            fresh_proofs: a.fresh_proofs.clone(),
            credential_store: a.credential_store.clone(),
            password_history: Some(a.password_history.clone()),
            hashing: password_hashing(a),
            user_store: a.user_store.clone(),
            session_store: a.session_store.clone(),
            tenant_store: a.tenant_store.clone(),
            new_password: new_password(a),
        },
    )
}

/// The second-factor use cases: setting up and removing an authenticator,
/// checking its codes, recovery codes and resuming a session.
fn mfa(a: &Adapters, s: &Settings) -> MfaUseCases {
    MfaUseCases {
        begin: Arc::new(begin_factor(a, s)),
        begin_code_factor: Arc::new(begin_code_factor(a, s)),
        confirm: Arc::new(enrollment_confirm(a, s)),
        abandon: Arc::new(abandon_factor(a)),
        disable: Arc::new(disable_factor(a, s)),
        status: Arc::new(factor_status(a)),
        options: Arc::new(factor_options(a)),
        send_code: Arc::new(send_factor_code(a, s)),
        verify: Arc::new(verify_factor(a, s)),
        recovery_code: Arc::new(recovery_code_sign_in(a, s)),
        regenerate_recovery_codes: Arc::new(regenerate_recovery_codes(a)),
        resume_session: Arc::new(resume_session(a, s)),
    }
}

/// Starts authenticator enrollment with the configured issuer and account proof ports.
fn begin_factor(a: &Adapters, s: &Settings) -> mfa::BeginUseCase {
    mfa::BeginUseCase::new(
        s.tunables.mfa_issuer.clone(),
        mfa::BeginPorts {
            enrollment_store: a.mfa_enrollment_store.clone(),
            encryptor: a.secret_encryptor.clone(),
            verifier: a.mfa_verifier.clone(),
            tenant_store: a.tenant_store.clone(),
            setter: setter(a),
        },
    )
}

/// Starts a mailed or texted factor under the configured code policy.
fn begin_code_factor(a: &Adapters, s: &Settings) -> mfa::CodeFactorBeginUseCase {
    mfa::CodeFactorBeginUseCase::new(
        s.tunables.sent_code,
        mfa::CodeFactorBeginPorts {
            enrollment_store: a.mfa_enrollment_store.clone(),
            codes: sent_codes(a),
            tenant_store: a.tenant_store.clone(),
            setter: setter(a),
        },
    )
}

/// Abandons pending enrollment through account authority and fresh proofs.
fn abandon_factor(a: &Adapters) -> mfa::AbandonUseCase {
    mfa::AbandonUseCase::new(mfa::AbandonPorts {
        enrollment_store: a.mfa_enrollment_store.clone(),
        user_store: a.user_store.clone(),
        session_store: a.session_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
    })
}

/// Disables an authenticator after verifying its code under the lockout policy.
fn disable_factor(a: &Adapters, s: &Settings) -> mfa::DisableUseCase {
    let lockout = s.tunables.mfa_lockout;
    mfa::DisableUseCase::new(
        lockout,
        mfa::DisablePorts {
            codes: factor_codes(a),
            user_store: a.user_store.clone(),
            session_store: a.session_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    )
}

/// Reads enrollment status through tenant authority.
fn factor_status(a: &Adapters) -> mfa::GetStatusUseCase {
    mfa::GetStatusUseCase::new(mfa::GetStatusPorts {
        enrollment_store: a.mfa_enrollment_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Verifies the session's second factor under the configured lockout.
fn verify_factor(a: &Adapters, s: &Settings) -> mfa::VerificationUseCase {
    let lockout = s.tunables.mfa_lockout;
    mfa::VerificationUseCase::new(
        lockout,
        mfa::VerificationPorts {
            session_store: a.session_store.clone(),
            user_store: a.user_store.clone(),
            tenant_store: a.tenant_store.clone(),
            codes: factor_codes(a),
        },
    )
}

/// Resumes a waiting session after second-factor verification.
fn resume_session(a: &Adapters, s: &Settings) -> mfa::ResumeSessionUseCase {
    let lockout = s.tunables.mfa_lockout;
    mfa::ResumeSessionUseCase::new(
        lockout,
        mfa::ResumeSessionPorts {
            session_store: a.session_store.clone(),
            user_store: a.user_store.clone(),
            tenant_store: a.tenant_store.clone(),
            codes: factor_codes(a),
        },
    )
}

/// Confirming a factor being set up with its first code, which hands out
/// recovery codes.
fn enrollment_confirm(a: &Adapters, s: &Settings) -> mfa::ConfirmUseCase {
    mfa::ConfirmUseCase::new(
        s.tunables.mfa_lockout,
        mfa::ConfirmPorts {
            codes: factor_codes(a),
            recovery_generator: a.recovery_code_generator.clone(),
            recovery_store: a.recovery_code_store.clone(),
            user_store: a.user_store.clone(),
            tenant_store: a.tenant_store.clone(),
            session_store: a.session_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    )
}

/// What a person may set up and what they hold.
fn factor_options(a: &Adapters) -> mfa::FactorOptionsUseCase {
    mfa::FactorOptionsUseCase::new(mfa::FactorOptionsPorts {
        enrollment_store: a.mfa_enrollment_store.clone(),
        tenant_store: a.tenant_store.clone(),
        text_messaging: a.text_messaging.clone(),
        mail: a.mail_setup.clone(),
        user_store: a.user_store.clone(),
        session_store: a.session_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Sending a code for a mailed or texted factor.
fn send_factor_code(a: &Adapters, s: &Settings) -> mfa::SendFactorCodeUseCase {
    mfa::SendFactorCodeUseCase::new(
        s.tunables.sent_code,
        mfa::SendFactorCodePorts {
            enrollment_store: a.mfa_enrollment_store.clone(),
            codes: sent_codes(a),
            user_store: a.user_store.clone(),
            session_store: a.session_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    )
}

/// Finishing a sign-in's second factor with a recovery code.
fn recovery_code_sign_in(a: &Adapters, s: &Settings) -> mfa::RecoveryCodeLoginUseCase {
    mfa::RecoveryCodeLoginUseCase::new(
        s.tunables.mfa_lockout,
        mfa::RecoveryCodeLoginPorts {
            session_store: a.session_store.clone(),
            user_store: a.user_store.clone(),
            tenant_store: a.tenant_store.clone(),
            recovery_store: a.recovery_code_store.clone(),
            recovery_generator: a.recovery_code_generator.clone(),
            enrollment_store: a.mfa_enrollment_store.clone(),
        },
    )
}

/// Replacing a person's recovery codes with a fresh set.
fn regenerate_recovery_codes(a: &Adapters) -> mfa::RegenerateRecoveryCodesUseCase {
    mfa::RegenerateRecoveryCodesUseCase::new(mfa::RegenerateRecoveryCodesPorts {
        tenant_authorities: a.tenant_authorities.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
        enrollment_store: a.mfa_enrollment_store.clone(),
        recovery_store: a.recovery_code_store.clone(),
        recovery_generator: a.recovery_code_generator.clone(),
    })
}

/// Who sets up a factor, and what lets them.
fn setter(a: &Adapters) -> mfa::SetterPorts {
    mfa::SetterPorts {
        user_store: a.user_store.clone(),
        session_store: a.session_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        fresh_proofs: a.fresh_proofs.clone(),
    }
}

/// What makes, keeps and sends a mailed or texted code.
fn sent_codes(a: &Adapters) -> mfa::SentCodePorts {
    mfa::SentCodePorts {
        sent_codes: a.sent_code_store.clone(),
        generator: a.sent_code_generator.clone(),
        sender: a.factor_code_sender.clone(),
        text_messaging: a.text_messaging.clone(),
        mail: a.mail_setup.clone(),
    }
}

/// The person's factor and what checks its codes, whether the factor's
/// own or sent.
fn factor_codes(a: &Adapters) -> mfa::FactorCodePorts {
    mfa::FactorCodePorts {
        enrollment_store: a.mfa_enrollment_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        verifier: a.mfa_verifier.clone(),
        sent_codes: a.sent_code_store.clone(),
        sent_code_generator: a.sent_code_generator.clone(),
    }
}

/// The passkey use cases: adding one, signing in with one, and listing,
/// renaming and deleting them.
fn passkeys(a: &Adapters, s: &Settings) -> PasskeyUseCases {
    PasskeyUseCases {
        register_begin: Arc::new(begin_passkey_registration(a, s)),
        register_confirm: Arc::new(confirm_passkey_registration(a, s)),
        login_begin: Arc::new(begin_passkey_sign_in(a, s)),
        discover_begin: Arc::new(discover_passkey(a, s)),
        login_confirm: Arc::new(confirm_passkey_sign_in(a)),
        list: Arc::new(list_passkeys(a)),
        rename: Arc::new(rename_passkey(a)),
        delete: Arc::new(delete_passkey(a)),
    }
}

/// Starts passkey registration with account proof ports and the configured ceremony lifetime.
fn begin_passkey_registration(a: &Adapters, s: &Settings) -> passkeys::RegistrationBeginUseCase {
    let ttl = s.tunables.passkey_ceremony_ttl;
    passkeys::RegistrationBeginUseCase::new(
        ttl,
        passkeys::RegistrationBeginPorts {
            registrant: registrant(a),
            verifier: a.passkey_verifier.clone(),
            ceremony_store: a.passkey_ceremony_store.clone(),
        },
    )
}

/// Confirms passkey registration with fresh proofs and the configured credential limit.
fn confirm_passkey_registration(
    a: &Adapters,
    s: &Settings,
) -> passkeys::RegistrationConfirmUseCase {
    passkeys::RegistrationConfirmUseCase::new(
        passkeys::RegistrationPolicy {
            max_passkeys_per_user: s.tunables.max_passkeys_per_user,
        },
        passkeys::RegistrationConfirmPorts {
            registrant: registrant(a),
            fresh_proofs: a.fresh_proofs.clone(),
            passkey_store: a.passkey_store.clone(),
            verifier: a.passkey_verifier.clone(),
            ceremony_store: a.passkey_ceremony_store.clone(),
            tenant_store: a.tenant_store.clone(),
        },
    )
}

/// Starts passkey sign-in using the account lookup and ceremony store.
fn begin_passkey_sign_in(a: &Adapters, s: &Settings) -> passkeys::LoginBeginUseCase {
    let ttl = s.tunables.passkey_ceremony_ttl;
    passkeys::LoginBeginUseCase::new(
        ttl,
        passkeys::LoginBeginPorts {
            user_lookup: a.user_lookup.clone(),
            passkey_store: a.passkey_store.clone(),
            verifier: a.passkey_verifier.clone(),
            ceremony_store: a.passkey_ceremony_store.clone(),
        },
    )
}

/// Starts a discoverable passkey ceremony through the verifier.
fn discover_passkey(a: &Adapters, s: &Settings) -> passkeys::DiscoverableBeginUseCase {
    let ttl = s.tunables.passkey_ceremony_ttl;
    passkeys::DiscoverableBeginUseCase::new(
        ttl,
        passkeys::DiscoverableBeginPorts {
            verifier: a.passkey_verifier.clone(),
            ceremony_store: a.passkey_ceremony_store.clone(),
        },
    )
}

/// Confirms passkey sign-in against account, tenant and session storage.
fn confirm_passkey_sign_in(a: &Adapters) -> passkeys::LoginConfirmUseCase {
    passkeys::LoginConfirmUseCase::new(passkeys::LoginConfirmPorts {
        passkey_store: a.passkey_store.clone(),
        verifier: a.passkey_verifier.clone(),
        ceremony_store: a.passkey_ceremony_store.clone(),
        session_store: a.session_store.clone(),
        user_store: a.user_store.clone(),
        tenant_store: a.tenant_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
    })
}

/// Lists passkeys under tenant authority.
fn list_passkeys(a: &Adapters) -> passkeys::ListUseCase {
    passkeys::ListUseCase::new(passkeys::ListPorts {
        passkey_store: a.passkey_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Renames passkeys under tenant authority.
fn rename_passkey(a: &Adapters) -> passkeys::RenameUseCase {
    passkeys::RenameUseCase::new(passkeys::RenamePorts {
        passkey_store: a.passkey_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Deletes passkeys with account and session storage.
fn delete_passkey(a: &Adapters) -> passkeys::DeleteUseCase {
    passkeys::DeleteUseCase::new(passkeys::DeletePorts {
        passkey_store: a.passkey_store.clone(),
        user_store: a.user_store.clone(),
        session_store: a.session_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// What finds out who is adding a passkey.
fn registrant(a: &Adapters) -> RegistrantPorts {
    RegistrantPorts {
        tenant_authorities: a.tenant_authorities.clone(),
        sessions: a.session_store.clone(),
        users: a.user_store.clone(),
        token_hasher: a.refresh_token_generator.clone(),
    }
}

/// The session use cases: signing out, refreshing, sign-in options,
/// trusted devices and break-glass access.
fn sessions(a: &Adapters, s: &Settings) -> SessionUseCases {
    SessionUseCases {
        logout: Arc::new(logout(a)),
        refresh: Arc::new(refresh_session(a)),
        sign_in_options: Arc::new(sign_in_options(a)),
        list_devices: Arc::new(list_devices(a)),
        trust_device: Arc::new(trust_device(a, s)),
        remember_device: Arc::new(remember_device(a, s)),
        revoke_device: Arc::new(revoke_device(a)),
        break_glass_grant: Arc::new(grant_break_glass(a, s)),
        break_glass_revoke: Arc::new(revoke_break_glass(a)),
        watch_use: Arc::new(watch_session_use(a)),
    }
}

/// Holds each session's uses against where it was last used.
fn watch_session_use(a: &Adapters) -> sessions::WatchUseUseCase {
    sessions::WatchUseUseCase::new(sessions::WatchUsePorts {
        session_store: a.session_store.clone(),
        geolocator: a.geolocator.clone(),
        factors: a.factor_standing.clone(),
        users: a.user_store.clone(),
    })
}

/// Signs tenant accounts out through their sessions and authority.
fn logout(a: &Adapters) -> sessions::LogoutUseCase {
    sessions::LogoutUseCase::new(sessions::LogoutPorts {
        session_store: a.session_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Refreshes sessions against the current tenant and account.
fn refresh_session(a: &Adapters) -> sessions::TokenRefreshUseCase {
    sessions::TokenRefreshUseCase::new(sessions::RefreshPorts {
        session_store: a.session_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
        users: a.user_store.clone(),
        tenants: a.tenant_store.clone(),
    })
}

/// Reads sign-in options from tenant connections and mail availability.
fn sign_in_options(a: &Adapters) -> sessions::SignInOptionsUseCase {
    sessions::SignInOptionsUseCase::new(sessions::SignInOptionsPorts {
        connection_store: a.connection_store.clone(),
        tenant_store: a.tenant_store.clone(),
        mail: a.mail_setup.clone(),
    })
}

/// Lists remembered devices under account authority.
fn list_devices(a: &Adapters) -> device_trust::ListDevicesUseCase {
    device_trust::ListDevicesUseCase::new(device_trust::ListDevicesPorts {
        device_store: a.trusted_device_store.clone(),
        user_store: a.user_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Remembers a device under the configured device limit.
fn trust_device(a: &Adapters, s: &Settings) -> device_trust::TrustDeviceUseCase {
    let t = &s.tunables;
    device_trust::TrustDeviceUseCase::new(
        device_trust::Policy {
            max_devices_per_user: t.max_trusted_devices_per_user,
        },
        device_trust::TrustDevicePorts {
            device_store: a.trusted_device_store.clone(),
            secret_hasher: a.code_hasher.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    )
}

/// Remembers a signed-in device through its session under the device limit.
fn remember_device(a: &Adapters, s: &Settings) -> device_trust::RememberSignedInDeviceUseCase {
    let t = &s.tunables;
    device_trust::RememberSignedInDeviceUseCase::new(
        device_trust::Policy {
            max_devices_per_user: t.max_trusted_devices_per_user,
        },
        device_trust::RememberSignedInPorts {
            device_store: a.trusted_device_store.clone(),
            secret_hasher: a.code_hasher.clone(),
            session_store: a.session_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    )
}

/// Revokes device trust and its access records through tenant authority.
fn revoke_device(a: &Adapters) -> device_trust::RevokeDeviceUseCase {
    device_trust::RevokeDeviceUseCase::new(device_trust::RevokeDevicePorts {
        device_store: a.trusted_device_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Grants emergency access under the configured duration limit.
fn grant_break_glass(a: &Adapters, s: &Settings) -> break_glass::GrantUseCase {
    let t = &s.tunables;
    break_glass::GrantUseCase::new(
        break_glass::BreakGlassLimits {
            max_duration_seconds: t.break_glass_max_seconds,
        },
        break_glass::GrantPorts {
            grant_store: a.break_glass_store.clone(),
            users: a.user_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    )
}

/// Revokes emergency access through the stored grant and account authority.
fn revoke_break_glass(a: &Adapters) -> break_glass::RevokeUseCase {
    break_glass::RevokeUseCase::new(break_glass::RevokePorts {
        grant_store: a.break_glass_store.clone(),
        users: a.user_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The single sign-on use cases: starting a sign-in, finishing it over
/// OIDC or SAML, and swapping the sign-in code for a session.
fn federation(a: &Adapters, s: &Settings) -> FederationUseCases {
    FederationUseCases {
        begin: Arc::new(begin_single_sign_on(a)),
        oidc_login: Arc::new(oidc_sign_in(a, s)),
        saml_login: Arc::new(saml_sign_in(a, s)),
        exchange: Arc::new(exchange_sign_in_code(a)),
    }
}

/// Starts tenant single sign-on through the configured provider and signing keys.
fn begin_single_sign_on(a: &Adapters) -> BeginSingleSignOnUseCase {
    BeginSingleSignOnUseCase::new(BeginSingleSignOnPorts {
        encryptor: a.secret_encryptor.clone(),
        connection_store: a.connection_store.clone(),
        oidc_validator: a.oidc_validator.clone(),
        flow_store: a.oidc_flow_store.clone(),
        saml_messages: a.saml_service_provider_messages.clone(),
        saml_requests: a.saml_request_store.clone(),
        code_hasher: a.code_hasher.clone(),
        tenant_store: a.tenant_store.clone(),
        key_store: a.signing_key_store.clone(),
    })
}

/// Checks an OIDC response and completes sign-in through the shared completion ports.
fn oidc_sign_in(a: &Adapters, s: &Settings) -> OidcLoginUseCase {
    OidcLoginUseCase::new(
        sso_policy(s),
        OidcLoginPorts {
            encryptor: a.secret_encryptor.clone(),
            connection_store: a.connection_store.clone(),
            oidc_validator: a.oidc_validator.clone(),
            flow_store: a.oidc_flow_store.clone(),
            tenant_store: a.tenant_store.clone(),
            completion: sso_completion(a),
        },
    )
}

/// Checks a SAML response and its replay ledger before completing sign-in.
fn saml_sign_in(a: &Adapters, s: &Settings) -> SamlLoginUseCase {
    SamlLoginUseCase::new(
        sso_policy(s),
        SamlLoginPorts {
            connection_store: a.connection_store.clone(),
            saml_validator: a.saml_validator.clone(),
            assertion_ledger: a.saml_assertion_ledger.clone(),
            saml_requests: a.saml_request_store.clone(),
            tenant_store: a.tenant_store.clone(),
            completion: sso_completion(a),
        },
    )
}

/// Exchanges a sign-in code through the account, tenant and provider-session stores.
fn exchange_sign_in_code(a: &Adapters) -> ExchangeSignInCodeUseCase {
    ExchangeSignInCodeUseCase::new(ExchangeSignInCodePorts {
        code_hasher: a.code_hasher.clone(),
        codes: a.sign_in_code_store.clone(),
        sessions: a.session_store.clone(),
        users: a.user_store.clone(),
        tenants: a.tenant_store.clone(),
        token_generator: a.refresh_token_generator.clone(),
        provider_sessions: a.provider_session_store.clone(),
    })
}

/// Sets the provider sign-in code's lifetime and accepted display-name shape.
fn sso_policy(s: &Settings) -> SsoPolicy {
    SsoPolicy {
        code_lifetime: s.tunables.sign_in_code_ttl,
        display_names: s.domain_limits.display_name.clone(),
    }
}

/// What finishes a sign-in an identity provider vouched for.
fn sso_completion(a: &Adapters) -> SsoCompletionPorts {
    SsoCompletionPorts {
        accounts: SsoAccountPorts {
            users: a.user_store.clone(),
            roles: a.role_store.clone(),
            assignments: a.role_assignment_store.clone(),
            links: a.federated_link_store.clone(),
            access: a.access_record_store.clone(),
            separation_rules: a.separation_rule_store.clone(),
            memberships: a.group_membership_store.clone(),
            mapped_holdings: a.mapped_holdings_store.clone(),
            limit_enforcer: a.limit_enforcer.clone(),
            plan_limits: a.plan_limits_source.clone(),
        },
        factors: SsoFactorPorts {
            mfa_enrollments: a.mfa_enrollment_store.clone(),
            passkeys: a.passkey_store.clone(),
            mailer: a.mailer.clone(),
        },
        session: SsoSessionPorts {
            sessions: a.session_store.clone(),
            provider_sessions: a.provider_session_store.clone(),
            token_generator: a.refresh_token_generator.clone(),
            code_hasher: a.code_hasher.clone(),
            sign_in_codes: a.sign_in_code_store.clone(),
        },
    }
}

/// Receiving the gateway's relayed sign-ins, driving `flows`.
fn app_sign_in(a: &Adapters, s: &Settings, flows: AppSignInFlows) -> Arc<ReceiveUseCase> {
    let lifetimes = s.tunables.app_sign_in;
    let hand_over = hand_over(a, s);
    let actions = AppSignInActions::new(
        SignInPorts {
            target: sign_in_target(a),
            session_store: a.session_store.clone(),
            challenge_store: a.mfa_challenge_store.clone(),
            code_hasher: a.code_hasher.clone(),
            tokens: a.app_session_tokens.clone(),
            branding_store: a.branding_store.clone(),
            connection_store: a.connection_store.clone(),
            handoff_store: a.handoff_store.clone(),
            session_check: a.app_session_check.clone(),
        },
        flows,
        s.app_base_url.clone(),
        lifetimes,
    );
    Arc::new(ReceiveUseCase::new(
        ReceivePorts {
            seal: a.request_seal.clone(),
            nonces: a.nonce_ledger.clone(),
        },
        Arc::new(actions),
        Arc::new(hand_over),
    ))
}

/// Carries an app session across hosts using the same checks and handoff store.
fn hand_over(a: &Adapters, s: &Settings) -> HandOverAppSessionUseCase {
    HandOverAppSessionUseCase::new(AcrossHosts::new(
        AcrossHostsPorts {
            target: sign_in_target(a),
            session_store: a.session_store.clone(),
            code_hasher: a.code_hasher.clone(),
            tokens: a.app_session_tokens.clone(),
            handoff_store: a.handoff_store.clone(),
            session_check: a.app_session_check.clone(),
        },
        s.app_base_url.clone(),
        s.tunables.app_sign_in,
    ))
}

/// The stores an app sign-in request is resolved against.
fn sign_in_target(a: &Adapters) -> TargetPorts {
    TargetPorts {
        tenant_store: a.tenant_store.clone(),
        org_store: a.organization_store.clone(),
        service_store: a.service_store.clone(),
    }
}
