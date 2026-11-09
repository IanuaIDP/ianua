//! App sign-in: signing people in, up and out on the host of an app behind
//! the gateway.
//!
//! The gateway answers a service's sign-in addresses and hands each request
//! here, over the internal listener. Everything that decides anything happens
//! here, through the same use cases the dashboard's own sign-in uses: the
//! tenant's password policy, lockout, risk checks, second factor, sign-up
//! switch, single sign-on, passkeys, password reset and audit trail all apply
//! unchanged. What is new is the result: a session bound to the app, and a
//! token for its host's cookie.

use std::num::NonZeroU8;
use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password_rules::ChangeReason;
use ianua_domain::domains::authentication::device_trust::DeviceSecret;
use ianua_domain::domains::authentication::recovery::change_proof::ChangeProof;
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    DomainName, Email, Fact, HttpsUrl, IpAddress, Lifetime, ServiceId, UserAgent,
};
use time::OffsetDateTime;

use crate::ports::authentication::{
    AppSessionCheck, AppSessionTokens, HandoffStore, IssuedAppSession, MfaChallengeStore,
};
use crate::ports::branding::BrandingStore;
use crate::ports::federation::ConnectionStore;
use crate::ports::oauth::CodeHasher;
use crate::ports::shared::SessionStore;
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authentication::federation::BeginSingleSignOnUseCase;
use crate::use_cases::authentication::mfa::VerificationUseCase;
use crate::use_cases::authentication::passkeys::{LoginConfirmUseCase, LoginStarted};
use crate::use_cases::authentication::password::{
    ConfirmSignInByEmailUseCase, ResetConfirmUseCase, ResetRequestUseCase, TenantChangeDueUseCase,
    TenantLoginUseCase,
};
use crate::use_cases::authentication::sessions::LogoutUseCase;
use crate::use_cases::authentication::sessions::device_trust::RememberSignedInDeviceUseCase;
use crate::use_cases::identity::email::VerifyUseCase;
use crate::use_cases::identity::users::SignUpUseCase;

/// Where an app sign-in request came from, as the gateway saw it.
pub struct AppSignInContext {
    /// The tenant the request's host belongs to.
    pub tenant: ScopedTenant,
    /// The service whose sign-in addresses the request was sent to.
    pub service_id: ServiceId,
    /// The host the request was sent to.
    pub host: DomainName,
    /// The address the request came from.
    pub ip_address: Option<IpAddress>,
    /// The client the request came from.
    pub user_agent: Option<UserAgent>,
}

impl AppSignInContext {
    /// Where the request came from, as a sign-in records it.
    #[must_use]
    pub fn origin(&self) -> ClientOrigin {
        ClientOrigin {
            ip_address: Fact::from_option(self.ip_address.clone()),
            user_agent: self.user_agent.clone(),
        }
    }
}

/// What a person asks for at an app's sign-in addresses, as the gateway
/// relayed it: each action and the request its use case takes.
pub(crate) enum AppSignInCommand {
    /// Sign in with a password.
    LogIn(AppLogInRequest),
    /// Finish signing in with a second factor.
    CompleteMfa(AppCompleteMfaRequest),
    /// Finish signing in from the link mailed to the person.
    ConfirmByEmail(AppConfirmByEmailRequest),
    /// Create an account.
    SignUp(AppSignUpRequest),
    /// Confirm an address from the link mailed to it, by its token.
    Verify(Secret),
    /// End the session the host's cookie holds, if any, by its token.
    LogOut(Option<Secret>),
    /// Fetch a short-lived token for a service that accepts this sign-in by
    /// token.
    IssueToken(AppIssueTokenRequest),
    /// Hand out a code carrying the session to a host of a service that
    /// accepts this sign-in with a cookie of its own, bound to the browser
    /// that asked from there.
    IssueHop(AppIssueHopRequest),
    /// Show the page a person fills in for an action.
    ShowPage(AppSignInPageRequest),
    /// Start signing in through an outside identity provider.
    SsoStart(AppSsoStartRequest),
    /// Finish signing in from the outside identity provider's answer.
    SsoCallback(AppSsoCallbackRequest),
    /// Ask for a passkey challenge, for the address typed if any.
    PasskeyBegin(Option<Email>),
    /// Sign in with a passkey's answer to its challenge.
    PasskeyConfirm(AppPasskeyConfirmRequest),
    /// Ask for a link to set a new password, mailed to the address.
    ForgotPassword(Email),
    /// Set a new password from the mailed link.
    ResetPassword(AppResetPasswordRequest),
    /// Set the new password a sign-in owes, in the browser whose challenge
    /// cookie holds it, and finish that sign-in.
    ChangePassword(AppChangePasswordRequest),
}

/// What came of an app sign-in request.
pub enum AppSignInOutcome {
    /// Signed in: set the session cookie and send them on.
    SignedIn {
        /// The token for the host's session cookie.
        session: IssuedAppSession,
        /// Where to send them.
        return_to: ReturnPath,
        /// The hosts of services accepting the sign-in with a cookie of their
        /// own, for the browser to pass through. Each asks for its code
        /// once the browser is there.
        hops: Vec<DomainName>,
        /// The secret of the device the sign-in just remembered on this
        /// host, for the host's device cookie; none when it remembered
        /// none.
        remembered: Option<DeviceSecret>,
    },
    /// A code for a hop, bound to the browser that asked for it.
    HopIssued(Hop),
    /// A hop arrived: set the session cookie on this host.
    HandedOver(IssuedAppSession),
    /// A short-lived bearer token for a service accepting the sign-in by
    /// token.
    Token(IssuedAppSession),
    /// The password was right, but an admin set it or it expired. No
    /// session opened; a new password set with the change's token finishes
    /// the sign-in. For a password an admin set it also asks the person's
    /// own proof: a code from their factor, or their mailbox, where the
    /// token went instead.
    PasswordChangeRequired {
        /// The single-use token the new password is set with, for the
        /// host's challenge cookie; none when it was mailed.
        challenge: Option<Secret>,
        /// What the change asks besides the new password.
        proof: ChangeProof,
        /// Why the password must change.
        reason: ChangeReason,
        /// When the token stops working.
        expires_at: OffsetDateTime,
    },
    /// The person proved who they are; a second factor is owed.
    MfaRequired {
        /// The token proving it, for the host's challenge cookie.
        challenge: Secret,
        /// When the challenge lapses.
        expires_at: OffsetDateTime,
    },
    /// The password was right; the sign-in waits for the person to confirm
    /// it from the link mailed to them, in this browser.
    ConfirmByEmail {
        /// The token holding the sign-in, for the host's challenge cookie.
        challenge: Secret,
        /// When the challenge lapses.
        expires_at: OffsetDateTime,
    },
    /// Send the browser to the outside identity provider. The host keeps
    /// both secrets and the return path in a cookie until it comes back.
    SsoRedirect {
        /// The provider's address.
        url: HttpsUrl,
        /// The secret the provider's answer is accepted only with.
        binding: Secret,
        /// The secret the session is handed back against.
        hand_back: Secret,
        /// Where to send the person once they are in.
        return_to: Option<ReturnPath>,
    },
    /// A passkey challenge for the browser to answer.
    PasskeyChallenge(LoginStarted),
    /// The session is over: clear the cookies.
    SignedOut,
    /// Done, with nothing to hand back. A sign-up or a request for a reset
    /// link answers this way whether or not the address was known, so it
    /// cannot be used to find accounts.
    Accepted,
    /// A page to show.
    Page(Box<SignInPage>),
}

/// A host of a service accepting the sign-in with a cookie of its own, and
/// the one-time code that sets the cookie there in the browser that asked
/// for it. The code is a credential, so this has no `Debug`.
pub struct Hop {
    /// Where the browser exchanges this code for a session cookie.
    pub host: DomainName,
    /// The code the browser carries to it.
    pub code: Secret,
}

/// The ports app sign-in needs beyond the use cases it drives.
#[derive(ianua_macros::Fakes)]
pub struct SignInPorts {
    /// The stores a request is resolved against.
    pub target: TargetPorts,
    /// Port for binding a new session to the app.
    pub session_store: Arc<dyn SessionStore>,
    /// Port for the second-factor step.
    pub challenge_store: Arc<dyn MfaChallengeStore>,
    /// Port for generating and hashing challenge tokens and the secrets a
    /// single sign-on is handed back against.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// Port for minting and reading app session tokens.
    pub tokens: Arc<dyn AppSessionTokens>,
    /// Port for the workspace's branding, which its pages wear.
    pub branding_store: Arc<dyn BrandingStore>,
    /// Port for the workspace's outside identity providers, which its login
    /// page offers.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// Port for the one-time codes that carry a session to other hosts.
    pub handoff_store: Arc<dyn HandoffStore>,
    /// Port for checking a session is still live before handing it on.
    pub session_check: Arc<dyn AppSessionCheck>,
}

/// The sign-in use cases app sign-in drives, shared with the dashboard's.
pub struct AppSignInFlows {
    /// Password sign-in.
    pub tenant_login: Arc<TenantLoginUseCase>,
    /// The second factor.
    pub mfa: Arc<VerificationUseCase>,
    /// Remembering the device a sign-in that proved its second factor came
    /// from, when the person asks.
    pub remember_device: Arc<RememberSignedInDeviceUseCase>,
    /// Confirming a sign-in from the link mailed for it.
    pub confirm_by_email: Arc<ConfirmSignInByEmailUseCase>,
    /// Self sign-up, which mails the verification link itself.
    pub sign_up: Arc<SignUpUseCase>,
    /// Confirming an address.
    pub verify_email: Arc<VerifyUseCase>,
    /// Ending a session.
    pub logout: Arc<LogoutUseCase>,
    /// Single sign-on through the tenant's outside identity providers.
    pub sso: AppSsoFlows,
    /// Passkey sign-in.
    pub passkeys: AppPasskeyFlows,
    /// Asking for and setting a new password.
    pub password_reset: AppPasswordResetFlows,
    /// Setting the new password a sign-in owes, and finishing it.
    pub change_due_password: Arc<TenantChangeDueUseCase>,
}

/// The dashboard's own single sign-on, which the app's host goes through.
pub struct AppSsoFlows {
    /// Sending the browser to the provider.
    pub begin: Arc<BeginSingleSignOnUseCase>,
    /// Finishing from the provider's answer.
    pub finish: AppSsoFinishFlows,
}

/// The dashboard's own passkey sign-in.
pub struct AppPasskeyFlows {
    /// Opening a ceremony.
    pub begin: AppPasskeyBeginFlows,
    /// Checking the answer and opening the session.
    pub confirm: Arc<LoginConfirmUseCase>,
}

/// The dashboard's own password reset.
pub struct AppPasswordResetFlows {
    /// Mailing the link.
    pub request: Arc<ResetRequestUseCase>,
    /// Setting the password from it.
    pub confirm: Arc<ResetConfirmUseCase>,
}

/// How long the short-lived steps of an app sign-in stay usable.
#[derive(Debug, Clone, Copy)]
pub struct AppSignInLifetimes {
    /// How long the second-factor step stays open after the password.
    pub mfa_challenge: Lifetime,
    /// Wrong codes the second-factor step tolerates before it closes.
    pub mfa_challenge_attempts: NonZeroU8,
    /// How long a one-time code carrying a session to another host lasts.
    pub handoff: Lifetime,
    /// How long a token for a service accepting the sign-in by token lasts.
    /// The owner's pages fetch another when it runs out, and a session that
    /// has ended hands out no more.
    pub access: Lifetime,
}

/// The use cases behind an app's sign-in addresses, one per action, sharing
/// the ports and the cross-host hand-over.
pub struct AppSignInActions {
    /// Signing in with a password.
    pub log_in: AppLogInUseCase,
    /// Finishing with a second factor.
    pub complete_mfa: AppCompleteMfaUseCase,
    /// Finishing from the link mailed to the person.
    pub confirm_by_email: AppConfirmByEmailUseCase,
    /// Creating an account.
    pub sign_up: AppSignUpUseCase,
    /// Confirming an address.
    pub verify_email: AppVerifyEmailUseCase,
    /// Ending a session.
    pub log_out: AppLogOutUseCase,
    /// Issuing a token for a service accepting the sign-in by token.
    pub issue_token: AppIssueTokenUseCase,
    /// Issuing a hop's code for a service accepting the sign-in with a
    /// cookie of its own.
    pub issue_hop: AppIssueHopUseCase,
    /// Showing a sign-in page.
    pub show_page: PageUseCase,
    /// Starting single sign-on.
    pub sso_start: AppSsoStartUseCase,
    /// Finishing single sign-on.
    pub sso_callback: AppSsoCallbackUseCase,
    /// Opening a passkey sign-in.
    pub passkey_begin: AppPasskeyBeginUseCase,
    /// Signing in with a passkey's answer.
    pub passkey_confirm: AppPasskeyConfirmUseCase,
    /// Mailing a link to set a new password.
    pub forgot_password: AppForgotPasswordUseCase,
    /// Setting a new password from the mailed link.
    pub reset_password: AppResetPasswordUseCase,
    /// Setting the new password a sign-in owes, and finishing it.
    pub change_password: AppChangePasswordUseCase,
}

impl AppSignInActions {
    /// Builds every action over `ports`, driving the dashboard's own sign-in
    /// use cases in `flows`. `app_base_url` is the platform's own address,
    /// which a tenant's token issuer is built from when it sets none, and
    /// which names the platform as a SAML service provider.
    #[must_use]
    pub fn new(
        ports: SignInPorts,
        flows: AppSignInFlows,
        app_base_url: HttpsUrl,
        lifetimes: AppSignInLifetimes,
    ) -> Self {
        let common = Arc::new(relay::common::AppSignInCommon::new(
            ports,
            app_base_url,
            lifetimes,
        ));
        let shared = || Arc::clone(&common);
        let AppSignInFlows {
            sso,
            passkeys,
            password_reset,
            ..
        } = flows;
        Self {
            log_in: AppLogInUseCase::new(shared(), flows.tenant_login),
            complete_mfa: AppCompleteMfaUseCase::new(shared(), flows.mfa, flows.remember_device),
            confirm_by_email: AppConfirmByEmailUseCase::new(shared(), flows.confirm_by_email),
            sign_up: AppSignUpUseCase::new(shared(), flows.sign_up),
            verify_email: AppVerifyEmailUseCase::new(shared(), flows.verify_email),
            log_out: AppLogOutUseCase::new(shared(), flows.logout),
            issue_token: AppIssueTokenUseCase::new(shared()),
            issue_hop: AppIssueHopUseCase::new(shared()),
            show_page: PageUseCase::new(shared()),
            sso_start: AppSsoStartUseCase::new(shared(), sso.begin),
            sso_callback: AppSsoCallbackUseCase::new(shared(), sso.finish),
            passkey_begin: AppPasskeyBeginUseCase::new(shared(), passkeys.begin),
            passkey_confirm: AppPasskeyConfirmUseCase::new(shared(), passkeys.confirm),
            forgot_password: AppForgotPasswordUseCase::new(shared(), password_reset.request),
            reset_password: AppResetPasswordUseCase::new(shared(), password_reset.confirm),
            change_password: AppChangePasswordUseCase::new(shared(), flows.change_due_password),
        }
    }
}
/// Signing up on the app's own domain and confirming the address.
mod accounts;
/// Signing in on the app's own domain with a passkey.
mod passkeys;
/// Signing in on the app's own domain with a password.
mod password;
/// The internal relay the gateway calls: the signed command, its target and the page it answers with.
mod relay;
/// The session the app's domain holds: handed over, carried across hosts, ended.
mod sessions;
/// Signing in on the app's own domain through an identity provider.
mod sso;

pub use accounts::{
    AppConfirmByEmailRequest, AppConfirmByEmailUseCase, AppSignUpRequest, AppSignUpUseCase,
    AppVerifyEmailUseCase,
};
pub use passkeys::{
    AppPasskeyBeginFlows, AppPasskeyBeginUseCase, AppPasskeyConfirmRequest,
    AppPasskeyConfirmUseCase,
};
pub use password::{
    AppChangePasswordRequest, AppChangePasswordUseCase, AppCompleteMfaRequest,
    AppCompleteMfaUseCase, AppForgotPasswordUseCase, AppLogInRequest, AppLogInUseCase,
    AppResetPasswordRequest, AppResetPasswordUseCase,
};
pub use relay::{
    AppSignInPageRequest, PageUseCase, ReceivePorts, ReceiveRequest, ReceiveUseCase, Refusal,
    SignInNote, SignInPage, SsoChoice, TargetPorts,
};
pub use sessions::{
    AcrossHosts, AcrossHostsPorts, AppHandOverRequest, AppIssueHopRequest, AppIssueHopUseCase,
    AppIssueTokenRequest, AppIssueTokenUseCase, AppLogOutUseCase, HandOverAppSessionUseCase,
};
pub use sso::{
    AppSsoAnswer, AppSsoCallbackRequest, AppSsoCallbackUseCase, AppSsoFinishFlows,
    AppSsoStartRequest, AppSsoStartUseCase,
};
