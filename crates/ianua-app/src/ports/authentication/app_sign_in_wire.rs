//! What the gateway and the API say to each other about an app sign-in.
//!
//! The gateway answers an app's sign-in addresses and passes each request on
//! as a [`WireRequest`], sealed with a key only the two of them derive. The
//! API answers with a [`WireOutcome`]: values, never headers. Which cookies
//! the browser gets, and with which attributes, is the gateway's to decide.

use ianua_domain::domains::routing::sign_in::app::SignInAction;
use ianua_domain::types::{
    CeremonyId, ConnectionId, DenialStatus, DomainName, Nonce, ServiceId, TenantId,
};
use serde::{Deserialize, Serialize};

/// The protocol version this build speaks.
pub const WIRE_VERSION: u8 = 1;

/// The header carrying a request's seal.
pub const SEAL_HEADER: &str = "x-ianua-seal";

/// The path on the API's internal listener requests are relayed to.
pub const RELAY_PATH: &str = "/internal/app-sign-in";

/// How far a request's timestamp may be from the receiver's clock, in seconds.
pub(crate) const MAX_SKEW_SECS: i64 = 30;

/// An app sign-in request as the gateway sends it.
#[derive(Serialize, Deserialize)]
pub struct WireRequest {
    /// The protocol version.
    pub v: u8,
    /// Where the request came from.
    pub ctx: WireContext,
    /// What was asked.
    pub command: WireCommand,
}

/// Where a request came from, as the gateway saw it.
#[derive(Serialize, Deserialize)]
pub struct WireContext {
    /// The tenant the host belongs to.
    pub tenant_id: TenantId,
    /// The service whose sign-in addresses were used.
    pub service_id: ServiceId,
    /// The host the request was sent to.
    pub host: DomainName,
    /// The client's address, as the gateway established it. Read on the API
    /// side, where one that does not parse is dropped.
    pub client_ip: Option<String>,
    /// The client's user agent, as the client sent it. Read on the API side,
    /// where one that does not parse is dropped.
    pub user_agent: Option<String>,
    /// The client's `Accept-Language`, as the client sent it, so a page is
    /// drawn in a language the person reads.
    #[serde(default)]
    pub accept_language: Option<String>,
    /// When the gateway sent it, in Unix seconds.
    pub ts: i64,
    /// A value used once, so a captured request cannot be sent again.
    pub nonce: Nonce,
}

/// What a person asked for. Holds credentials, so it has no `Debug`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum WireCommand {
    /// Sign in with a password.
    LogIn {
        /// The account's address.
        email: String,
        /// The secret supplied to prove control of the account.
        password: String,
        /// The device cookie's secret, when the browser holds one on this
        /// host.
        #[serde(default)]
        device: Option<String>,
        /// Where to send them afterwards.
        return_to: Option<String>,
    },
    /// Finish signing in with a second factor.
    CompleteMfa {
        /// The challenge cookie's token.
        challenge: String,
        /// The authenticator's code.
        code: String,
        /// When the person asked to remember this device: a fresh secret
        /// the gateway made for the host's device cookie.
        #[serde(default)]
        remember_device: Option<String>,
        /// Where to send them afterwards.
        return_to: Option<String>,
    },
    /// Finish signing in from the link mailed to the person, in the browser
    /// whose challenge cookie holds the sign-in.
    ConfirmByEmail {
        /// The challenge cookie's token.
        challenge: String,
        /// The token from the mailed link.
        link: String,
        /// Where to send them afterwards.
        return_to: Option<String>,
    },
    /// Create an account.
    SignUp {
        /// The address it signs in with.
        email: String,
        /// The name shown for it.
        display_name: String,
        /// The password chosen.
        password: String,
    },
    /// Confirm an address.
    Verify {
        /// The token from the mailed link.
        token: String,
    },
    /// End the session the cookie holds.
    LogOut {
        /// The session cookie's token, if one was sent.
        session: Option<String>,
    },
    /// Fetch a short-lived token for a service accepting the sign-in by
    /// token.
    IssueToken {
        /// The session cookie's token, if one was sent.
        session: Option<String>,
        /// The audience of the service the token is for.
        audience: String,
    },
    /// Set the session a hop carries on the host it arrived at.
    Hop {
        /// The one-time code the browser carried.
        code: String,
        /// The digest of the value the arriving browser keeps in its hop
        /// cookie on this host.
        browser: String,
    },
    /// Hand out a code carrying the session to a host of a service that
    /// accepts the sign-in with a cookie of its own, for the browser that
    /// asked from there.
    IssueHop {
        /// The session cookie's token on the owner's host, if one was sent.
        session: Option<String>,
        /// The host the code is for.
        host: DomainName,
        /// The digest of the value the asking browser keeps in its hop
        /// cookie on that host.
        browser: String,
    },
    /// Show the page a person fills in.
    ShowPage {
        /// The sign-in form or confirmation screen to render.
        page: WirePage,
        /// The note the page's address asked for, as a code.
        note: Option<String>,
        /// Where to send the person once they are in.
        return_to: Option<String>,
        /// The token of the mailed link the page was opened from, carried in
        /// its form. Only the reset and change pages take one.
        #[serde(default)]
        token: Option<String>,
    },
    /// Start signing in through one of the tenant's outside identity
    /// providers.
    Sso {
        /// The connection the person picked.
        connection_id: ConnectionId,
        /// Where to send them once they are in.
        return_to: Option<String>,
    },
    /// The outside identity provider sent the browser back.
    SsoCallback {
        /// What the provider answered with.
        answer: WireSsoAnswer,
        /// The secret the browser kept since the sign-in started.
        binding: String,
        /// The second secret the browser kept, which the session is handed
        /// back against.
        hand_back: String,
        /// Where to send them once they are in, as kept since the start.
        return_to: Option<String>,
    },
    /// Ask for a passkey challenge.
    PasskeyBegin {
        /// The address typed, if any. Without one the browser offers
        /// whichever passkey it holds for the site.
        email: Option<String>,
    },
    /// Answer a passkey challenge.
    PasskeyConfirm {
        /// The ceremony the challenge came from.
        ceremony_id: CeremonyId,
        /// The passkey that signed the answer.
        credential_id: Vec<u8>,
        /// The authenticator's signed answer.
        response: Vec<u8>,
        /// Where to send them once they are in.
        return_to: Option<String>,
    },
    /// Ask for a link to set a new password.
    ForgotPassword {
        /// The address typed.
        email: String,
    },
    /// Set a new password from the mailed link.
    ResetPassword {
        /// The token from the mailed link.
        token: String,
        /// The password chosen.
        password: String,
        /// A code from the account's second factor, when it has one.
        mfa_code: Option<String>,
    },
    /// Set the new password a sign-in owes, in the browser whose challenge
    /// cookie holds it, and finish that sign-in.
    ChangePassword {
        /// The change's token: the challenge cookie's, or the mailed link's.
        challenge: String,
        /// The new password.
        password: String,
        /// A code from the person's own second factor, when the change asks
        /// for one.
        mfa_code: Option<String>,
        /// The device cookie's secret, when the browser holds one on this
        /// host.
        #[serde(default)]
        device: Option<String>,
        /// Where to send them afterwards.
        return_to: Option<String>,
    },
}

/// What an outside identity provider sends the browser back with. Holds
/// credentials, so it has no `Debug`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum WireSsoAnswer {
    /// An OIDC redirect.
    Oidc {
        /// The `state` parameter.
        state: String,
        /// The authorization code.
        code: String,
    },
    /// A SAML response, posted.
    Saml {
        /// The `RelayState`.
        relay_state: String,
        /// The base64 `SAMLResponse`.
        saml_response: String,
    },
}

/// A host to hop through. The code that sets the session there is asked for
/// once the browser is on its way, bound to that browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireHop {
    /// Where the browser must establish the next session cookie.
    pub host: DomainName,
}

/// A page the gateway shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WirePage {
    /// Logging in.
    LogIn,
    /// Signing up.
    SignUp,
    /// The second factor.
    Mfa,
    /// Asking for a link to set a new password.
    ForgotPassword,
    /// Setting a new password from the mailed link.
    ResetPassword,
    /// Setting the new password a sign-in owes.
    ChangePassword,
}

impl From<WirePage> for SignInAction {
    fn from(page: WirePage) -> Self {
        match page {
            WirePage::LogIn => Self::LogIn,
            WirePage::SignUp => Self::SignUp,
            WirePage::Mfa => Self::Mfa,
            WirePage::ForgotPassword => Self::ForgotPassword,
            WirePage::ResetPassword => Self::ResetPassword,
            WirePage::ChangePassword => Self::ChangePassword,
        }
    }
}

/// What came of a request, as the API answers it.
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum WireOutcome {
    /// Authentication succeeded; the browser can install the session cookie.
    SignedIn {
        /// The session token for the host's cookie.
        token: String,
        /// When it lapses, in Unix seconds.
        expires_at: i64,
        /// The path to send the browser to.
        return_to: String,
        /// Hosts of services accepting the sign-in with a cookie of their
        /// own, for the browser to pass through.
        #[serde(default)]
        hops: Vec<WireHop>,
        /// The secret of the device the sign-in just remembered, for the
        /// host's device cookie; none when it remembered none.
        #[serde(default)]
        remembered_device: Option<String>,
    },
    /// A code for a hop, bound to the browser that asked for it.
    HopIssued {
        /// The host the code sets the session on.
        host: DomainName,
        /// The one-time code.
        code: String,
    },
    /// A hop arrived; the session token for this host's cookie.
    HandedOver {
        /// The session token.
        token: String,
        /// When it lapses, in Unix seconds.
        expires_at: i64,
    },
    /// A short-lived bearer token.
    Token {
        /// The bearer value presented to authorize subsequent requests.
        access_token: String,
        /// When it lapses, in Unix seconds.
        expires_at: i64,
    },
    /// A second factor is owed.
    MfaRequired {
        /// The token for the host's challenge cookie.
        challenge: String,
        /// When it lapses, in Unix seconds.
        expires_at: i64,
    },
    /// The sign-in waits for the person to confirm it from the link mailed
    /// to them.
    ConfirmByEmail {
        /// The token for the host's challenge cookie.
        challenge: String,
        /// When it lapses, in Unix seconds.
        expires_at: i64,
    },
    /// The password was right, but an admin set it or it expired: a new one
    /// is owed before the sign-in finishes. Nothing is mailed.
    PasswordChangeRequired {
        /// The token for the host's challenge cookie, sent back with the new
        /// password; none when it was mailed to the person instead.
        challenge: Option<String>,
        /// What the change asks besides the new password: `none`,
        /// `own_factor` (a code sent as `mfa_code`) or `mailed_link`.
        proof: String,
        /// Why: `set_by_admin` or `expired`.
        reason: String,
        /// When it lapses, in Unix seconds.
        expires_at: i64,
    },
    /// Send the browser to the outside identity provider. The gateway keeps
    /// the two secrets and the return path in a cookie on this host until
    /// the browser comes back.
    SsoRedirect {
        /// The provider's address.
        url: String,
        /// The secret the browser keeps for the way back.
        binding: String,
        /// The second secret the session is handed back against.
        hand_back: String,
        /// Where to send the person once they are in.
        return_to: Option<String>,
    },
    /// A passkey challenge for the browser to answer.
    PasskeyChallenge {
        /// The ceremony the server keeps for it, returned with the answer.
        ceremony_id: CeremonyId,
        /// The `WebAuthn` options for `navigator.credentials.get()`.
        options: Vec<u8>,
    },
    /// The session is over.
    SignedOut,
    /// Done.
    Accepted,
    /// A page to show, drawn by the API.
    Page {
        /// The page's HTML.
        html: String,
    },
    /// Refused, with the status to answer and a stable reason.
    Rejected {
        /// The HTTP status the gateway answers with, always an error status.
        status: DenialStatus,
        /// A machine-readable reason, safe to show.
        code: String,
    },
}
