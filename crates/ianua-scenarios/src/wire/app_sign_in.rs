//! Signing people in on an app's own host: the service's setting, as the
//! API takes it, and what the gateway's sign-in addresses take and answer.

use serde::{Deserialize, Serialize};

/// Where a service's sign-in addresses answer, and what a signed-out
/// browser gets.
#[derive(Debug, Clone, Serialize)]
pub struct AppSignInSettings {
    /// The service's hosts to answer on: verified domains of the tenant.
    pub hosts: Vec<String>,
    /// `refuse` (a `Status::UNAUTHORIZED`) or `redirect` (to the sign-in address).
    pub signed_out_browsers: String,
}

/// How a service accepting another's sign-in is reached.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Delivery {
    /// On the same host, by the same cookie.
    SameHost,
    /// By short-lived tokens for its own audience.
    Tokens,
}

/// `PUT …/services/{id}/app-sign-in`: a service's own sign-in, or whose it
/// accepts.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigureAppSignIn {
    /// Its own sign-in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_sign_in: Option<AppSignInSettings>,
    /// The service whose sign-in it accepts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepts_app_sign_in_of: Option<String>,
    /// How it is reached when it accepts one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Delivery>,
}

/// `POST <prefix>/login` on an app's host, sent as JSON. `Debug` shows no
/// password.
#[derive(Clone, Serialize)]
pub struct AppLogIn {
    /// The person's address.
    pub email: String,
    /// Secret checked against the tenant account before opening a session.
    pub password: String,
}

impl std::fmt::Debug for AppLogIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppLogIn")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// `POST <prefix>/mfa` on an app's host: the code the person's
/// authenticator shows, finishing a sign-in that owes it. Holds the code,
/// so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct AppFactorCode {
    /// Authenticator proof completing the pending sign-in.
    pub code: String,
}

/// What a sign-in on an app's host answered.
#[derive(Debug, Clone, Deserialize)]
pub struct AppSignedIn {
    /// Whether the person is signed in now.
    #[serde(default)]
    pub signed_in: bool,
    /// Whether a second factor is owed first.
    #[serde(default)]
    pub mfa_required: bool,
}

/// `POST <prefix>/token` on an app's host.
#[derive(Debug, Clone, Serialize)]
pub struct TokenFor {
    /// The audience of the service the token is for.
    pub audience: String,
}

/// A short-lived token for one service. `Debug` shows no token.
#[derive(Clone, Deserialize)]
pub struct AppToken {
    /// The token, sent as `Authorization: Bearer`.
    pub access_token: String,
    /// How long it lasts, in seconds.
    pub expires_in: u64,
}

impl std::fmt::Debug for AppToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppToken")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}
