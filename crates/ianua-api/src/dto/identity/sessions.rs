//! A user's sessions and sign-in history: listing them, ending one, and
//! signing out everywhere else.

use ianua_app::context::{CallerContext, Credential};
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::SessionId;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// One session a user holds.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SessionResponse {
    /// The session's id, to end it by.
    pub id: Uuid,
    /// `active`, or `suspended` until its holder proves themselves again.
    pub status: &'static str,
    /// How it signed in: `password`, `magic_link`, `passkey`, `saml` or
    /// `oidc`.
    pub auth_method: &'static str,
    /// Whether it gave a second factor.
    pub mfa_satisfied: bool,
    /// The address it signed in from, when it could be told.
    pub ip_address: Option<String>,
    /// The browser or client it signed in with, as it described itself.
    pub user_agent: Option<String>,
    /// When it signed in.
    #[serde(with = "time::serde::rfc3339")]
    pub signed_in_at: OffsetDateTime,
    /// When it was last used.
    #[serde(with = "time::serde::rfc3339")]
    pub last_active_at: OffsetDateTime,
    /// When it ends at the latest.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Whether it is the session this request came with.
    pub current: bool,
}

impl SessionResponse {
    /// Each of `sessions`, marking the one `caller` came with.
    #[must_use]
    pub(crate) fn listing(
        sessions: &[Session<ResolvedTenant>],
        caller: &CallerContext,
    ) -> Vec<Self> {
        let current = own_session(caller);
        sessions
            .iter()
            .map(|session| Self::of(session, current))
            .collect()
    }

    /// `session`, marked current when it is `current`.
    fn of(session: &Session<ResolvedTenant>, current: Option<SessionId>) -> Self {
        Self {
            id: *session.id().as_uuid(),
            status: status_name(session.status()),
            auth_method: session.auth_method().as_str(),
            mfa_satisfied: session.mfa_satisfied(),
            ip_address: session
                .ip_address()
                .known()
                .map(|ip| ip.as_str().to_owned()),
            user_agent: session
                .user_agent()
                .known()
                .map(|agent| agent.as_str().to_owned()),
            signed_in_at: session.signed_in_at(),
            last_active_at: session.last_active_at(),
            expires_at: session.expires_at(),
            current: current == Some(*session.id()),
        }
    }
}

/// The session `caller` signed in with, when they came with one.
fn own_session(caller: &CallerContext) -> Option<SessionId> {
    match caller.credential() {
        Credential::TenantSession(session) => Some(*session),
        _ => None,
    }
}

/// How a session's status reads on the wire.
fn status_name(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Active => "active",
        SessionStatus::Suspended => "suspended",
        SessionStatus::Revoked => "revoked",
    }
}

/// How many other sessions signing out everywhere else ended.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SignedOutResponse {
    /// The sessions ended; the one the request came with stays.
    pub signed_out: u64,
}

impl From<u64> for SignedOutResponse {
    fn from(signed_out: u64) -> Self {
        Self { signed_out }
    }
}
