//! Which apps hear of a sign-out over the back channel, and the logout
//! tokens each is sent: one per app, or one per session for an app that
//! wants each session named.

use std::collections::HashSet;

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::clients::settings::{ChannelLogout, SessionRequired};
use ianua_domain::domains::oauth::grants::logout_notice::SignedOut;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{HttpsUrl, OAuthClientId, SessionId};

use crate::ports::oauth::ConsentedSession;

/// One logout token to send: to whom, where, and who signed out.
pub(super) struct Notice {
    /// The app.
    pub(super) client: OAuthClient<ResolvedTenant>,
    /// Its back-channel address.
    pub(super) uri: HttpsUrl,
    /// Who the token says signed out.
    pub(super) signed_out: SignedOut,
}

/// Each client in `signed_into`, once.
pub(super) fn distinct_clients(signed_into: &[ConsentedSession]) -> Vec<OAuthClientId> {
    let mut seen = HashSet::new();
    signed_into
        .iter()
        .map(|pair| pair.client)
        .filter(|id| seen.insert(*id))
        .collect()
}

/// The tokens `client` is sent for `signed_out`, given the sessions the
/// person signed in to it through. None for an app with no back channel,
/// or one the ended session never reached.
pub(super) fn notices_for(
    client: &OAuthClient<ResolvedTenant>,
    signed_out: SignedOut,
    signed_into: &[ConsentedSession],
) -> Vec<Notice> {
    let ChannelLogout::At { uri, session } = client.settings().logout.back_channel.clone() else {
        return Vec::new();
    };
    let sessions = sessions_of(*client.id(), signed_out, signed_into);
    let told: Vec<SignedOut> = match (signed_out, session) {
        (SignedOut::Everywhere { person }, SessionRequired::Required) => sessions
            .into_iter()
            .map(|session| SignedOut::Session { person, session })
            .collect(),
        (SignedOut::Everywhere { .. }, SessionRequired::NotRequired) => vec![signed_out],
        (SignedOut::Session { .. }, _) if sessions.is_empty() => Vec::new(),
        (SignedOut::Session { .. }, _) => vec![signed_out],
    };
    told.into_iter()
        .map(|signed_out| Notice {
            client: client.clone(),
            uri: uri.clone(),
            signed_out,
        })
        .collect()
}

/// The sessions through which the person signed in to `client` that
/// `signed_out` ends.
fn sessions_of(
    client: OAuthClientId,
    signed_out: SignedOut,
    signed_into: &[ConsentedSession],
) -> Vec<SessionId> {
    signed_into
        .iter()
        .filter(|pair| pair.client == client)
        .filter(|pair| match signed_out {
            SignedOut::Session { session, .. } => pair.session == session,
            SignedOut::Everywhere { .. } => true,
        })
        .map(|pair| pair.session)
        .collect()
}
