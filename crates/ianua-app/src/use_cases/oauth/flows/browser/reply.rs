//! Where and how the answer to an authorization request goes back to its
//! client: the redirect, the response mode, and the `state` handed back as
//! it came. For a pushed request only the server knows them, so the
//! screening and the consent step both say them.

use ianua_domain::domains::oauth::grants::authorization_request::ResponseMode;
use ianua_domain::domains::oauth::grants::pushed_request::{PushedParameters, StateSent};
use ianua_domain::types::RedirectUri;

/// Where and how a client is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The redirect, one the client registered.
    pub redirect_uri: RedirectUri,
    /// How the answer is sent there.
    pub response_mode: ResponseMode,
    /// The client's `state`, handed back as it came.
    pub state: StateSent,
}

impl Reply {
    /// How the request `parameters` describe is answered.
    #[must_use]
    pub fn to(parameters: &PushedParameters) -> Self {
        Self {
            redirect_uri: parameters.redirect_uri.clone(),
            response_mode: parameters.asked.response_mode,
            state: parameters.state.clone(),
        }
    }
}
