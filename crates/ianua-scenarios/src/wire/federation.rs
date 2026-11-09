//! Browser bindings and protocol answers shared by independent sign-in providers.

use serde::{Deserialize, Serialize};

/// `POST /api/v1/login/sso`: a member starts signing in through their
/// organization's identity provider.
#[derive(Debug, Clone, Serialize)]
pub struct Begin {
    /// The organization's slug.
    pub organization: String,
}

/// The provider redirect and browser binding, both secret-bearing and not Debug.
#[derive(Deserialize)]
pub struct Begun {
    /// The authorization request, including its state and nonce.
    pub redirect_url: String,
    /// The secret bound to the returning browser.
    pub binding: String,
}

/// The provider's answer forwarded by the browser with its independent binding.
#[derive(Serialize)]
pub struct Callback {
    /// The returning browser's proof of the initiated flow.
    pub binding: String,
    /// The protocol-specific answer that the real adapter verifies.
    pub answer: ProviderAnswer,
}

/// Protocol proofs as the dashboard forwards them, with no Debug of secrets.
#[derive(Serialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum ProviderAnswer {
    /// A single-use authorization code and its matching state.
    Oidc {
        /// The state generated for this sign-in.
        state: String,
        /// The authorization code retained by the provider peer.
        code: String,
    },
    /// A signed SAML response bound to a specific sign-in request.
    Saml {
        /// The request answered by the provider.
        relay_state: String,
        /// The signed XML response encoded for transport.
        saml_response: String,
    },
}
