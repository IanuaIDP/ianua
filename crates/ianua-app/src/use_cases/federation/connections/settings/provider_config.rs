//! How a connection reaches its provider, as the administrator gives it.
//!
//! It differs from the stored configuration in three places: an OIDC client
//! secret arrives in plain text, and is sealed before the connection keeps
//! it; a SAML provider may be given by its metadata, read before the
//! connection takes it; and the key a SAML provider seals its assertions to
//! is never given here, since a private key is made or uploaded through its
//! own use case and sealed there. Creating a connection and changing its
//! configuration both take this.

use ianua_domain::domains::federation::connection::{
    AssertionDecryption, AuthnRequestSigning, IdpCertificates, SamlConfig, ScopeToken,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{HttpsUrl, Label, SamlNameIdFormat, Setting};

use crate::ports::federation::MetadataSource;

/// How a connection reaches its provider, over SAML or OIDC.
pub enum ProviderConfig {
    /// SAML 2.0, each setting given by hand.
    Saml(Box<SamlProviderConfig>),
    /// SAML 2.0, its endpoints and certificates read from the provider's
    /// metadata. A new connection takes the persistent `NameID`, unsigned
    /// requests and readable assertions; a connection already kept keeps its
    /// own choices of those.
    SamlMetadata(MetadataSource),
    /// OpenID Connect, with the client secret as typed.
    Oidc(OidcProviderConfig),
}

/// A SAML provider as the administrator gives it by hand.
pub struct SamlProviderConfig {
    /// The provider's entity id.
    pub entity_id: HttpsUrl,
    /// Where sign-in requests go.
    pub sso_url: HttpsUrl,
    /// Where logout requests go, or unset to log nobody out at the
    /// provider.
    pub slo_url: Setting<HttpsUrl>,
    /// The certificates its answers may be signed with: the current one,
    /// and the next one while it rolls its key over.
    pub certificates: IdpCertificates,
    /// The `NameID` format it names people by.
    pub name_id_format: SamlNameIdFormat,
    /// Whether sign-in requests to it are signed.
    pub request_signing: AuthnRequestSigning,
}

impl SamlProviderConfig {
    /// The stored configuration these settings make, keeping `decryption`,
    /// the key assertions are sealed to as the connection holds it now.
    /// Settings typed by hand follow no metadata address.
    pub(crate) fn keeping(self, decryption: AssertionDecryption) -> SamlConfig {
        SamlConfig {
            entity_id: self.entity_id,
            sso_url: self.sso_url,
            slo_url: self.slo_url,
            certificates: self.certificates,
            name_id_format: self.name_id_format,
            request_signing: self.request_signing,
            assertion_decryption: decryption,
            metadata_url: Setting::Unset,
        }
    }
}

/// An OIDC provider as the administrator gives it. Holds the client secret
/// in plain text, so it has no `Debug`.
pub struct OidcProviderConfig {
    /// The issuer, whose discovery document names its endpoints.
    pub issuer: HttpsUrl,
    /// The client id this platform is registered under at the provider.
    pub client_id: Label,
    /// The client secret, as the provider issued it.
    pub client_secret: Secret,
    /// The scopes to ask for.
    pub scopes: Vec<ScopeToken>,
}
