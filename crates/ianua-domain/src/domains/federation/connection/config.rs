//! How a connection reaches its provider, over SAML or OIDC.

use crate::domains::authentication::sessions::sign_in_progress::FederatedMethod;
use crate::domains::federation::connection::saml_keys::{
    AssertionDecryption, AuthnRequestSigning, IdpCertificates,
};
use crate::domains::federation::scope_token::ScopeToken;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{HttpsUrl, Label, PublicHttpsUrl, SamlNameIdFormat, SealedSecret, Setting};

/// The federation protocol used by a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FederationProtocol {
    /// Security Assertion Markup Language 2.0.
    Saml,

    /// `OpenID` Connect 1.0.
    Oidc,
}

impl From<FederationProtocol> for FederatedMethod {
    fn from(protocol: FederationProtocol) -> Self {
        match protocol {
            FederationProtocol::Saml => Self::Saml,
            FederationProtocol::Oidc => Self::Oidc,
        }
    }
}

impl FederationProtocol {
    /// The stable name the audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Saml => "saml",
            Self::Oidc => "oidc",
        }
    }
}

/// SAML-specific configuration for a federated connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlConfig {
    /// The external `IdP`'s entity ID (a URL identifying the `IdP`).
    pub entity_id: HttpsUrl,

    /// The SSO endpoint URL where login requests are sent.
    pub sso_url: HttpsUrl,

    /// The provider's single logout endpoint, where logout requests and
    /// answers to its own go. Unset, single logout with it is off.
    pub slo_url: Setting<HttpsUrl>,

    /// The certificates the provider's answers may be signed with: the
    /// current one, and the next one while it rolls its key over.
    pub certificates: IdpCertificates,

    /// The expected `NameID` format. A sign-in connection takes only
    /// `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`: accounts are
    /// linked to the `NameID`, so it must name one person for good.
    pub name_id_format: SamlNameIdFormat,

    /// Whether the sign-in requests sent to the provider are signed.
    pub request_signing: AuthnRequestSigning,

    /// Whether the provider's assertions must come encrypted, and to which
    /// key of this platform's.
    pub assertion_decryption: AssertionDecryption,

    /// The address the provider publishes its metadata at, when the
    /// connection was made or last updated from it. The platform reads it
    /// again from there on a schedule, so a certificate the provider rolls
    /// over is taken without an admin. Unset for a connection typed in by
    /// hand or made from a pasted document.
    pub metadata_url: Setting<PublicHttpsUrl>,
}

/// OIDC-specific configuration for a federated connection.
///
/// The provider's endpoints are not part of it: they are read from the
/// issuer's discovery document (`/.well-known/openid-configuration`), so they
/// stay right when the provider moves them.
///
/// `Debug` leaves the client secret out: it is the credential this platform
/// authenticates to the customer's identity provider with.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OidcConfig {
    /// The OIDC issuer URL (e.g. `"https://accounts.google.com"`).
    pub issuer: HttpsUrl,

    /// The `OAuth2` client ID registered with the external `IdP`.
    /// Its format differs from one provider to the next.
    pub client_id: Label,

    /// The client secret, sealed by the platform before it is stored.
    pub encrypted_client_secret: SealedSecret,

    /// Scopes to request (e.g. `["openid", "email", "profile"]`).
    pub scopes: Vec<ScopeToken>,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("encrypted_client_secret", &"<redacted>")
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Protocol-specific configuration, one of SAML or OIDC.
///
/// Storage maps it through a record of its own: the SAML part holds
/// certificates and keys built through their checks, which a derived
/// deserializer would step around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionConfig {
    /// SAML 2.0 federation configuration.
    Saml(Box<SamlConfig>),

    /// OIDC 1.0 federation configuration.
    Oidc(OidcConfig),
}

/// Which provider a configuration signs people in through: its protocol
/// and the name the provider signs its answers with.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Provider<'a> {
    Saml(&'a HttpsUrl),
    Oidc(&'a HttpsUrl),
}

impl ConnectionConfig {
    /// Refuses a SAML configuration whose `NameID` does not name one person
    /// for good. Accounts are linked to the subject a provider names: with
    /// an email address as the subject, the next person given that address
    /// lands in the account of the one who left.
    pub(crate) fn ensure_stable_subject(&self) -> Result<(), DomainError> {
        let Self::Saml(saml) = self else {
            return Ok(());
        };
        if saml.name_id_format.names_one_person_for_good() {
            return Ok(());
        }
        Err(DomainError::invalid(message!(
            "federation-a-saml-sign-in-connection-needs",
            format!(
                "a SAML sign-in connection needs the NameID format {}, which never names another person",
                SamlNameIdFormat::PERSISTENT
            )
        )))
    }

    /// The provider this configuration signs people in through.
    pub(crate) fn provider(&self) -> Provider<'_> {
        match self {
            Self::Saml(saml) => Provider::Saml(&saml.entity_id),
            Self::Oidc(oidc) => Provider::Oidc(&oidc.issuer),
        }
    }

    /// Whether this configuration lets someone sign answers that `before`
    /// did not: a SAML certificate it takes and `before` did not. Whoever
    /// holds the key behind it can sign in every subject linked to the
    /// connection.
    ///
    /// Rolling over to a next certificate already taken brings nobody new.
    /// An OIDC connection checks answers against its issuer's published
    /// keys. The issuer never changes, so neither does this. Scopes, the
    /// client secret and the SSO URL say nothing about who signed an
    /// answer.
    pub(crate) fn brings_new_signer(&self, before: &Self) -> bool {
        let (Self::Saml(now), Self::Saml(was)) = (self, before) else {
            return false;
        };
        now.certificates.adds_beyond(&was.certificates)
    }

    /// The protocol this configuration speaks.
    #[must_use]
    pub fn protocol(&self) -> FederationProtocol {
        match self {
            Self::Saml(_) => FederationProtocol::Saml,
            Self::Oidc(_) => FederationProtocol::Oidc,
        }
    }
}
