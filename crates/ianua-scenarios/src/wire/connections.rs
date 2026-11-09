//! A tenant's connections to outside identity providers, as its
//! administrators keep them: which address is sent to which provider, the
//! provider's groups mapped to roles here, sealed assertions, and the
//! links of the tenant's users.

use serde::{Deserialize, Serialize};

/// `POST …/federation/discover`: the address a person typed on the sign-in
/// page.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoverRealm {
    /// The address.
    pub email: String,
}

/// Where an address signs in.
#[derive(Debug, Clone, Deserialize)]
pub struct HomeRealm {
    /// Whether it is sent to a provider instead of signing in here.
    pub routed: bool,
    /// The connection it is sent to, when routed.
    #[serde(default)]
    pub connection_id: Option<String>,
    /// The provider's name, when routed.
    #[serde(default)]
    pub provider_name: Option<String>,
    /// `Oidc` or `Saml`, when routed.
    #[serde(default)]
    pub protocol: Option<String>,
}

/// One connection, as read back.
#[derive(Debug, Clone, Deserialize)]
pub struct Connection {
    /// The id the connection's endpoints take in their path.
    pub id: String,
    /// `Active` or `Disabled`.
    pub status: String,
    /// The domain whose addresses are sent straight to this provider.
    #[serde(default)]
    pub domain_hint: Option<String>,
    /// Which of the provider's groups give which roles here, when on.
    #[serde(default)]
    pub group_mapping: Option<GroupMapping>,
    /// A SAML connection's settings.
    #[serde(default)]
    pub saml: Option<SamlSettings>,
}

/// A connection's SAML settings.
#[derive(Debug, Clone, Deserialize)]
pub struct SamlSettings {
    /// Whether answers must be sealed to the platform's key.
    pub requires_encrypted_assertions: bool,
    /// The certificate the provider seals to, when required.
    #[serde(default)]
    pub encryption_certificate: Option<String>,
}

/// `PUT …/federation/connections/{id}/group-mapping`: which of the
/// provider's groups give which roles here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMapping {
    /// The provider's claim that lists the groups.
    pub claim: String,
    /// One rule per provider group.
    pub rules: Vec<GroupRule>,
}

/// One rule of a mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRule {
    /// The group's name at the provider.
    pub provider_group: String,
    /// What it gives.
    pub grant: MappedGrant,
}

/// What a provider group gives.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappedGrant {
    /// A role here, by id.
    Role(String),
    /// A group here, by id.
    Group(String),
}

/// The key a SAML connection's assertions are sealed to, `{}` to have the
/// platform make one.
#[derive(Clone, Default, Serialize)]
pub struct EncryptionKey {
    /// The certificate brought.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// The key that goes with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("brought", &self.certificate.is_some())
            .finish_non_exhaustive()
    }
}

/// The certificate to give the provider.
#[derive(Debug, Clone, Deserialize)]
pub struct EncryptionCertificate {
    /// In PEM.
    pub certificate: String,
}
