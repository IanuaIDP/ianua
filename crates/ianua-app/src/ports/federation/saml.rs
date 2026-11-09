//! SAML as a service provider: the requests this platform sends to a
//! connection's identity provider and keeps until they are answered, the
//! answers it checks, the metadata it publishes and imports, and the key
//! assertions are sealed to.

use async_trait::async_trait;
use ianua_domain::domains::federation::connection::{
    AssertionDecryption, IdpMetadataFacts, SamlConfig,
};
use ianua_domain::domains::federation::saml::assertion::SamlAssertion;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CertificatePem, ConnectionId, HttpsUrl, PublicHttpsUrl, SamlAssertionId, SamlEntityId,
    SamlNameIdFormat, SamlRequestId, TokenHash,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::authentication::{SealOwner, SealedField, SealedFor};
use crate::ports::crypto::XmlSigningKey;
use crate::tenancy::ScopedTenant;

/// Who the platform is, to the identity provider that issued an assertion.
///
/// An assertion names its audience and its destination. Without both, a
/// response minted for some *other* relying party, or posted to a different
/// endpoint than the one it was bound to, passes signature verification and
/// is accepted, because a valid signature only says the IdP wrote it, not
/// that it wrote it for us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceProvider {
    /// The entity id the IdP must name in `<Audience>`: the relying party,
    /// which is this platform, not the IdP's own id.
    pub entity_id: SamlEntityId,
    /// The assertion consumer URL the IdP must name in `Destination`, and
    /// where this response actually arrived.
    pub acs_url: HttpsUrl,
}

/// The connection a SAML answer arrives through: whose it is, and its id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamlConnection {
    /// The tenant or organization the connection belongs to.
    pub owner: SealOwner,
    /// The connection.
    pub id: ConnectionId,
}

impl SamlConnection {
    /// Where the connection keeps the sealed private key its provider
    /// encrypts assertions to.
    #[must_use]
    pub fn decryption_key_place(&self) -> SealedFor {
        SealedFor::new(self.owner, SealedField::FederationDecryptionKey, self.id)
    }
}

/// An identity provider's answer to a sign-in request this platform sent.
pub struct SamlAnswer<'a> {
    /// The base64 `SAMLResponse`.
    pub response: &'a str,
    /// The ID of the request it must answer. A response answering any other
    /// request, or none, is refused.
    pub in_response_to: &'a SamlRequestId,
}

/// Dyn-safe port for validating SAML responses.
///
/// The infrastructure layer handles XML parsing, decryption with the
/// connection's own key when the assertion came sealed, signature
/// verification against every certificate the connection takes, certificate
/// validation, and claim extraction. This port returns a domain-level
/// `SamlAssertion` or an error.
#[async_trait]
pub trait SamlValidator: Send + Sync {
    /// Validates a SAML answer against the connection's config and the
    /// relying party it must have been issued for.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the response is malformed,
    /// the signature is invalid, the assertion is expired, the
    /// audience, destination or issuer doesn't match, or it answers another
    /// request.
    async fn validate(
        &self,
        answer: &SamlAnswer<'_>,
        config: &SamlConfig,
        connection: &SamlConnection,
        service_provider: &ServiceProvider,
    ) -> Result<SamlAssertion, DomainError>;
}

/// A SAML sign-in request on its way to the identity provider.
pub struct SamlRedirect {
    /// The IdP address to send the browser to, carrying the request.
    pub url: HttpsUrl,
    /// The request's ID; the answer must name it in `InResponseTo`, and the
    /// IdP posts it back as `RelayState`.
    pub request_id: SamlRequestId,
}

/// Whether a sign-in request goes out signed, and with which key.
#[derive(Clone, Copy)]
pub enum RequestSigningKey<'a> {
    /// The request goes unsigned.
    Unsigned,
    /// The request is signed with the tenant's signing key.
    SignedWith(XmlSigningKey<'a>),
}

/// The certificate the metadata names for the requests this platform
/// signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSigningCertificate {
    /// Requests go unsigned, and the metadata says so.
    Unsigned,
    /// Requests are signed by the key in this certificate.
    SignedBy(CertificatePem),
}

/// What the metadata of one connection's service provider says beyond who
/// it is: the `NameID` asked for, how its requests are signed, the key
/// assertions are sealed to, and where logouts go.
pub struct SpMetadataTerms<'a> {
    /// The `NameID` format asked for.
    pub name_id_format: &'a SamlNameIdFormat,
    /// Whether requests are signed, and the certificate of the key that
    /// signs them.
    pub request_signing: RequestSigningCertificate,
    /// Whether the provider must seal its assertions, and to which
    /// certificate.
    pub decryption: &'a AssertionDecryption,
    /// Where the provider sends logout requests and answers.
    pub slo_url: &'a HttpsUrl,
}

/// Dyn-safe port for the SAML messages this platform sends as a service
/// provider.
pub trait SamlServiceProviderMessages: Send + Sync {
    /// Builds a sign-in request for `config`'s IdP, asking it to answer
    /// `service_provider`, signed with `key` when it says so.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the request cannot be
    /// encoded or signed.
    fn sign_in_request(
        &self,
        config: &SamlConfig,
        service_provider: &ServiceProvider,
        key: RequestSigningKey<'_>,
    ) -> Result<SamlRedirect, DomainError>;

    /// The metadata document an IdP imports to trust `service_provider`.
    fn metadata(&self, service_provider: &ServiceProvider, terms: &SpMetadataTerms<'_>) -> String;
}

/// A SAML sign-in request awaiting its answer.
#[derive(Debug, Clone)]
pub struct SamlLoginRequest {
    /// The connection the request went out on.
    pub connection_id: ConnectionId,
    /// Hash of the secret held by the browser that started the sign-in.
    pub binding_hash: TokenHash,
    /// Hash of the value the dashboard that started the sign-in keeps, which
    /// the one-time code is bound to.
    pub dashboard_hash: TokenHash,
}

/// Dyn-safe port for SAML sign-in requests in flight.
///
/// Keyed by request ID. Taking a request removes it, so an answer is used
/// once, and only an answer to a request sent here is accepted.
#[async_trait]
pub trait SamlRequestStore: Send + Sync + TenantScoped {
    /// Remembers a request sent under `request_id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request_id: &SamlRequestId,
        request: &SamlLoginRequest,
    ) -> Result<(), DomainError>;

    /// Atomically fetches and removes the request. `None` if it was never
    /// sent, was already answered, or has lapsed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        request_id: &SamlRequestId,
    ) -> Result<Option<SamlLoginRequest>, DomainError>;
}

/// Dyn-safe port recording which assertions have been spent.
///
/// A SAML assertion is a bearer credential that stays valid for its whole
/// window, so replay is only prevented by remembering the ones already
/// answered.
#[async_trait]
pub trait SamlAssertionLedger: Send + Sync + TenantScoped {
    /// Records `assertion_id` as spent, returning whether this call was the
    /// one that spent it.
    ///
    /// `false` means it had already been used and the caller must refuse.
    /// Atomic: two nodes racing the same replay cannot both see `true`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, which
    /// the caller must treat as a refusal, not a pass.
    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        assertion_id: &SamlAssertionId,
        expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError>;
}

/// Where an identity provider's metadata is read from.
pub enum MetadataSource {
    /// Fetched from the provider's metadata address.
    Url(PublicHttpsUrl),
    /// The document itself, as an admin pasted or uploaded it.
    Document(String),
}

/// Dyn-safe port for reading an identity provider's SAML metadata.
#[async_trait]
pub trait SamlMetadataReader: Send + Sync {
    /// The metadata document served at `url`.
    ///
    /// The adapter resolves the host again and refuses an internal,
    /// loopback or link-local address before connecting, follows no
    /// redirect to such an address, caps the document's size, and gives up
    /// after a short timeout, so an admin cannot point the server at the
    /// tenant's neighbours or hold a request open.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation`, with a message fit to show the
    /// administrator, if the address is refused, the fetch fails or times
    /// out, or the document is too large.
    async fn fetch(&self, url: &PublicHttpsUrl) -> Result<String, DomainError>;

    /// What the metadata `document` says about its provider: its entity
    /// id, sign-in and logout endpoints, and signing certificates, current
    /// first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the document is not SAML
    /// metadata for an identity provider, or names an endpoint that is not
    /// HTTPS.
    fn read(&self, document: &str) -> Result<IdpMetadataFacts, DomainError>;
}

/// A key pair the platform made for assertions sealed to it. Holds the
/// private key, so it has no `Debug`.
pub struct GeneratedSpKey {
    /// The certificate published for the provider to encrypt to.
    pub certificate: CertificatePem,
    /// The private key, to seal before it is stored.
    pub private_key: Secret,
}

/// Dyn-safe port for the keys a provider's assertions are sealed to.
#[async_trait]
pub trait SamlEncryptionKeys: Send + Sync {
    /// A new key pair, its certificate issued in the name of `subject`, this
    /// platform as the connection's service provider.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the key cannot be made.
    async fn generate(&self, subject: &SamlEntityId) -> Result<GeneratedSpKey, DomainError>;

    /// Refuses a pair whose private key is not the one `certificate`
    /// carries the public half of, or that cannot decrypt.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the key does not match the
    /// certificate or cannot be read.
    fn ensure_pair(
        &self,
        certificate: &CertificatePem,
        private_key: &Secret,
    ) -> Result<(), DomainError>;
}
