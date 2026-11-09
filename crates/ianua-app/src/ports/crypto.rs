//! Crypto-specific ports.

use async_trait::async_trait;
use ianua_domain::domains::crypto::algorithm_migration::AlgorithmMigration;
use ianua_domain::domains::crypto::assertion_key::{AssertionKeySet, AssertionSigningKey};
use ianua_domain::domains::crypto::jwk::JwkComponents;
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKeySet};
use ianua_domain::domains::crypto::verifying_key::VerifyingKey;
use ianua_domain::domains::proxy::assertion::{AssertedCaller, UpstreamAssertion};
use ianua_domain::domains::proxy::exchange::ExchangedToken;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, KeyId, PublicKeyPem, RevocationListPem, TenantId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting and retrieving signing key sets.
#[async_trait]
pub trait SigningKeyStore: Send + Sync + TenantScoped {
    /// Loads the tenant's signing key set.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<SigningKeySet<ResolvedTenant>>, DomainError>;

    /// Saves the tenant's signing key set.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        key_set: &SigningKeySet<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port reading only the public halves of a tenant's signing keys,
/// for the gateway, which verifies what the tenant signed and serves its
/// JWKS.
///
/// The private halves are out of its reach on purpose: the gateway's
/// database role cannot read them, so the adapter selects the public
/// columns alone, and a gateway that is broken into signs nothing in a
/// tenant's name.
#[async_trait]
pub trait VerifyingKeyStore: Send + Sync + TenantScoped {
    /// Every key of the tenant's set that is not revoked, newest first. A
    /// tenant with no key set has none. Which of them a verifier accepts
    /// now is [`VerifyingKey::is_in_jwks`]'s to say.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, or
    /// when a stored key is corrupt.
    async fn find(&self, tenant_id: &ScopedTenant) -> Result<Vec<VerifyingKey>, DomainError>;
}

/// Dyn-safe port for finding signing key sets across every tenant.
///
/// Not [`TenantScoped`]: the sweeps that revoke keys after their grace and
/// rotate them by age run with nobody asking, over every tenant's keys.
#[async_trait]
pub trait CrossTenantKeySets: Send + Sync {
    /// The tenants whose key set holds a key that is rotated out but not yet
    /// revoked.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn tenants_with_rotated_keys(&self) -> Result<Vec<TenantId>, DomainError>;

    /// The tenants whose key set holds an active key created before
    /// `cutoff`: the ones a scheduled rotation may be due for. The rotation
    /// checks each set again, so a tenant listed too eagerly is skipped.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn tenants_with_keys_made_before(
        &self,
        cutoff: OffsetDateTime,
    ) -> Result<Vec<TenantId>, DomainError>;
}

/// Dyn-safe port keeping a tenant's assertion keys: their public halves and
/// where each stands.
///
/// It never reads a private half back. A key found here holds none; a key
/// just made holds its own, which the store seals as it writes it. Only
/// [`AssertionSigningKeys`] opens one, for the gateway.
#[async_trait]
pub trait AssertionKeyStore: Send + Sync + TenantScoped {
    /// The tenant's assertion keys, or `None` when it has none yet.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, or
    /// when a stored key is corrupt.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AssertionKeySet<ResolvedTenant>>, DomainError>;

    /// Keeps the tenant's assertion keys: a key just made is written with
    /// its private half sealed, a known one takes its new standing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, or
    /// when a new key holds no private half to write.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        keys: &AssertionKeySet<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port reading the key that signs a tenant's assertions now, its
/// private half opened. The gateway alone reads it: it is the one that
/// signs `X-Ianua-Assertion`.
#[async_trait]
pub trait AssertionSigningKeys: Send + Sync + TenantScoped {
    /// The key that signs the tenant's assertions now, or `None` when
    /// nothing of its set signs or it has no set.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, when a
    /// stored key is corrupt, or when its private half does not open.
    async fn signing(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AssertionSigningKey>, DomainError>;
}

/// Dyn-safe port finding the tenants whose assertion keys a sweep has work
/// for.
///
/// Not [`TenantScoped`]: the sweeps that rotate assertion keys and retire
/// them run with nobody asking, over every tenant's keys.
#[async_trait]
pub trait CrossTenantAssertionKeys: Send + Sync {
    /// The tenants holding an assertion key rotated out but not yet
    /// retired.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn tenants_with_rotated_keys(&self) -> Result<Vec<TenantId>, DomainError>;

    /// The tenants due a new assertion key: those holding keys but none
    /// active made at or after `cutoff`, whose signing key is old or where
    /// nothing signs, and the active tenants holding none at all, made
    /// before their setup made one. The rotation checks each set again, so
    /// a tenant listed too eagerly is skipped.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn tenants_due(&self, cutoff: OffsetDateTime) -> Result<Vec<TenantId>, DomainError>;
}

/// Dyn-safe port signing what the gateway hands an upstream with the
/// tenant's assertion key: the identity assertion, as a JWT typed
/// `ianua-assertion+jwt`, and the narrowed token a TokenExchange stage
/// mints, typed `ianua-exchanged+jwt`. No check of access tokens takes
/// either, and neither check takes the other or an access token.
#[async_trait]
pub trait AssertionSigner: Send + Sync {
    /// `assertion` signed with `key`, in compact form.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the key does not read or
    /// the signing fails.
    async fn sign(
        &self,
        assertion: &UpstreamAssertion,
        key: &AssertionSigningKey,
    ) -> Result<Secret, DomainError>;

    /// `token` signed with `key`, in compact form.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the key does not read or
    /// the signing fails.
    async fn sign_exchanged(
        &self,
        token: &ExchangedToken,
        key: &AssertionSigningKey,
    ) -> Result<Secret, DomainError>;
}

/// Dyn-safe port reading who a signed `X-Ianua-Assertion` says made the
/// request it came with, for the egress gateway, which holds an outbound
/// call against the agent whose request caused it.
///
/// The assertion is checked against the tenant's own assertion keys, its
/// algorithm pinned to the key and its type to `ianua-assertion+jwt`, so no
/// access token passes for one, and held to its times. It names a service
/// of the tenant as its audience, which the egress gateway cannot tell from
/// the calling service's certificate, so the audience is not compared: an
/// assertion lasts seconds, and a call carrying none is held to the
/// strictest class anyway.
#[async_trait]
pub trait AssertionVerifier: Send + Sync + TenantScoped {
    /// Who `assertion` says made the request, once it checks as one of
    /// `tenant_id`'s.
    ///
    /// # Errors
    ///
    /// - `DomainError::Unauthorized` when it is no assertion of the tenant,
    ///   does not check against its keys, or is outside its times.
    /// - `DomainError::Infrastructure` when the tenant's keys cannot be
    ///   read.
    async fn caller(
        &self,
        tenant_id: &ScopedTenant,
        assertion: &Secret,
    ) -> Result<AssertedCaller, DomainError>;
}

/// Dyn-safe port signing the gateway's message signatures: the signature
/// over a request it forwards or an answer it hands back, typed
/// `ianua-signature+jwt`, so it is never taken for an access token.
///
/// With the tenant's assertion key, which the gateway holds, never the
/// tenant's token signing key: a gateway that could sign with that could
/// mint the tenant's access tokens. An upstream checks a signature against
/// the assertion keys the tenant publishes.
#[async_trait]
pub trait MessageSigner: Send + Sync {
    /// The compact JWS of `claims_json`, signed for `tenant_id`, the tenant
    /// the request's host resolved to.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the tenant has no key the gateway may sign
    ///   with, or the signature cannot be made.
    async fn sign(&self, tenant_id: &TenantId, claims_json: &str) -> Result<String, DomainError>;
}

/// Dyn-safe port for generating cryptographic signing keys.
///
/// Infrastructure handles the actual key generation. The local adapter
/// generates the pair in memory and returns the private key as PEM.
#[async_trait]
pub trait KeyGenerator: Send + Sync {
    /// Generates a new signing key pair for the given algorithm.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the key cannot be generated.
    async fn generate(&self, algorithm: SigningAlgorithm) -> Result<GeneratedKey, DomainError>;
}

/// Dyn-safe port for persisting and retrieving algorithm migrations.
#[async_trait]
pub trait MigrationStore: Send + Sync + TenantScoped {
    /// Finds the active (non-terminal) migration for the tenant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_active(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AlgorithmMigration<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated migration.
    ///
    /// A tenant runs one migration at a time: a new one replaces the last
    /// only once that has finished.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when another migration of the tenant
    /// is under way, or `DomainError::Infrastructure` on persistence
    /// failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        migration: &AlgorithmMigration<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for signing JWTs with a tenant's signing key.
///
/// The infrastructure layer handles the actual cryptographic operation
/// with the key's private half.
#[async_trait]
pub trait JwtSigner: Send + Sync {
    /// Signs JWT claims as a token of kind `typ` and returns the compact JWS
    /// string (`header.payload.signature`).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if signing fails.
    async fn sign_typed(
        &self,
        claims_json: &str,
        typ: JwtType,
        key: JwtSigningKey<'_>,
    ) -> Result<String, DomainError>;

    /// Signs JWT claims as an access token, the one kind a caller may present
    /// back as a credential.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if signing fails.
    async fn sign(&self, claims_json: &str, key: JwtSigningKey<'_>) -> Result<String, DomainError> {
        self.sign_typed(claims_json, JwtType::Access, key).await
    }
}

/// The key a JWT is signed with. Holds the private key, so it has no
/// `Debug`.
#[derive(Clone, Copy)]
pub struct JwtSigningKey<'a> {
    /// The key id written to the JWT header.
    pub kid: &'a KeyId,
    /// The signing algorithm.
    pub algorithm: SigningAlgorithm,
    /// The private key PEM, or where a key service keeps it.
    pub private_key: &'a Secret,
}

/// Dyn-safe port for decoding PEM public keys into JWK components.
///
/// Infrastructure handles the actual PEM parsing using crypto libraries.
/// The domain defines the `JwkComponents` shape; this port bridges the two.
#[async_trait]
pub trait PublicKeyDecoder: Send + Sync {
    /// Decodes a PEM-encoded public key into structured JWK components.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the PEM is malformed or
    /// the algorithm doesn't match the key type.
    fn decode(
        &self,
        pem: &PublicKeyPem,
        kid: &KeyId,
        algorithm: SigningAlgorithm,
    ) -> Result<JwkComponents, DomainError>;
}

/// Dyn-safe port for checking that PEM text holds well-formed certificates,
/// without performing any cryptographic operation on them.
///
/// Used to reject an unparseable CA certificate at write time (when a
/// tenant configures an mTLS trust anchor) rather than letting it fail
/// silently later, inside the proxy's TLS layer.
pub trait CertPemValidator: Send + Sync {
    /// Checks that `pem` decodes to at least one well-formed X.509
    /// certificate.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if `pem` doesn't parse as a
    /// certificate.
    fn validate_cert_pem(&self, pem: &CertificatePem) -> Result<(), DomainError>;

    /// Checks that `pem` decodes to at least one well-formed certificate
    /// revocation list. Its signature is checked where it is used, in the
    /// handshake.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if `pem` doesn't parse as a
    /// revocation list.
    fn validate_revocation_list_pem(&self, pem: &RevocationListPem) -> Result<(), DomainError>;
}

/// The key an XML document is signed with. Holds the private key, so it has
/// no `Debug`.
#[derive(Clone, Copy)]
pub struct XmlSigningKey<'a> {
    /// The key's id, named in the signature.
    pub kid: &'a KeyId,
    /// The algorithm it signs with.
    pub algorithm: SigningAlgorithm,
    /// The private key PEM, or where a key service keeps it.
    pub private_key: &'a Secret,
    /// The public key, embedded so a verifier can check the signature.
    pub public_key: &'a PublicKeyPem,
}

/// Dyn-safe port for signing XML documents with enveloped XML Signature.
///
/// Used for SAML Response and Assertion signing. The infrastructure
/// layer handles the actual XML canonicalization, digest computation,
/// and cryptographic signing.
#[async_trait]
pub trait XmlSigner: Send + Sync {
    /// Signs an XML document by inserting an enveloped `<ds:Signature>` element.
    ///
    /// The signature is inserted after the `<saml:Issuer>` element if there is
    /// one, otherwise as the first child of the root element. Uses exclusive
    /// XML canonicalization (exc-c14n) per the XML Signature spec.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if signing fails.
    async fn sign_xml(&self, xml: &str, key: &XmlSigningKey<'_>) -> Result<String, DomainError>;
}

/// Dyn-safe port for generating cryptographically secure random tokens.
///
/// Infrastructure wraps the platform's OS-backed RNG. Kept as its own
/// port (rather than a bare function call) so use cases that need one,
/// like minting a canary decoy value, stay testable with a fake,
/// without pulling `ianua-infra` into `ianua-app`.
pub trait SecureTokenGenerator: Send + Sync {
    /// Generates a URL-safe, base64-encoded random token from
    /// `byte_len` bytes of OS randomness.
    fn generate(&self, byte_len: usize) -> Secret;
}

/// A newly generated signing key pair. Holds the private key, so it has no
/// `Debug`.
pub struct GeneratedKey {
    /// PEM-encoded public key for JWKS.
    pub public_key: PublicKeyPem,
    /// The private key. The local generator puts the PEM itself here, not a
    /// pointer to secure storage.
    pub private_key: Secret,
}
