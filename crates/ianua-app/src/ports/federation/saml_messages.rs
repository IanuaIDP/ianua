//! SAML messages a peer sends this platform, read and checked against the
//! keys it trusts for that peer, and single logout: the requests this
//! platform sent and keeps until they are answered, and the provider
//! sessions a logout names.

use async_trait::async_trait;
use ianua_domain::domains::federation::saml::authn_request::InboundAuthnRequest;
use ianua_domain::domains::federation::saml::logout::{
    SamlLogoutRequest, SamlLogoutResponse, SentLogoutRequest,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CertificatePem, ConnectionId, FederatedSubject, SamlEntityId, SamlRequestId, SessionId,
    SessionIndex,
};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// How a SAML message reached this platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlBinding {
    /// Posted in a form: the base64 message, any signature inside the XML.
    Post,
    /// In the query string: the deflated base64 message, any signature on
    /// the query itself.
    Redirect(RedirectSignature),
}

/// The signature the HTTP-Redirect binding carries beside the message, as
/// it arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectSignature {
    /// The query carried no signature.
    Absent,
    /// The query carried one.
    Present {
        /// The `SigAlg` parameter.
        algorithm: String,
        /// The base64 `Signature` parameter.
        signature: String,
        /// The query string exactly as it arrived, which the signature
        /// covers.
        signed_query: String,
    },
}

/// A SAML message a peer sent, as it arrived and not yet read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSamlMessage {
    /// How it arrived.
    pub binding: SamlBinding,
    /// The encoded `SAMLRequest` or `SAMLResponse`.
    pub message: String,
}

/// Which keys a message must be signed by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureTrust {
    /// The peer is not required to sign. A signature it sends anyway is not
    /// checked, and the message counts as unsigned.
    NotRequired,
    /// The message must be signed by the key in one of these certificates.
    /// An unsigned message reads as unsigned; a signature that does not
    /// verify against any of them is refused.
    SignedBy(Vec<CertificatePem>),
}

/// Dyn-safe port reading the SAML messages peers send.
///
/// The adapter decodes the binding, parses the XML, and checks the
/// signature against the trust it is given. The domain decides what an
/// unsigned message may do; the adapter only refuses one whose signature
/// does not verify.
pub trait SamlMessageReader: Send + Sync {
    /// Who sent `message`, its `Issuer`, read before anything is trusted,
    /// so the keys for that peer can be found.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the message is malformed or
    /// names no issuer.
    fn issuer(&self, message: &InboundSamlMessage) -> Result<SamlEntityId, DomainError>;

    /// The sign-in request in `message`, its signature checked under
    /// `trust`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the message is malformed or is
    /// not a sign-in request, or `DomainError::Forbidden` if it carries a
    /// signature that does not verify.
    fn authn_request(
        &self,
        message: &InboundSamlMessage,
        trust: &SignatureTrust,
    ) -> Result<InboundAuthnRequest, DomainError>;

    /// The logout request in `message`, its signature checked under
    /// `trust`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the message is malformed or is
    /// not a logout request, or `DomainError::Forbidden` if `trust` asks
    /// for a signature and it is missing or does not verify.
    fn logout_request(
        &self,
        message: &InboundSamlMessage,
        trust: &SignatureTrust,
    ) -> Result<SamlLogoutRequest, DomainError>;

    /// The logout answer in `message`, its signature checked under `trust`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the message is malformed or is
    /// not a logout answer, or `DomainError::Forbidden` if `trust` asks for
    /// a signature and it is missing or does not verify.
    fn logout_response(
        &self,
        message: &InboundSamlMessage,
        trust: &SignatureTrust,
    ) -> Result<SamlLogoutResponse, DomainError>;
}

/// Dyn-safe port for the logout requests this platform sent, kept until
/// their answer comes back.
#[async_trait]
pub trait SentLogoutRequestStore: Send + Sync + TenantScoped {
    /// Keeps `request` until it is answered or lapses.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &SentLogoutRequest,
    ) -> Result<(), DomainError>;

    /// Atomically fetches and removes the request with `id`, so an answer
    /// is taken once. `None` if it was never sent or was answered.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlRequestId,
    ) -> Result<Option<SentLogoutRequest>, DomainError>;
}

/// Dyn-safe port recording which logout requests from peers were taken.
///
/// A signed logout request ends a person's sessions whenever it arrives,
/// so a captured one sent again would end them again. Each is taken once,
/// by its issuer and `ID`, and remembered until it is too old to be taken
/// anyway.
#[async_trait]
pub trait SamlLogoutLedger: Send + Sync + TenantScoped {
    /// Records `request` as taken until its
    /// [`taken_until`](SamlLogoutRequest::taken_until), answering whether
    /// this call was the one that took it.
    ///
    /// `false` means it was taken before and the caller must refuse it.
    /// Atomic: two nodes racing the same replay cannot both see `true`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, which
    /// the caller must treat as a refusal, not a pass.
    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        request: &SamlLogoutRequest,
    ) -> Result<bool, DomainError>;
}

/// The session a connection's provider keeps for a person signed in here
/// through it: whom it named and the session index its assertion carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSession {
    /// The session here the sign-in opened.
    pub session_id: SessionId,
    /// The connection the person signed in through.
    pub connection_id: ConnectionId,
    /// Who the provider named.
    pub subject: FederatedSubject,
    /// The session index its assertion carried.
    pub session_index: SessionIndex,
}

/// Dyn-safe port for the provider sessions behind sessions here.
#[async_trait]
pub trait ProviderSessionStore: Send + Sync + TenantScoped {
    /// Remembers the provider session behind a session here.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        session: &ProviderSession,
    ) -> Result<(), DomainError>;

    /// The provider session behind `session_id`, if it was opened through a
    /// SAML provider that named one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<Option<ProviderSession>, DomainError>;

    /// Forgets the provider session behind `session_id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete_by_session(
        &self,
        tenant_id: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<(), DomainError>;
}
