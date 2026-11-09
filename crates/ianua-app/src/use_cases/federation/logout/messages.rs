//! What the single logout use cases share: signing the logout messages this
//! platform sends, ending the person's own session when a peer asks, taking
//! each of a peer's logout requests once while it is fresh, and fresh
//! request ids. Response ids are the federation's own, shared with
//! the answers to SAML apps. The browser a peer's request came through is the
//! shared [`LogoutBrowser`].

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_domain::domains::federation::connection::{ConnectionConfig, FederatedIdpConnection};
use ianua_domain::domains::federation::saml::logout::SamlLogoutRequest;
use ianua_domain::domains::federation::saml::logout_builder::BuiltLogoutMessage;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, HttpsUrl, SamlRequestId};
use uuid::Uuid;

use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{SigningKeyStore, XmlSigner};
use crate::ports::federation::{SamlLogoutLedger, SignatureTrust};
use crate::ports::shared::SessionStore;
pub use crate::services::authentication::logout_browser::LogoutBrowser;
use crate::services::lookup::existing_key_set;
use crate::tenancy::ScopedTenant;
use crate::use_cases::federation::lookup::{active_signing_key, xml_signing_key};

/// A logout message on its way to a peer, for the browser to post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingLogoutMessage {
    /// The peer's logout address.
    pub destination: HttpsUrl,
    /// The signed message XML, base64-encoded for the HTTP-POST binding.
    pub base64_message: String,
}

/// Signs logout messages with the tenant's key, for every use case that
/// sends one.
#[derive(Clone)]
pub struct LogoutSigner {
    /// The tenant's signing keys.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Signs XML.
    pub xml_signer: Arc<dyn XmlSigner>,
}

impl LogoutSigner {
    /// `message`, signed with the key `tenant` signs with now, ready to post
    /// to `destination`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant has no signing key set.
    /// - `AppError::Internal` if the set holds no active key, or on signing
    ///   failure.
    pub(super) async fn signed(
        &self,
        tenant: &ScopedTenant,
        message: &BuiltLogoutMessage,
        destination: HttpsUrl,
    ) -> Result<OutgoingLogoutMessage, AppError> {
        let key_set = existing_key_set(self.key_store.as_ref(), tenant).await?;
        let key = active_signing_key(&key_set)?;
        let signed = self
            .xml_signer
            .sign_xml(message.xml(), &xml_signing_key(key))
            .await
            .or_internal()?;
        Ok(OutgoingLogoutMessage {
            destination,
            base64_message: STANDARD.encode(signed.as_bytes()),
        })
    }
}

/// Ends sessions a peer's logout names, for every use case that answers
/// one.
#[derive(Clone)]
pub struct SessionEnding {
    /// The tenant's sessions.
    pub sessions: Arc<dyn SessionStore>,
}

impl SessionEnding {
    /// Ends `person`'s session, as they asked through the peer, and records
    /// `authentication.session_revoked`. A session already ended stays so.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` if the domain refuses the holder ending it,
    ///   which it never does.
    /// - `AppError::Internal` on storage, cache or audit failure.
    pub(super) async fn end(
        &self,
        tenant: &ScopedTenant,
        person: SignedInAccount,
        auditor: &RequestAuditor,
    ) -> Result<(), AppError> {
        let mut session = person.session;
        match session.revoke(&person.signed_in) {
            Ok(()) => {}
            Err(DomainError::InvalidTransition(_)) => return Ok(()),
            Err(refused) => return Err(AppError::from_domain(refused)),
        }
        self.sessions.save(tenant, &session).await.or_internal()?;
        let holder = ActorRef::User(*session.user_id());
        auditor
            .dispatch_by(&holder, session.take_events(tenant))
            .await
            .or_internal()
    }
}

/// The certificates a SAML connection's provider signs its messages with.
///
/// # Errors
///
/// - `AppError::Conflict` if it is not a SAML connection.
pub(super) fn provider_trust(
    connection: &FederatedIdpConnection<ResolvedTenant>,
) -> Result<SignatureTrust, AppError> {
    let ConnectionConfig::Saml(saml) = connection.config() else {
        return Err(AppError::Conflict(message!(
            "federation-only-a-saml-connection-takes-logout",
            "only a SAML connection takes logout messages"
        )));
    };
    Ok(SignatureTrust::SignedBy(
        saml.certificates.accepted().cloned().collect(),
    ))
}

/// Refuses `request` when it is no longer fresh, or was taken before, and
/// records it as taken otherwise, so a captured request ends no session a
/// second time.
///
/// # Errors
///
/// - `AppError::Domain` if it is too old, or issued ahead of now.
/// - `AppError::Forbidden` if it was taken before.
/// - `AppError::Internal` if the ledger cannot be written.
pub(super) async fn take_once(
    ledger: &dyn SamlLogoutLedger,
    tenant: &ScopedTenant,
    request: &SamlLogoutRequest,
) -> Result<(), AppError> {
    request
        .ensure_fresh(clock::now())
        .map_err(AppError::from_domain)?;
    if !ledger.spend(tenant, request).await.or_internal()? {
        return Err(AppError::Forbidden(message!(
            "federation-this-logout-request-was-taken-already",
            "this logout request was taken already"
        )));
    }
    Ok(())
}

/// A new, unique logout request id.
///
/// # Errors
///
/// - `AppError::Internal` if the id is refused, which it never is.
pub(super) fn fresh_request_id() -> Result<SamlRequestId, AppError> {
    SamlRequestId::new(format!("_l{}", Uuid::now_v7().simple())).or_internal()
}
