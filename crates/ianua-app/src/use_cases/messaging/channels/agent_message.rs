//! Agent message channel: layer B of the message plane (message provenance).
//!
//! Seals every agent-to-agent message with a signed authorship envelope and
//! verifies it before the recipient acts. **Sign-then-encrypt**: this produces
//! the signed provenance token, which travels in a message header; the
//! payload-encryption decorator then encrypts the payload only, so the token
//! itself is not inside the ciphertext.
//!
//! Verification binds the claim to the exact payload via a content hash, so a
//! legitimately-connected agent can neither spoof another's authorship nor swap
//! the payload under a captured envelope.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::provenance::{MessageProvenance, SealedProvenance};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

use crate::ports::broker::{
    AgentPrincipal, MessageProvenanceSigner, MessageProvenanceVerifier, PayloadHasher,
};
use crate::tenancy::ScopedTenant;

/// Seals and opens signed provenance envelopes for agent-to-agent messages.
pub struct AgentMessageChannel {
    hasher: Arc<dyn PayloadHasher>,
    signer: Arc<dyn MessageProvenanceSigner>,
    verifier: Arc<dyn MessageProvenanceVerifier>,
}

impl AgentMessageChannel {
    /// Creates the channel over the provenance ports.
    #[must_use]
    pub fn new(
        hasher: Arc<dyn PayloadHasher>,
        signer: Arc<dyn MessageProvenanceSigner>,
        verifier: Arc<dyn MessageProvenanceVerifier>,
    ) -> Self {
        Self {
            hasher,
            signer,
            verifier,
        }
    }

    /// Seals `payload`'s provenance for `principal`, returning a signed token to
    /// travel alongside the (later encrypted) payload.
    ///
    /// # Errors
    ///
    /// Returns a [`DomainError`] when the provenance chain is invalid or the
    /// tenant cannot sign.
    pub async fn seal(
        &self,
        principal: &AgentPrincipal,
        payload: &[u8],
    ) -> Result<SealedProvenance, DomainError> {
        let payload_hash = self.hasher.hash(payload).await;
        let provenance = MessageProvenance::new(
            principal.agent_id,
            principal.on_behalf_of(),
            principal.delegation_id,
            payload_hash,
        )?;
        self.signer
            .sign(
                &ScopedTenant::from_verified_credential(principal.tenant_id),
                &provenance,
            )
            .await
    }

    /// Opens a sealed token and verifies it binds to `payload`.
    ///
    /// Returns the authenticated authorship. Enforcement is the caller's cue to
    /// act: an error here means *do not act*.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when the signature does not verify.
    /// - [`DomainError::Forbidden`] when the payload does not match the sealed
    ///   provenance (tamper or replay against a different payload).
    pub async fn open(
        &self,
        tenant_id: &ScopedTenant,
        token: &SealedProvenance,
        payload: &[u8],
    ) -> Result<MessageProvenance, DomainError> {
        let provenance = self.verifier.verify(tenant_id, token).await?;
        let payload_hash = self.hasher.hash(payload).await;
        if !provenance.binds_to(&payload_hash) {
            return Err(DomainError::forbidden(message!(
                "messaging-message-payload-does-not-match-its",
                "message payload does not match its provenance"
            )));
        }
        Ok(provenance)
    }
}

/// A channel sealing through an in-memory signer, for ports structs a test
/// fills with its fakes.
#[cfg(any(test, feature = "test-support"))]
impl crate::test_support::Fake for Arc<AgentMessageChannel> {
    fn fake() -> Self {
        let store = Arc::new(crate::test_support::messaging::MapProvenanceStore::default());
        Arc::new(AgentMessageChannel::new(
            Arc::new(crate::test_support::messaging::FirstByteHasher),
            store.clone(),
            store,
        ))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::types::{AgentId, DelegationId, PrincipalRef, TenantId, UserId};

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::messaging::{FirstByteHasher, MapProvenanceStore};

    fn channel(store: Arc<MapProvenanceStore>) -> AgentMessageChannel {
        AgentMessageChannel::new(Arc::new(FirstByteHasher), store.clone(), store)
    }

    fn principal(tenant: TenantId) -> AgentPrincipal {
        AgentPrincipal {
            tenant_id: tenant,
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            subject: PrincipalRef::User(UserId::new()),
            caps: CapabilitySet::empty(),
        }
    }

    /// An agent acting for Ann seals a message. Opening it names the agent,
    /// its delegation and Ann as the one it acts for.
    #[test]
    fn seal_then_open_round_trips_authorship() {
        let channel = channel(Arc::new(MapProvenanceStore::default()));
        let tenant = TenantId::new();
        let principal = principal(tenant);

        let token = block_on(channel.seal(&principal, b"payload one")).unwrap();
        let provenance =
            block_on(channel.open(&ScopedTenant::for_test(tenant), &token, b"payload one"))
                .unwrap();

        assert_eq!(provenance.sender(), &principal.agent_id);
        assert_eq!(provenance.delegation_id(), &principal.delegation_id);
        assert_eq!(provenance.on_behalf_of(), &[principal.subject]);
    }

    /// Opening a sealed envelope with a different payload returns a
    /// forbidden error.
    #[test]
    fn open_rejects_a_payload_that_does_not_match() {
        let channel = channel(Arc::new(MapProvenanceStore::default()));
        let tenant = TenantId::new();

        let token = block_on(channel.seal(&principal(tenant), b"aaa")).unwrap();
        let result = block_on(channel.open(&ScopedTenant::for_test(tenant), &token, b"bbb"));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Opening a provenance token absent from the signing store returns
    /// an unauthorized error.
    #[test]
    fn open_rejects_an_unverifiable_token() {
        let channel = channel(Arc::new(MapProvenanceStore::default()));

        let forged = SealedProvenance::new("forged-provenance-token").unwrap();
        let result =
            block_on(channel.open(&ScopedTenant::for_test(TenantId::new()), &forged, b"aaa"));

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// An agent acting on its own authority seals a message that names
    /// nobody it acts for.
    #[test]
    fn autonomous_principal_seals_an_empty_chain() {
        let channel = channel(Arc::new(MapProvenanceStore::default()));
        let tenant = TenantId::new();
        let agent = AgentId::new();
        let principal = AgentPrincipal {
            tenant_id: tenant,
            agent_id: agent,
            delegation_id: DelegationId::new(),
            subject: PrincipalRef::Agent(agent),
            caps: CapabilitySet::empty(),
        };

        let token = block_on(channel.seal(&principal, b"x")).unwrap();
        let provenance =
            block_on(channel.open(&ScopedTenant::for_test(tenant), &token, b"x")).unwrap();

        assert!(provenance.on_behalf_of().is_empty());
    }
}
