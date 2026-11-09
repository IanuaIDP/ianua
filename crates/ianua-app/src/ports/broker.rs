//! Message-plane ports: authentication, authorization and provenance for
//! agent-to-agent messaging.
//!
//! Agents never touch a broker: every message goes through the agent message
//! relay, which drives these ports. They are the message-plane siblings of the
//! HTTP proxy's identity and policy stages, and resolve authority from the
//! same delegation graph, so an agent's topic rights can never silently
//! disagree with its HTTP scopes.
//!
//! Four layers, all deny-by-default:
//!
//! - **A0, [`BrokerAuthenticator`]**, resolves a task token to an
//!   [`AgentPrincipal`], rejecting anonymous, invalid or revoked ones.
//! - **A, [`TopicAuthorizer`]**, decides whether a principal may publish or
//!   read a topic, matching the request against the principal's attenuated
//!   [`TopicCapability`](ianua_domain::domains::agents::authority::capability::TopicCapability) set.
//! - **B, [`MessageProvenanceSigner`] and [`MessageProvenanceVerifier`]**, seal
//!   and open the signed authorship of a relayed message, so no agent can pass
//!   a message off as another's.
//! - **Credential, [`TaskTokenVerifier`]**, verifies the presented task token
//!   offline against the tenant's signing key (the driven crypto primitive A0
//!   builds on).
//!
//! [`BrokerAuthenticator`] and [`TopicAuthorizer`] are implemented by the
//! application and driven by the relay. [`TaskTokenVerifier`],
//! [`PayloadHasher`], [`MessageProvenanceSigner`], and
//! [`MessageProvenanceVerifier`] are driven ports the infrastructure
//! implements.

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::{CapabilitySet, PubSub};
use ianua_domain::domains::agents::authority::provenance::{
    MessageProvenance, PayloadHash, SealedProvenance,
};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AgentId, DelegationId, Issuer, PrincipalRef, TenantId};

use crate::tenancy::ScopedTenant;

/// An authenticated agent connection: the identity, its delegation, the subject
/// it ultimately acts for, and its attenuated capabilities.
///
/// This is the message-plane principal: the resolved output of layer A0 and
/// the input to layers A and B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPrincipal {
    /// The tenant the connection is bound to (from the token's `tid`).
    pub tenant_id: TenantId,
    /// The connecting agent (from the token's `act`).
    pub agent_id: AgentId,
    /// The delegation the agent acts under (the token's `jti`).
    pub delegation_id: DelegationId,
    /// The ultimate authority the agent acts for (from the token's `sub`).
    pub subject: PrincipalRef,
    /// The attenuated capabilities carried by the delegation.
    pub caps: CapabilitySet,
}

impl AgentPrincipal {
    /// The provenance chain the agent acts for: the subject, unless the agent
    /// is its own subject (an autonomous, owner-delegated agent), in which case
    /// the chain is empty.
    #[must_use]
    pub fn on_behalf_of(&self) -> Vec<PrincipalRef> {
        match self.subject {
            PrincipalRef::Agent(id) if id == self.agent_id => Vec::new(),
            subject => vec![subject],
        }
    }
}

/// A task token that checked out against its tenant's key: the principal it
/// names, and the issuer it says made it, which the caller holds to the
/// tenant's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTaskToken {
    /// The principal the token names.
    pub principal: AgentPrincipal,
    /// The token's `iss`.
    pub issuer: Issuer,
}

/// Driven port: verifies a presented task token offline against the tenant's
/// signing key.
///
/// Pins the expected algorithm to the tenant key (never trusts the JWT header to
/// choose it), rejects `alg: none`, and checks `tid` and `exp`. Returns the
/// resolved principal with the token's issuer, or a domain error, never a
/// transport or crypto type. The adapter does not know the tenant's issuer,
/// so whether `iss` is the tenant's own is the caller's to check.
#[async_trait]
pub trait TaskTokenVerifier: Send + Sync {
    /// Verifies a task token and resolves it to a principal and its issuer.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Unauthorized`] when the token is malformed, has an
    /// unexpected algorithm, fails signature verification, is expired, names
    /// no known signing key, or names no issuer.
    async fn verify(&self, credential: &Secret) -> Result<VerifiedTaskToken, DomainError>;
}

/// Inbound port (layer A0): resolves a connection credential to a principal.
///
/// Rejects anonymous or invalid connections and re-checks that the delegation
/// has not been revoked, so an evicted agent cannot ride an unexpired token onto
/// the bus.
#[async_trait]
pub trait BrokerAuthenticator: Send + Sync {
    /// Authenticates a broker connection.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Unauthorized`] when the credential does not verify
    /// or its delegation has been revoked.
    async fn authenticate(&self, credential: &Secret) -> Result<AgentPrincipal, DomainError>;
}

/// Inbound port (layer A): decides whether a principal may act on a topic.
///
/// Deny by default: an unmatched request is a denial, never an allow. The
/// topic is tenant-relative; the driving broker adapter confirms the wire
/// subject belongs to the principal's tenant before delegating here.
#[async_trait]
pub trait TopicAuthorizer: Send + Sync {
    /// Authorizes a publish or subscribe on a topic.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] when the principal's capabilities do
    /// not cover the requested topic and rights.
    async fn authorize(
        &self,
        principal: &AgentPrincipal,
        topic: &TopicName,
        action: PubSub,
    ) -> Result<(), DomainError>;
}

/// Driven port: hashes a payload for provenance binding.
///
/// A single SHA-256 primitive, kept behind a port so the application layer never
/// depends on a crypto crate.
#[async_trait]
pub trait PayloadHasher: Send + Sync {
    /// Hashes a payload.
    async fn hash(&self, payload: &[u8]) -> PayloadHash;
}

/// Driven port (layer B, seal): signs a provenance envelope with the tenant key.
#[async_trait]
pub trait MessageProvenanceSigner: Send + Sync {
    /// Signs a provenance claim into a compact token.
    ///
    /// # Errors
    ///
    /// Returns a [`DomainError`] when the tenant has no active signing key or the
    /// signature cannot be computed.
    async fn sign(
        &self,
        tenant_id: &ScopedTenant,
        provenance: &MessageProvenance,
    ) -> Result<SealedProvenance, DomainError>;
}

/// Driven port (layer B, open): verifies a provenance envelope's signature.
#[async_trait]
pub trait MessageProvenanceVerifier: Send + Sync {
    /// Verifies a provenance token and reconstructs the claim.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Unauthorized`] when the token is malformed, signed
    /// by no known tenant key, or fails signature verification.
    async fn verify(
        &self,
        tenant_id: &ScopedTenant,
        token: &SealedProvenance,
    ) -> Result<MessageProvenance, DomainError>;
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;

    use super::*;

    fn principal(agent_id: AgentId, subject: PrincipalRef) -> AgentPrincipal {
        AgentPrincipal {
            tenant_id: TenantId::new(),
            agent_id,
            delegation_id: DelegationId::new(),
            subject,
            caps: CapabilitySet::empty(),
        }
    }

    /// An agent that acts on its own authority names nobody it acts for.
    #[test]
    fn an_agent_acting_for_itself_acts_on_behalf_of_nobody() {
        let agent = AgentId::new();

        assert!(
            principal(agent, PrincipalRef::Agent(agent))
                .on_behalf_of()
                .is_empty()
        );
    }

    /// Another agent as the subject is someone else's authority, and the
    /// provenance must say so rather than read as autonomous.
    #[test]
    fn an_agent_acting_for_another_agent_names_it() {
        let other = PrincipalRef::Agent(AgentId::new());

        assert_eq!(principal(AgentId::new(), other).on_behalf_of(), [other]);
    }

    /// An agent acting for Ann names Ann as the person it acts for.
    #[test]
    fn an_agent_acting_for_a_person_names_them() {
        let person = PrincipalRef::User(UserId::new());

        assert_eq!(principal(AgentId::new(), person).on_behalf_of(), [person]);
    }
}
