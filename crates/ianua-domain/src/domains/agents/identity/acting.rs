//! An agent that proved who it is just now, and so may act as itself.

use crate::types::{AgentCredentialId, AgentId};

/// An agent that signed in with its own key, as the credential checked.
///
/// Wherever an agent acts in its own name, such as passing part of its
/// delegation on, widening a child it passed on, minting a task token or
/// filing a review verdict, it shows this rather than its bare id. Agent B
/// learns agent A's id from a log. Without this, B passes A's delegation on
/// to itself by naming A.
///
/// It names the credential whose key proved possession, too. A task token
/// the agent mints is bound to that key and stands only while that key is
/// not revoked. The agent holds k2 and k3 and signs in with k3. Without the
/// name, its token could be bound to k2, which whoever holds k2 then uses.
///
/// Only [`AgentCredential::signed_in`] makes one, after the credential
/// verified an assertion for that agent. It is neither `Clone` nor `Copy`,
/// so a proof is lent, never multiplied.
///
/// [`AgentCredential::signed_in`]: crate::domains::agents::identity::credential::AgentCredential::signed_in
#[derive(Debug, PartialEq, Eq)]
pub struct ActingAgent {
    agent: AgentId,
    credential: AgentCredentialId,
}

impl ActingAgent {
    /// The proof that `agent` signed in with `credential`, once that
    /// credential verified it.
    pub(super) fn proven(agent: AgentId, credential: AgentCredentialId) -> Self {
        Self { agent, credential }
    }

    /// `agent`, signed in as a test says, with a credential nobody stored.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(agent: AgentId) -> Self {
        Self {
            agent,
            credential: AgentCredentialId::new(),
        }
    }

    /// `agent`, signed in as a test says with `credential`.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed_with(agent: AgentId, credential: AgentCredentialId) -> Self {
        Self { agent, credential }
    }

    /// The agent that signed in.
    #[must_use]
    pub fn agent(&self) -> &AgentId {
        &self.agent
    }

    /// The credential whose key signed the agent in.
    #[must_use]
    pub fn credential(&self) -> &AgentCredentialId {
        &self.credential
    }
}
