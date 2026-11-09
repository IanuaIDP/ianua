//! An agent's task token: the agent acting under one delegation, held to
//! every limit the token confines it to.
//!
//! The token alone is not enough. Suspending or revoking the agent, or
//! revoking its delegation, stops it on the next request rather than when
//! the token runs out. A token bound to the agent's key works only beside
//! a fresh proof of that key, made for this request and used once, so a
//! copied token is useless without the key.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::token_attack::KeyProofFault;
use ianua_domain::domains::oauth::grants::token_binding::{JwkThumbprint, ProvenKey};
use ianua_domain::domains::proxy::access::question::DpopBinding;
use ianua_domain::domains::proxy::request::context::{Caller, CallerClaims, KeyBinding};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, Expiry, PrincipalRef};

use crate::ports::agents::{AgentStandingCheck, DelegationRevocationCheck};
use crate::ports::authentication::AgentToken;
use crate::ports::oauth::DpopUse;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::enforcement::authority::{
    AgentAuthority, AgentAuthorityRequest, authority_of,
};
use crate::use_cases::oauth::sender::{
    DpopHeader, SenderEvidence, SenderProofPorts, proven_sender,
};
use crate::use_cases::proxy::credentials::checking::{Bearer, Checking};
use crate::use_cases::proxy::credentials::held::held_by;
use crate::use_cases::proxy::credentials::outcome::{Identification, KeyMismatch, Refusal, proven};

/// The ports checking an agent may still act, and that a bound token came
/// with its key's proof.
#[derive(ianua_macros::Fakes)]
pub struct AgentPorts {
    /// Whether the agent may act right now.
    pub standings: Arc<dyn AgentStandingCheck>,
    /// Whether the delegation was revoked.
    pub revocations: Arc<dyn DelegationRevocationCheck>,
    /// Checks a `DPoP` proof and spends it.
    pub sender: SenderProofPorts,
}

/// The agent a task token names, once it may act, its delegation stands,
/// and a bound token came with its key's proof.
///
/// What it may do is what its delegation granted, as the token carries it,
/// and nothing its roles give: an agent acts within a person's grant. Its
/// own records are read once here for the roles and groups a tenant's
/// policy names; the access decision reads what the person it acts for
/// still holds.
///
/// # Errors
///
/// - [`Refusal::Revoked`] when the agent may not act now, or the
///   delegation was revoked or is gone.
/// - [`Refusal::DpopMismatch`] when a bound token came without a proof of
///   its key, or with one that does not check out.
/// - [`Refusal::Invalid`] when the token's binding and its key disagree.
/// - [`Refusal::Unavailable`] when a check fails, or the agent's records
///   cannot be read.
pub(crate) async fn by_token(
    ports: &AgentPorts,
    checking: &Checking<'_>,
    agent: AgentToken,
    bearer: Bearer,
) -> Result<Identification, Refusal> {
    ensure_authority_holds(ports, checking.tenant, &agent).await?;
    let binding = ensure_key_proven(ports, checking, &agent, bearer).await?;
    let principal = PrincipalRef::Agent(agent.agent_id);
    let held = held_by(checking.records, checking.tenant, principal).await?;
    let claims = CallerClaims {
        permissions: agent.permissions,
        ..CallerClaims::default()
    };
    let caller = Caller::Agent {
        agent_id: agent.agent_id,
        delegation_id: agent.delegation_id,
        acting_for: agent.acting_for,
        limits: Box::new(agent.limits),
    };
    Ok(proven(
        caller,
        Expiry::At(agent.expires_at),
        held,
        claims,
        binding,
    ))
}

/// Refuses an agent that may not act now, suspended, revoked, owing a fresh
/// attestation or unknown to the tenant, and a token whose delegation was
/// revoked or is gone: the rule the gateway asks again while a connection
/// the agent opened stays open.
///
/// # Errors
///
/// - [`Refusal::Revoked`] when the authority no longer holds.
/// - [`Refusal::Unavailable`] when the standing or the delegation cannot
///   be read.
async fn ensure_authority_holds(
    ports: &AgentPorts,
    tenant: &ScopedTenant,
    agent: &AgentToken,
) -> Result<(), Refusal> {
    let request = AgentAuthorityRequest {
        agent_id: agent.agent_id,
        delegation_id: agent.delegation_id,
    };
    let authority = authority_of(
        ports.standings.as_ref(),
        ports.revocations.as_ref(),
        tenant,
        request,
    )
    .await
    .map_err(Refusal::unavailable)?;
    match authority {
        AgentAuthority::Holds => Ok(()),
        AgentAuthority::Lost(_) => Err(Refusal::Revoked),
    }
}

/// Whether the token is bound to a key the request proved it holds;
/// refuses a bound token that came without a fresh proof of its key, and a
/// token whose binding names no key or a key it does not bind.
///
/// # Errors
///
/// - [`Refusal::Invalid`] when the binding and the key disagree.
/// - The cases [`ensure_proof_by`] lists.
async fn ensure_key_proven(
    ports: &AgentPorts,
    checking: &Checking<'_>,
    agent: &AgentToken,
    bearer: Bearer,
) -> Result<DpopBinding, Refusal> {
    match (&agent.limits.key_binding, &agent.bound_key) {
        (KeyBinding::Bearer, None) => Ok(DpopBinding::Unbound),
        (KeyBinding::Key(_), Some(key)) => {
            ensure_proof_by(ports, checking, bearer, key)
                .await
                .map_err(|unproved| unproved.refusal(agent.agent_id))?;
            Ok(DpopBinding::Bound)
        }
        (KeyBinding::Bearer, Some(_)) | (KeyBinding::Key(_), None) => Err(Refusal::Invalid),
    }
}

/// Why a bound token's key proof was not taken.
enum Unproved {
    /// The proof is missing, does not check out, or is by another key.
    Fault(KeyProofFault),
    /// The proof could not be checked.
    Unavailable(Refusal),
}

impl Unproved {
    /// The refusal of the token naming `agent_id`.
    fn refusal(self, agent_id: AgentId) -> Refusal {
        match self {
            Self::Fault(fault) => Refusal::DpopMismatch(KeyMismatch { agent_id, fault }),
            Self::Unavailable(refusal) => refusal,
        }
    }
}

/// Refuses a request whose `DPoP` proof is missing, does not check out for
/// this method, address and token, was used before, or was signed by
/// another key than `key`.
///
/// # Errors
///
/// - [`Unproved::Fault`] in each of those cases, saying which.
/// - [`Unproved::Unavailable`] when the proof cannot be spent.
async fn ensure_proof_by(
    ports: &AgentPorts,
    checking: &Checking<'_>,
    bearer: Bearer,
    key: &JwkThumbprint,
) -> Result<(), Unproved> {
    if matches!(bearer.dpop, DpopHeader::NotSent) {
        return Err(Unproved::Fault(KeyProofFault::NotSent));
    }
    let evidence = SenderEvidence {
        dpop: bearer.dpop,
        method: checking.target.method.as_str().to_owned(),
        url: checking.target.url.as_str().to_owned(),
    };
    let proof = proven_sender(
        &ports.sender,
        checking.tenant,
        &evidence,
        DpopUse::AccessToken(&bearer.token),
    )
    .await
    .map_err(proof_refusal)?;
    match proof.dpop {
        ProvenKey::Proved(proved) if proved == *key => Ok(()),
        ProvenKey::Proved(_) => Err(Unproved::Fault(KeyProofFault::ByAnotherKey)),
        ProvenKey::NotShown => Err(Unproved::Fault(KeyProofFault::NotSent)),
    }
}

/// Why the check turned a proof away.
fn proof_refusal(error: DomainError) -> Unproved {
    match error {
        DomainError::Unauthorized(_) => Unproved::Fault(KeyProofFault::NotChecked),
        other => Unproved::Unavailable(Refusal::unavailable(other)),
    }
}
