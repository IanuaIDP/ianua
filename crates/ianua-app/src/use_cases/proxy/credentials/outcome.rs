//! What authenticating a request's credential comes to: anonymous, a
//! proven caller, or a refusal the gateway turns into a deny.

use std::fmt::Display;

use ianua_domain::domains::agents::identity::token_attack::KeyProofFault;
use ianua_domain::domains::authorization::held::Held;
use ianua_domain::domains::proxy::access::question::DpopBinding;
use ianua_domain::domains::proxy::request::context::{Caller, CallerClaims, Verified};
pub use ianua_domain::domains::proxy::request::identification::{Identification, Proven};
use ianua_domain::shared::clock;
use ianua_domain::types::{AgentId, Expiry};

use crate::ports::authentication::{TokenFault, TokenReading};

/// Why a request's credential is refused. Every kind is a deny; the kind is
/// for the audit record and the status, never for the client to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The route needs a credential, or a client certificate, and the
    /// request presented none.
    Missing,
    /// The credential is malformed, of the wrong kind, badly signed, not
    /// yet valid, or says something that cannot be read.
    Invalid,
    /// The credential is past its expiry.
    Expired,
    /// The token names another issuer, or the route has no issuer to hold
    /// it to.
    WrongIssuer,
    /// The token was not minted for the route's service, or the service
    /// pins no audience on a route that needs a caller.
    WrongAudience,
    /// The app session was minted for another host, tenant or sign-in.
    WrongHost,
    /// Nobody the tenant knows holds the credential: no such person or
    /// consumer, a consumer disabled or not holding it, or a machine token
    /// no caller kind stands for.
    UnknownSubject,
    /// The person may no longer sign in.
    Inactive,
    /// What stands behind the credential was withdrawn: the session ended,
    /// the delegation or grant revoked, or the agent stopped.
    Revoked,
    /// A cookie request that changes something came from another site
    /// without a CSRF proof.
    CrossSite,
    /// A token bound to a key came without a proof of it, or with a proof
    /// that does not check out, names another key, or was used before.
    DpopMismatch(KeyMismatch),
    /// The consumer's quota for this period is spent.
    QuotaSpent,
    /// A store or a key could not be read, so nothing could be checked.
    Unavailable,
}

/// Whose key-bound token was refused for its key proof, and why: what the
/// gateway records a stolen token by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMismatch {
    /// The agent the token names.
    pub agent_id: AgentId,
    /// Why its proof was refused.
    pub fault: KeyProofFault,
}

impl Refusal {
    /// The refusal of a check that failed, logged with its error and
    /// nothing of the credential.
    pub(crate) fn unavailable(error: impl Display) -> Self {
        tracing::warn!(%error, "a request's credential could not be checked");
        Self::Unavailable
    }
}

impl From<TokenFault> for Refusal {
    fn from(fault: TokenFault) -> Self {
        match fault {
            TokenFault::Invalid | TokenFault::NotYetValid => Self::Invalid,
            TokenFault::Expired => Self::Expired,
            TokenFault::WrongIssuer => Self::WrongIssuer,
            TokenFault::WrongAudience => Self::WrongAudience,
            TokenFault::WrongHost => Self::WrongHost,
        }
    }
}

/// What a reader read, or its refusal.
///
/// # Errors
///
/// - The [`Refusal`] the reader's [`TokenFault`] stands for.
pub(crate) fn read<T>(reading: TokenReading<T>) -> Result<T, Refusal> {
    match reading {
        TokenReading::Read(token) => Ok(token),
        TokenReading::Refused(fault) => Err(Refusal::from(fault)),
    }
}

/// `caller`, proven until `expiry`, holding `held`, its credential carrying
/// `claims` and bound to a key as `binding` says, established now.
pub(crate) fn proven(
    caller: Caller,
    expiry: Expiry,
    held: Held,
    claims: CallerClaims,
    binding: DpopBinding,
) -> Identification {
    Identification::Proven(Box::new(Proven {
        verified: Verified { caller, expiry },
        claims,
        held,
        established_at: clock::now(),
        binding,
    }))
}
