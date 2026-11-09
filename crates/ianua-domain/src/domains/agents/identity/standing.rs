//! Whether an agent may act right now.
//!
//! A delegation can be live while the agent holding it is suspended, revoked
//! or owes a re-attestation. Each of those must stop the agent's next
//! request, not only its next token. [`AgentStanding`] combines the agent's
//! status and whether it owes a re-attestation into the one answer
//! enforcement needs. An agent owes one when someone required it, or when its
//! last attestation is older than its policy allows.

use crate::domains::agents::identity::status::AgentStatus;

/// Whether an agent must prove where it runs again before it may act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reattestation {
    /// It must re-attest.
    Required,
    /// Its last attestation still stands.
    Current,
}

/// Whether an agent may act right now, and if not, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStanding {
    /// Active, attested, and free to act.
    Active,
    /// Active, but blocked until it proves what it is again.
    MustReattest,
    /// Suspended. Recoverable by a resume.
    Suspended,
    /// Revoked, or the agent does not exist. Nothing changes this.
    Revoked,
}

impl AgentStanding {
    /// The standing of an agent with `status` that does or does not owe a
    /// re-attestation.
    ///
    /// Status outranks the block. A suspended agent that also owes a
    /// re-attestation is suspended, because re-attesting alone would not let
    /// it act.
    #[must_use]
    pub fn of(status: AgentStatus, reattestation: Reattestation) -> Self {
        match (status, reattestation) {
            (AgentStatus::Revoked, _) => Self::Revoked,
            (AgentStatus::Suspended, _) => Self::Suspended,
            (AgentStatus::Active, Reattestation::Required) => Self::MustReattest,
            (AgentStatus::Active, Reattestation::Current) => Self::Active,
        }
    }

    /// Whether requests made under this standing may proceed.
    #[must_use]
    pub fn permits_requests(self) -> bool {
        self == Self::Active
    }

    /// Whether this standing can never change back to [`Active`](Self::Active).
    ///
    /// A cache may keep such an answer past its usual expiry, because nothing
    /// un-revokes an agent.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        self == Self::Revoked
    }

    /// Why a request under this standing is refused, or `None` when it is not.
    #[must_use]
    pub fn denial_reason(self) -> Option<&'static str> {
        match self {
            Self::Active => None,
            Self::MustReattest => Some("agent must re-attest"),
            Self::Suspended => Some("agent is suspended"),
            Self::Revoked => Some("agent is revoked"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An active agent whose attestation is current may make requests. One
    /// that must re-attest, is suspended or is revoked is refused.
    #[test]
    fn only_an_active_attested_agent_may_make_requests() {
        assert!(AgentStanding::of(AgentStatus::Active, Reattestation::Current).permits_requests());

        for standing in [
            AgentStanding::of(AgentStatus::Active, Reattestation::Required),
            AgentStanding::of(AgentStatus::Suspended, Reattestation::Current),
            AgentStanding::of(AgentStatus::Revoked, Reattestation::Current),
        ] {
            assert!(!standing.permits_requests(), "{standing:?} must be refused");
        }
    }

    /// A suspended agent also owes a re-attestation. Its standing is
    /// suspended, because re-attesting alone would not let it act.
    #[test]
    fn a_suspension_outranks_a_pending_re_attestation() {
        assert_eq!(
            AgentStanding::of(AgentStatus::Suspended, Reattestation::Required),
            AgentStanding::Suspended
        );
    }

    /// A revoked agent also owes a re-attestation. Its standing is revoked.
    #[test]
    fn a_revocation_outranks_every_other_condition() {
        assert_eq!(
            AgentStanding::of(AgentStatus::Revoked, Reattestation::Required),
            AgentStanding::Revoked
        );
    }

    /// An active standing gives no denial reason. Each of the three refused
    /// standings gives one.
    #[test]
    fn every_refused_standing_names_its_reason_and_only_those_do() {
        assert_eq!(AgentStanding::Active.denial_reason(), None);
        assert!(AgentStanding::MustReattest.denial_reason().is_some());
        assert!(AgentStanding::Suspended.denial_reason().is_some());
        assert!(AgentStanding::Revoked.denial_reason().is_some());
    }

    /// Only a revoked standing may be cached past its usual expiry. Suspended,
    /// must-re-attest and active can all still change.
    #[test]
    fn only_a_revocation_is_terminal() {
        assert!(AgentStanding::Revoked.is_terminal());
        assert!(!AgentStanding::Suspended.is_terminal());
        assert!(!AgentStanding::MustReattest.is_terminal());
        assert!(!AgentStanding::Active.is_terminal());
    }
}
