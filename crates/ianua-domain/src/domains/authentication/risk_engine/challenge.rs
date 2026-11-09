//! What a password sign-in must show while sign-in is under high pressure.
//!
//! Under high pressure, a sign-in from a device the person never trusted
//! carries a passed challenge, or it is refused before its password is
//! hashed. A trusted device goes through as it is: the flood does not hold
//! its secret. The refusal reads the same whether or not the address has an
//! account, so it tells a guesser nothing.
//!
//! Deny by default: with no challenge provider set up, nothing could pass,
//! so a device that is not trusted is refused rather than let through.

use crate::domains::authentication::risk_engine::step_up::Familiarity;
use crate::shared::validation::{TextValue, Validator, text_value};

/// The kinds of challenge a deployment may set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ChallengeKind {
    /// A puzzle the browser works through itself, served by ianua.
    ProofOfWork,
    /// Cloudflare Turnstile.
    Turnstile,
}

impl ChallengeKind {
    /// The name the API and the sign-in page use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofOfWork => "proof_of_work",
            Self::Turnstile => "turnstile",
        }
    }
}

/// Whether the deployment can set a challenge, and which kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeSetup {
    /// No challenge provider is set up. Nothing can pass.
    Unconfigured,
    /// Challenges of this kind are set and checked.
    Configured(ChallengeKind),
}

/// The challenge a refused sign-in is told it needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredChallenge {
    /// Solve a challenge of this kind and send its proof.
    Solve(ChallengeKind),
    /// No challenge can be set right now. Only a trusted device or single
    /// sign-on gets in until pressure eases.
    Unavailable,
}

impl RequiredChallenge {
    /// The kind to solve, when one can be set.
    #[must_use]
    pub fn kind(self) -> Option<ChallengeKind> {
        match self {
            Self::Solve(kind) => Some(kind),
            Self::Unavailable => None,
        }
    }
}

text_value! {
    redacted
    /// The proof a browser sends that it passed a challenge: a solved
    /// puzzle or a Turnstile token.
    ///
    /// It lets a sign-in through while sign-in is under pressure, so it is
    /// treated as a credential: never logged, never put in an event.
    pub struct ChallengeProof;
}

impl TextValue for ChallengeProof {
    const FIELD: &'static str = "challenge_proof";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .max_bytes(ChallengeProof::MAX_BYTES)
            .not_blank()
            .ascii_only()
    }
}

impl ChallengeProof {
    /// Turnstile tokens run to about two thousand characters. Twice that
    /// leaves room for a puzzle's answer and refuses a payload sent to make
    /// the check itself costly.
    const MAX_BYTES: usize = 4096;
}

/// What the challenge provider said about a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeVerdict {
    /// A solved challenge, not used before.
    Passed,
    /// Forged, expired, or already used.
    Failed,
}

/// What a sign-in under high pressure has, as the gate reads it.
#[derive(Debug, Clone, Copy)]
pub struct GateSignals<'a> {
    /// Whether the device is one the person trusted and that still counts.
    pub device: Familiarity,
    /// Whether challenges can be set, and which kind.
    pub setup: ChallengeSetup,
    /// The proof the browser sent, if it sent one.
    pub proof: Option<&'a ChallengeProof>,
}

/// What happens next to a sign-in under high pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStep<'a> {
    /// It goes on to the password.
    Proceed,
    /// Its proof is checked by the provider of this kind first.
    CheckProof(ChallengeKind, &'a ChallengeProof),
    /// It is refused, told it needs this challenge.
    Refuse(RequiredChallenge),
}

/// The step `signals` lead to while sign-in is under high pressure.
///
/// A trusted device goes on. Any other device is refused unless it sent a
/// proof for a provider that is set up, and then the proof is checked.
#[must_use]
pub fn under_high_pressure(signals: GateSignals<'_>) -> GateStep<'_> {
    match (signals.device, signals.setup, signals.proof) {
        (Familiarity::Known, _, _) => GateStep::Proceed,
        (Familiarity::New, ChallengeSetup::Unconfigured, _) => {
            GateStep::Refuse(RequiredChallenge::Unavailable)
        }
        (Familiarity::New, ChallengeSetup::Configured(kind), None) => {
            GateStep::Refuse(RequiredChallenge::Solve(kind))
        }
        (Familiarity::New, ChallengeSetup::Configured(kind), Some(proof)) => {
            GateStep::CheckProof(kind, proof)
        }
    }
}

impl ChallengeVerdict {
    /// The step a proof for a `kind` challenge leads to once the provider
    /// judged it: a passed one goes on, any other is refused and told to
    /// solve a fresh one.
    #[must_use]
    pub fn step(self, kind: ChallengeKind) -> GateStep<'static> {
        match self {
            Self::Passed => GateStep::Proceed,
            Self::Failed => GateStep::Refuse(RequiredChallenge::Solve(kind)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof() -> ChallengeProof {
        ChallengeProof::new("solved-puzzle-0042").unwrap()
    }

    const POW: ChallengeSetup = ChallengeSetup::Configured(ChallengeKind::ProofOfWork);

    fn signals(
        device: Familiarity,
        setup: ChallengeSetup,
        proof: Option<&ChallengeProof>,
    ) -> GateSignals<'_> {
        GateSignals {
            device,
            setup,
            proof,
        }
    }

    /// Ann signs in on the laptop she trusted while Acme is flooded. She is
    /// let through without a challenge, whatever the setup.
    #[test]
    fn a_trusted_device_goes_through_under_pressure() {
        for setup in [POW, ChallengeSetup::Unconfigured] {
            let step = under_high_pressure(signals(Familiarity::Known, setup, None));

            assert_eq!(step, GateStep::Proceed);
        }
    }

    /// An untrusted device without proof must solve the configured proof-of-work challenge.
    #[test]
    fn an_untrusted_device_without_a_proof_is_told_to_solve_one() {
        let step = under_high_pressure(signals(Familiarity::New, POW, None));

        assert_eq!(
            step,
            GateStep::Refuse(RequiredChallenge::Solve(ChallengeKind::ProofOfWork))
        );
    }

    /// Ann, on a new phone, sends a solved puzzle. Its proof is checked by
    /// the provider before anything else.
    #[test]
    fn an_untrusted_device_with_a_proof_has_it_checked() {
        let sent = proof();

        let step = under_high_pressure(signals(Familiarity::New, POW, Some(&sent)));

        assert_eq!(
            step,
            GateStep::CheckProof(ChallengeKind::ProofOfWork, &sent)
        );
    }

    /// Without a configured challenge provider, an untrusted device is refused
    /// whether it supplies proof or omits it.
    #[test]
    fn with_no_provider_an_untrusted_device_is_refused() {
        let sent = proof();
        let unconfigured = ChallengeSetup::Unconfigured;

        for proof in [None, Some(&sent)] {
            let step = under_high_pressure(signals(Familiarity::New, unconfigured, proof));

            assert_eq!(step, GateStep::Refuse(RequiredChallenge::Unavailable));
        }
    }

    /// A proof the provider passed goes on; a forged or replayed one is
    /// refused and told to solve a fresh challenge of the same kind.
    #[test]
    fn the_providers_verdict_decides_the_step() {
        let kind = ChallengeKind::Turnstile;

        assert_eq!(ChallengeVerdict::Passed.step(kind), GateStep::Proceed);
        assert_eq!(
            ChallengeVerdict::Failed.step(kind),
            GateStep::Refuse(RequiredChallenge::Solve(kind))
        );
    }

    /// An empty proof, one past the size limit, and one with characters
    /// outside ASCII are all refused before any provider is asked.
    #[test]
    fn a_malformed_proof_is_refused() {
        assert!(ChallengeProof::new("").is_err());
        assert!(ChallengeProof::new("   ").is_err());
        assert!(ChallengeProof::new("x".repeat(4097)).is_err());
        assert!(ChallengeProof::new("pr\u{00f6}of").is_err());
        assert!(ChallengeProof::new("x".repeat(4096)).is_ok());
    }

    /// A proof is a credential: its debug form never shows it.
    #[test]
    fn a_proof_never_shows_in_debug_output() {
        let shown = format!("{:?}", proof());

        assert!(!shown.contains("solved-puzzle"));
    }
}
