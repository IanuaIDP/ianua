//! Which refused agent sign-ins look like an attack.
//!
//! An agent proves itself with an assertion its own key signed, spent on
//! first use, and a task token bound to its key works only beside a fresh
//! proof of that key. Most refusals are the agent's own slip: an assertion
//! that ran out on the way, a clock running ahead, an assertion made for
//! another endpoint, a key it was told to stop using. A few cannot happen
//! by accident, and those are what the people who run the tenant must hear
//! of:
//!
//! - an assertion presented again after it was spent: someone captured it;
//! - an assertion whose signature does not check against the agent's key,
//!   or that names a key the agent never held: someone forged it;
//! - an assertion naming another agent than the one it was presented for:
//!   someone is passing one agent off as another;
//! - a key-bound task token presented without a proof of its key, or with
//!   a proof by another key: someone copied the token and not the key.
//!
//! An agent id the tenant does not have is no attack on anything: there is
//! no agent to warn about, and anyone can make one up.

/// The kind of attack a refused agent sign-in looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenAttack {
    /// An assertion already spent was presented again.
    Replayed,
    /// The assertion was not signed by any key the agent holds.
    Forged,
    /// The assertion names another agent than the one it was presented for.
    WrongAgent,
    /// A task token bound to the agent's key came without a proof of that
    /// key.
    StolenBinding,
}

impl TokenAttack {
    /// A short, stable name for the audit record.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replayed => "replayed",
            Self::Forged => "forged",
            Self::WrongAgent => "wrong_agent",
            Self::StolenBinding => "stolen_binding",
        }
    }
}

/// Why an agent's assertion did not check out against the key it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionFault {
    /// It cannot be read as a signed assertion, or lacks a claim it must
    /// carry.
    Malformed,
    /// Its signature does not check against the agent's key with the
    /// algorithm stored beside it.
    BadSignature,
    /// It names another agent as its issuer or subject.
    WrongAgent,
    /// It was made for another audience than this token endpoint.
    WrongAudience,
    /// It is past its expiry.
    Expired,
    /// It is not valid yet, or says it was issued in the future.
    NotYetValid,
    /// It is valid for longer than an exchange needs.
    TooLongLived,
}

/// Why an agent was refused signing in with an assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInRefusal {
    /// The tenant has no agent of the id presented.
    UnknownAgent,
    /// The assertion names no key id that can be read.
    NoKeyId,
    /// The assertion names a key the agent does not hold.
    UnknownKey,
    /// The agent proves itself by attestation, and the key was enrolled
    /// by hand.
    KeyNotAdmitted,
    /// The key does not sign the agent in now: it was revoked, rotated
    /// out before the assertion was signed, or ran out, or the agent may
    /// not act.
    KeyNotUsable,
    /// The assertion did not check out against the agent's key.
    Assertion(AssertionFault),
    /// The assertion was spent before.
    Replayed,
}

impl SignInRefusal {
    /// The attack this refusal looks like, or `None` when it may be the
    /// agent's own slip.
    ///
    /// A key the agent never held counts as forged: the assertion was
    /// signed by a key that is not the agent's, whatever its header says.
    #[must_use]
    pub fn attack(self) -> Option<TokenAttack> {
        match self {
            Self::Replayed => Some(TokenAttack::Replayed),
            Self::UnknownKey | Self::Assertion(AssertionFault::BadSignature) => {
                Some(TokenAttack::Forged)
            }
            Self::Assertion(AssertionFault::WrongAgent) => Some(TokenAttack::WrongAgent),
            Self::UnknownAgent
            | Self::NoKeyId
            | Self::KeyNotAdmitted
            | Self::KeyNotUsable
            | Self::Assertion(
                AssertionFault::Malformed
                | AssertionFault::WrongAudience
                | AssertionFault::Expired
                | AssertionFault::NotYetValid
                | AssertionFault::TooLongLived,
            ) => None,
        }
    }
}

/// Why a task token bound to an agent's key was refused for its key proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProofFault {
    /// No proof came with the token.
    NotSent,
    /// The proof does not check out: malformed, for another request, out
    /// of date or used before.
    NotChecked,
    /// The proof checks out, but by another key than the one the token is
    /// bound to.
    ByAnotherKey,
}

impl KeyProofFault {
    /// The attack this refusal looks like, or `None` when it may be the
    /// agent's own slip.
    ///
    /// A bound token presented bare, or proven by another key, is a copy in
    /// hands that do not hold the agent's key. A proof that does not check
    /// out may be an agent whose clock drifted.
    #[must_use]
    pub fn attack(self) -> Option<TokenAttack> {
        match self {
            Self::NotSent | Self::ByAnotherKey => Some(TokenAttack::StolenBinding),
            Self::NotChecked => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replayed assertions, invalid signatures, unknown signing keys and
    /// assertions for another agent map to their corresponding attack kinds.
    #[test]
    fn replayed_forged_and_misattributed_assertions_are_attacks() {
        let attacks = [
            (SignInRefusal::Replayed, TokenAttack::Replayed),
            (
                SignInRefusal::Assertion(AssertionFault::BadSignature),
                TokenAttack::Forged,
            ),
            (SignInRefusal::UnknownKey, TokenAttack::Forged),
            (
                SignInRefusal::Assertion(AssertionFault::WrongAgent),
                TokenAttack::WrongAgent,
            ),
        ];

        for (refusal, attack) in attacks {
            assert_eq!(refusal.attack(), Some(attack), "{refusal:?}");
        }
    }

    /// Ann's agent sends an assertion that ran out on the way, one made for
    /// another endpoint, or one with its clock ahead. Those are its own
    /// slips, and no alert goes out.
    #[test]
    fn an_agents_own_slips_are_no_attack() {
        let slips = [
            SignInRefusal::NoKeyId,
            SignInRefusal::KeyNotAdmitted,
            SignInRefusal::KeyNotUsable,
            SignInRefusal::Assertion(AssertionFault::Malformed),
            SignInRefusal::Assertion(AssertionFault::WrongAudience),
            SignInRefusal::Assertion(AssertionFault::Expired),
            SignInRefusal::Assertion(AssertionFault::NotYetValid),
            SignInRefusal::Assertion(AssertionFault::TooLongLived),
        ];

        for refusal in slips {
            assert_eq!(refusal.attack(), None, "{refusal:?}");
        }
    }

    /// Mallory makes up an agent id. There is no agent to warn about, so it
    /// is no attack.
    #[test]
    fn an_unknown_agent_is_no_attack() {
        assert_eq!(SignInRefusal::UnknownAgent.attack(), None);
    }

    /// Missing proof or proof by another key indicates a stolen token
    /// binding; proof that has not been checked does not establish an attack.
    #[test]
    fn a_bound_token_without_its_keys_proof_is_a_stolen_binding() {
        assert_eq!(
            KeyProofFault::NotSent.attack(),
            Some(TokenAttack::StolenBinding)
        );
        assert_eq!(
            KeyProofFault::ByAnotherKey.attack(),
            Some(TokenAttack::StolenBinding)
        );
        assert_eq!(KeyProofFault::NotChecked.attack(), None);
    }
}
