//! How much a step shows about the person taking it, weakest first.
//!
//! The rules that decide what a sign-in, a password change or an
//! invitation asks each map their answer to one of these, so answers of
//! different rules can be compared. A rule that depends on the deployment,
//! such as whether a mail server is set up, must never answer lower without
//! the capability than with it.

/// What a step shows about the person, beyond what they already showed,
/// from weakest to strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PersonProof {
    /// Nothing more: the password they gave, or the link someone handed
    /// them, is all there is.
    Nothing,
    /// That they hold the mailbox of their address.
    Mailbox,
    /// That they hold a second factor they set up before this step.
    OwnFactor,
    /// Nothing they could show is enough: the step is refused.
    Refused,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal shows the most and a step asking nothing the least, a
    /// factor set up beforehand above a mailbox.
    #[test]
    fn proof_runs_from_nothing_to_a_refusal() {
        assert!(PersonProof::Nothing < PersonProof::Mailbox);
        assert!(PersonProof::Mailbox < PersonProof::OwnFactor);
        assert!(PersonProof::OwnFactor < PersonProof::Refused);
    }
}
