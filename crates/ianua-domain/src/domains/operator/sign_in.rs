//! What an operator's sign-in leaves on the record.
//!
//! An operator signs in with their password to get a short-lived key; the
//! key's making records a sign-in that worked. A refused one changes
//! nothing an aggregate keeps, and may name an address no operator holds,
//! so it is recorded through this short-lived value instead: made when
//! the attempt arrives, raising its record once it is refused, dropped
//! once the record is taken.

use crate::domains::authentication::events::login::LoginFailureReason;
use crate::domains::operator::events::OperatorSignInFailed;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::types::{Email, Fact, IpAddress, UntrustedText};

/// One operator sign-in, from the address it named and the client it came
/// from, until it is refused or makes a key.
#[derive(Debug)]
pub struct OperatorSignInAttempt {
    email: UntrustedText,
    ip_address: Fact<IpAddress>,
    raised: RaisedEvents,
}

impl OperatorSignInAttempt {
    /// A sign-in naming `email`, made from `ip_address`. It has raised
    /// nothing yet.
    #[must_use]
    pub fn new(email: &Email, ip_address: Fact<IpAddress>) -> Self {
        Self {
            email: UntrustedText::record(email.as_str()),
            ip_address,
            raised: RaisedEvents::default(),
        }
    }

    /// The sign-in was refused for `reason`. Raises
    /// `operator.operator_sign_in_failed` with the address it named and
    /// where it came from.
    pub fn record_refusal(&mut self, reason: LoginFailureReason) {
        self.raised.raise_platform(OperatorSignInFailed {
            email: self.email.clone(),
            reason,
            ip_address: self.ip_address.clone(),
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl RaisesComplete for OperatorSignInAttempt {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::events::raised_complete_names;

    fn mallorys_guess() -> OperatorSignInAttempt {
        let email = Email::new("bob@ianua.dev").unwrap();
        OperatorSignInAttempt::new(&email, Fact::Unknown)
    }

    /// Mallory guesses Bob's operator password. The refusal is recorded
    /// once, naming the address she typed and why.
    #[test]
    fn a_refused_sign_in_is_recorded_once() {
        let mut attempt = mallorys_guess();

        attempt.record_refusal(LoginFailureReason::BadPassword);

        assert_eq!(
            raised_complete_names(&mut attempt),
            vec!["operator.operator_sign_in_failed"]
        );
        assert!(attempt.take_events().is_empty());
    }

    /// An attempt not yet refused has recorded nothing.
    #[test]
    fn an_attempt_not_refused_records_nothing() {
        let mut attempt = mallorys_guess();

        assert!(attempt.take_events().is_empty());
    }
}
