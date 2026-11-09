//! How a push to a receiver's endpoint ended, said outright.

use crate::shared::errors::DomainError;

/// How one push to a receiver, such as a webhook endpoint or a signal
/// stream, ended.
///
/// It is one value, not a status beside an optional HTTP code. An answer
/// always carries its code, and success is read from that code. So a
/// delivery never reads as successful with a 500, or as answered with no
/// code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The receiver answered with this HTTP status code.
    Answered {
        /// The code it answered with.
        code: u16,
    },
    /// The receiver did not answer in time.
    TimedOut,
    /// The request could not be sent, such as after a DNS failure or a
    /// refused connection.
    Unreachable,
}

/// The broad result a delivery outcome reads as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryResult {
    /// Answered with a 2xx code.
    Success,
    /// Answered with any other code.
    Failed,
    /// No answer in time.
    Timeout,
    /// Never sent.
    Unreachable,
}

impl DeliveryOutcome {
    /// What the outcome reads as.
    #[must_use]
    pub fn result(self) -> DeliveryResult {
        match self {
            Self::Answered { code } if (200..300).contains(&code) => DeliveryResult::Success,
            Self::Answered { .. } => DeliveryResult::Failed,
            Self::TimedOut => DeliveryResult::Timeout,
            Self::Unreachable => DeliveryResult::Unreachable,
        }
    }

    /// The code the receiver answered with, if it answered. Storage keeps it
    /// in this form.
    #[must_use]
    pub fn response_code(self) -> Option<u16> {
        match self {
            Self::Answered { code } => Some(code),
            Self::TimedOut | Self::Unreachable => None,
        }
    }

    /// Reads an outcome back from its stored result and response code.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a success or failure has no
    ///   code.
    /// - [`DomainError::Infrastructure`] when a timeout or unreachable
    ///   outcome has a code.
    /// - [`DomainError::Infrastructure`] when the code contradicts the
    ///   result, such as a success with a 500.
    pub fn from_stored(result: DeliveryResult, code: Option<u16>) -> Result<Self, DomainError> {
        let outcome = match (result, code) {
            (DeliveryResult::Success | DeliveryResult::Failed, Some(code)) => {
                Self::Answered { code }
            }
            (DeliveryResult::Timeout, None) => Self::TimedOut,
            (DeliveryResult::Unreachable, None) => Self::Unreachable,
            (result, _) => return Err(Self::contradiction(result)),
        };
        if outcome.result() != result {
            return Err(Self::contradiction(result));
        }
        Ok(outcome)
    }

    fn contradiction(result: DeliveryResult) -> DomainError {
        DomainError::infra_msg(format!(
            "stored {result:?} delivery has a response code that contradicts it"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A receiver that answers 204 counts as a success. One that answers 500
    /// counts as failed, though it did answer.
    #[test]
    fn success_is_read_from_the_code() {
        assert_eq!(
            DeliveryOutcome::Answered { code: 204 }.result(),
            DeliveryResult::Success
        );
        assert_eq!(
            DeliveryOutcome::Answered { code: 500 }.result(),
            DeliveryResult::Failed
        );
    }

    /// A stored success with 200 reads back. A stored success with 500 or no
    /// code, and a timeout with 200, are refused as corrupt.
    #[test]
    fn a_stored_result_and_code_must_agree() {
        assert!(DeliveryOutcome::from_stored(DeliveryResult::Success, Some(200)).is_ok());
        assert!(DeliveryOutcome::from_stored(DeliveryResult::Success, Some(500)).is_err());
        assert!(DeliveryOutcome::from_stored(DeliveryResult::Success, None).is_err());
        assert!(DeliveryOutcome::from_stored(DeliveryResult::Timeout, Some(200)).is_err());
    }
}
