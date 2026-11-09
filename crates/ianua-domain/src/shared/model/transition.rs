//! The one shape every status machine refuses a move in.

use std::fmt;

use crate::shared::errors::DomainError;

/// A status move the status's state machine does not allow.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move from {from:?} to {to:?}")]
pub struct InvalidTransition<S> {
    /// The status it is in.
    pub from: S,
    /// The status it was asked to move to.
    pub to: S,
}

impl<S: fmt::Debug> From<InvalidTransition<S>> for DomainError {
    fn from(refused: InvalidTransition<S>) -> Self {
        Self::invalid_transition(refused.to_string())
    }
}

/// A move from `from` to `to`, made when `permits` allows that move.
///
/// The rule is asked about the two ends, not handed a verdict, so every
/// status machine states its rule in the same place it is applied.
///
/// # Errors
///
/// - [`InvalidTransition`] when `permits` refuses the move.
pub fn checked<S: Copy>(
    from: S,
    to: S,
    permits: impl FnOnce(S, S) -> bool,
) -> Result<S, InvalidTransition<S>> {
    if permits(from, to) {
        return Ok(to);
    }
    Err(InvalidTransition { from, to })
}

/// Makes each named status refusal a [`DomainError::InvalidTransition`]
/// carrying its message, so a mutator can pass one on with `?`.
///
/// Invoked next to the status machine that defines the refusal.
macro_rules! refusal_is_a_domain_error {
    ($($refusal:ty),+ $(,)?) => {
        $(
            impl From<$refusal> for crate::shared::errors::DomainError {
                fn from(refusal: $refusal) -> Self {
                    Self::invalid_transition(refusal.to_string())
                }
            }
        )+
    };
}

pub(crate) use refusal_is_a_domain_error;

#[cfg(test)]
mod tests {
    use super::*;

    /// A move from `Archived` to `Active` that the rule refuses becomes an
    /// invalid-transition error whose message names both statuses.
    #[test]
    fn a_refused_move_names_both_ends() {
        let refused = checked("Archived", "Active", |_, _| false).unwrap_err();

        assert_eq!(
            DomainError::from(refused).to_string(),
            DomainError::invalid_transition("cannot move from \"Archived\" to \"Active\"")
                .to_string()
        );
    }

    /// A rule that allows moving upward lets 1 move to 2, and the result is
    /// the new status 2.
    #[test]
    fn an_allowed_move_lands_on_the_target() {
        assert_eq!(checked(1, 2, |from, to| from < to), Ok(2));
    }
}
