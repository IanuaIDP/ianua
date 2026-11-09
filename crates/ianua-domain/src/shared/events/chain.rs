//! Where an event came from: outside any workflow, or from the work of a
//! workflow execution, and how deep that execution is in a chain of
//! executions that set each other off.
//!
//! Every event an execution's work raises carries the execution's depth,
//! so an execution that event starts is one deeper, and a chain of
//! workflows setting each other off stops at [`MAX_CHAIN_DEPTH`].

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;

/// The most executions that may start one another through events, the
/// first included, so workflows set off by each other's work come to an
/// end.
pub const MAX_CHAIN_DEPTH: u8 = 3;

/// How many executions led to this one, itself included. It is one for an
/// execution no other workflow set off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChainDepth(u8);

impl ChainDepth {
    /// The depth of an execution no other execution led to.
    pub const FIRST: Self = Self(1);

    /// Reads a stored depth.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for a depth below one or above
    ///   [`MAX_CHAIN_DEPTH`].
    pub fn from_stored(depth: u8) -> Result<Self, DomainError> {
        if !(1..=MAX_CHAIN_DEPTH).contains(&depth) {
            return Err(DomainError::corrupt_row(
                "event chain",
                "a chain depth outside its range",
            ));
        }
        Ok(Self(depth))
    }

    /// The depth.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }

    /// The depth of an execution this one's work led to.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when this execution is already
    ///   [`MAX_CHAIN_DEPTH`] deep.
    pub fn next(self) -> Result<Self, DomainError> {
        match self.0.checked_add(1) {
            Some(depth) if depth <= MAX_CHAIN_DEPTH => Ok(Self(depth)),
            Some(_) | None => Err(DomainError::forbidden(message!(
                "values-at-most-workflows-may-set-each",
                format!("at most {MAX_CHAIN_DEPTH} workflows may set each other off")
            ))),
        }
    }
}

/// Where an event came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOrigin {
    /// From outside any workflow.
    Outside,
    /// From the work of an execution this deep in its chain.
    Execution(ChainDepth),
}

impl EventOrigin {
    /// `event`, marked as coming from here. An event from the work of an
    /// execution carries its depth, so a workflow it sets off continues the
    /// chain rather than starting a new one.
    pub(crate) fn mark(self, event: DomainEvent) -> DomainEvent {
        match self {
            Self::Outside => event,
            Self::Execution(depth) => event.from_execution(depth),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::model::row_check::refused_as_corrupt;

    /// The first workflow's child has depth two, but extending a chain already
    /// at the maximum is forbidden, bounding mutually triggered executions.
    #[test]
    fn a_chain_goes_one_deeper_up_to_its_limit() {
        let last = ChainDepth::from_stored(MAX_CHAIN_DEPTH).unwrap();

        assert_eq!(ChainDepth::FIRST.next().unwrap().get(), 2);
        assert!(matches!(last.next(), Err(DomainError::Forbidden(_))));
    }

    /// A stored depth of zero, or one above [`MAX_CHAIN_DEPTH`], cannot come
    /// from this code. It is refused as a corrupt row, not loaded or clamped.
    #[test]
    fn a_stored_depth_outside_its_range_is_corrupt() {
        assert!(refused_as_corrupt(&ChainDepth::from_stored(0)));
        assert!(refused_as_corrupt(&ChainDepth::from_stored(
            MAX_CHAIN_DEPTH + 1
        )));
    }
}
