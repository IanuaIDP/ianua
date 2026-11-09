//! Whether a tool is offered to agents.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::transition::{InvalidTransition, checked};

/// Whether a tool is offered to agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ToolStatus {
    /// Available to agents.
    Active,
    /// Kept, but not offered to agents.
    Disabled,
}

impl ToolStatus {
    /// Moves to `to`. An active tool may be disabled, and a disabled one
    /// enabled.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] when it is already in `to`.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| from != to)
    }

    /// The stored string representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    /// Reads a value a caller sent.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] naming the value when it is not one of
    ///   the known names.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::named(value).ok_or_else(|| {
            DomainError::invalid(message!(
                "agents-unknown-tool-status",
                format!("unknown tool status: {value}")
            ))
        })
    }

    /// Reads a stored value.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the stored name is not one of
    ///   the known names. The row is corrupt, not the caller's input.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        Self::named(value)
            .ok_or_else(|| DomainError::corrupt_row("agent tool", "an unknown status"))
    }

    /// The value a name stands for.
    fn named(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both statuses read back from their stored names. A stored `retired` is
    /// an infrastructure error, a sent one a validation error. A disabled tool
    /// read back as active would be offered to agents again.
    #[test]
    fn the_tool_status_round_trips_through_its_stored_name() {
        let statuses = [
            (ToolStatus::Active, "active"),
            (ToolStatus::Disabled, "disabled"),
        ];

        for (status, name) in statuses {
            assert_eq!(status.as_str(), name);
            assert_eq!(ToolStatus::from_stored(name).unwrap(), status);
        }

        assert!(matches!(
            ToolStatus::from_stored("retired"),
            Err(DomainError::Infrastructure(_))
        ));
        assert!(matches!(
            ToolStatus::parse("retired"),
            Err(DomainError::Validation(_))
        ));
    }

    /// An active status may move to disabled. A disabled status moving to
    /// disabled is refused.
    #[test]
    fn a_tool_status_only_moves_to_the_other_status() {
        assert_eq!(
            ToolStatus::Active.try_transition(ToolStatus::Disabled),
            Ok(ToolStatus::Disabled)
        );
        assert!(
            ToolStatus::Disabled
                .try_transition(ToolStatus::Disabled)
                .is_err()
        );
    }
}
