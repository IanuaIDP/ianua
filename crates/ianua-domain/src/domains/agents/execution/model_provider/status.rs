//! Whether runs may use a model provider, and how its last test went.

use time::OffsetDateTime;

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::UntrustedText;

/// Whether runs may use a model provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ModelProviderStatus {
    /// Runs may use it.
    Active,
    /// Kept, but new runs may not pick it.
    Disabled,
}

impl ModelProviderStatus {
    /// Moves to `to`. An active provider may be disabled, and a disabled one
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
                "agents-unknown-model-provider-status",
                format!("unknown model provider status: {value}")
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
            .ok_or_else(|| DomainError::corrupt_row("model provider", "an unknown status"))
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

/// The outcome of a test of whether the provider answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ModelProviderTestStatus {
    /// The provider answered.
    Passed,
    /// The test failed.
    Failed,
}

impl ModelProviderTestStatus {
    /// The stored string representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }

    /// Reads a stored value.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the name is unknown.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "passed" => Ok(Self::Passed),
            "failed" => Ok(Self::Failed),
            _ => Err(DomainError::corrupt_row(
                "model provider",
                "an unknown test status",
            )),
        }
    }
}

/// The last test of whether the provider answers, if one has run.
///
/// It is one value, not a status, a time and a message kept apart. So a test
/// cannot be recorded as passed with no time. Nor can a test that never ran
/// keep a failure reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LastTest {
    /// No test has run yet.
    NotYet,
    /// The last test passed.
    Passed {
        /// When it ran.
        at: OffsetDateTime,
    },
    /// The last test failed.
    Failed {
        /// When it ran.
        at: OffsetDateTime,
        /// What the provider answered, if anything. It is shortened and its
        /// control characters replaced, because operators are shown it.
        reason: Option<UntrustedText>,
    },
}

impl LastTest {
    /// Reads the three stored columns back as one test.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when there is a status with no time,
    ///   or a time with no status.
    /// - [`DomainError::Infrastructure`] when a test that passed or never ran
    ///   has a failure reason.
    pub fn from_stored(
        status: Option<ModelProviderTestStatus>,
        at: Option<OffsetDateTime>,
        reason: Option<String>,
    ) -> Result<Self, DomainError> {
        match (status, at, reason) {
            (None, None, None) => Ok(Self::NotYet),
            (Some(ModelProviderTestStatus::Passed), Some(at), None) => Ok(Self::Passed { at }),
            (Some(ModelProviderTestStatus::Failed), Some(at), reason) => Ok(Self::Failed {
                at,
                reason: reason.map(UntrustedText::from),
            }),
            _ => Err(DomainError::infra_msg(
                "a stored model provider test has a status, time and message that contradict each other",
            )),
        }
    }

    /// The outcome, if a test has run.
    #[must_use]
    pub fn status(&self) -> Option<ModelProviderTestStatus> {
        match self {
            Self::NotYet => None,
            Self::Passed { .. } => Some(ModelProviderTestStatus::Passed),
            Self::Failed { .. } => Some(ModelProviderTestStatus::Failed),
        }
    }

    /// When the test ran, if one has.
    #[must_use]
    pub fn at(&self) -> Option<OffsetDateTime> {
        match self {
            Self::NotYet => None,
            Self::Passed { at } | Self::Failed { at, .. } => Some(*at),
        }
    }

    /// Why the test failed, when it failed and the provider said why.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Failed { reason, .. } => reason.as_ref().map(UntrustedText::as_str),
            Self::NotYet | Self::Passed { .. } => None,
        }
    }
}
