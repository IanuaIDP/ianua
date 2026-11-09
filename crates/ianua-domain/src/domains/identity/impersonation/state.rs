//! Where a tenant admin's request to act as a person stands, how long it may
//! last, and whether the person must agree first.

use time::{Duration, OffsetDateTime};

use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;

/// Whether the person must agree before a tenant admin acts as them. The
/// tenant chooses, and the request keeps the choice it was made under.
///
/// A tenant that never chose has the person approve first: acting as
/// someone is holding all they hold, so it is not done behind their back
/// unless the tenant says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ImpersonationConsent {
    /// The admin starts at once. The person is told, and may end it.
    AdminDecides,
    /// The person approves the request from their own sign-in first.
    #[default]
    HolderApproves,
}

impl ImpersonationConsent {
    /// The rule's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdminDecides => "admin_decides",
            Self::HolderApproves => "holder_approves",
        }
    }
}

/// How long an admin may act as the person once it starts: from five
/// minutes to an hour.
///
/// It is short on purpose. Support looks at what the person sees and puts
/// it right; a longer stretch would be a second account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImpersonationWindow(u32);

impl ImpersonationWindow {
    /// The shortest window, in minutes.
    pub const MIN_MINUTES: u32 = 5;
    /// The longest window, in minutes.
    pub const MAX_MINUTES: u32 = 60;

    /// A window of `minutes`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `minutes` is outside
    ///   [`Self::MIN_MINUTES`] to [`Self::MAX_MINUTES`].
    pub fn minutes(minutes: u32) -> Result<Self, DomainError> {
        validate_range(
            "impersonation_minutes",
            minutes,
            Self::MIN_MINUTES..=Self::MAX_MINUTES,
        )?;
        Ok(Self(minutes))
    }

    /// The window in minutes, as storage keeps it.
    #[must_use]
    pub fn as_minutes(self) -> u32 {
        self.0
    }

    /// The window as a length of time.
    #[must_use]
    pub fn as_duration(self) -> Duration {
        Duration::minutes(i64::from(self.0))
    }
}

/// Where a request to act as a person stands.
///
/// The allowed moves:
/// - `AwaitingConsent` to `Active` when the person approves, to `Declined`
///   when they refuse, and to `Ended` when either side withdraws it.
/// - `Active` to `Ended` when either side ends it early.
///
/// An active one whose window is over is over without a move: every use
/// checks the time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImpersonationStatus {
    /// Waiting for the person to approve.
    AwaitingConsent,
    /// The admin may act as the person until the window ends.
    Active,
    /// The person refused.
    Declined,
    /// Ended early, or withdrawn before it started.
    Ended,
}

/// An impersonation status change the rules refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a support impersonation from {from:?} to {to:?}")]
pub struct InvalidImpersonationTransition {
    /// The current status.
    pub from: ImpersonationStatus,
    /// The status asked for.
    pub to: ImpersonationStatus,
}

impl ImpersonationStatus {
    /// Moves to `to`.
    ///
    /// # Errors
    ///
    /// - [`InvalidImpersonationTransition`] when the move is not one of the
    ///   moves listed on [`ImpersonationStatus`].
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidImpersonationTransition> {
        let allowed = matches!(
            (self, to),
            (
                Self::AwaitingConsent,
                Self::Active | Self::Declined | Self::Ended
            ) | (Self::Active, Self::Ended)
        );
        if !allowed {
            return Err(InvalidImpersonationTransition { from: self, to });
        }
        Ok(to)
    }

    /// The status's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingConsent => "awaiting_consent",
            Self::Active => "active",
            Self::Declined => "declined",
            Self::Ended => "ended",
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidImpersonationTransition);

/// Where a request to act as a person stands, with the time its status
/// began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpersonationState {
    /// Waiting for the person to approve.
    AwaitingConsent,
    /// The admin may act as the person.
    Active {
        /// When it started; the window runs from here.
        since: OffsetDateTime,
    },
    /// The person refused.
    Declined {
        /// When they refused.
        at: OffsetDateTime,
    },
    /// Ended early, or withdrawn before it started.
    Ended {
        /// When it ended.
        at: OffsetDateTime,
    },
}

impl ImpersonationState {
    /// The [`ImpersonationStatus`] for this state.
    #[must_use]
    pub fn status(self) -> ImpersonationStatus {
        match self {
            Self::AwaitingConsent => ImpersonationStatus::AwaitingConsent,
            Self::Active { .. } => ImpersonationStatus::Active,
            Self::Declined { .. } => ImpersonationStatus::Declined,
            Self::Ended { .. } => ImpersonationStatus::Ended,
        }
    }

    /// Reads a state back from its stored status and the time it began.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a request awaiting consent has
    ///   a time, or any other status has none.
    pub fn from_stored(
        status: ImpersonationStatus,
        since: Option<OffsetDateTime>,
    ) -> Result<Self, DomainError> {
        match (status, since) {
            (ImpersonationStatus::AwaitingConsent, None) => Ok(Self::AwaitingConsent),
            (ImpersonationStatus::Active, Some(since)) => Ok(Self::Active { since }),
            (ImpersonationStatus::Declined, Some(at)) => Ok(Self::Declined { at }),
            (ImpersonationStatus::Ended, Some(at)) => Ok(Self::Ended { at }),
            (status, _) => Err(DomainError::infra_msg(format!(
                "stored {} support impersonation has a time that contradicts it",
                status.as_str()
            ))),
        }
    }

    /// When its status began, unless it still awaits consent. Storage keeps
    /// it this way.
    #[must_use]
    pub fn since(self) -> Option<OffsetDateTime> {
        match self {
            Self::AwaitingConsent => None,
            Self::Active { since } => Some(since),
            Self::Declined { at } | Self::Ended { at } => Some(at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Four minutes and sixty-one are refused; five and sixty are the
    /// bounds.
    #[test]
    fn a_window_is_from_five_minutes_to_an_hour() {
        assert!(ImpersonationWindow::minutes(4).is_err());
        assert!(ImpersonationWindow::minutes(61).is_err());
        assert_eq!(
            ImpersonationWindow::minutes(60).unwrap().as_duration(),
            Duration::hours(1)
        );
        assert!(ImpersonationWindow::minutes(5).is_ok());
    }

    /// Declined and ended requests reject every subsequent status transition.
    #[test]
    fn a_declined_or_ended_request_stays_so() {
        for from in [ImpersonationStatus::Declined, ImpersonationStatus::Ended] {
            for to in [
                ImpersonationStatus::AwaitingConsent,
                ImpersonationStatus::Active,
                ImpersonationStatus::Declined,
                ImpersonationStatus::Ended,
            ] {
                assert!(from.try_transition(to).is_err(), "{from:?} to {to:?}");
            }
        }
    }

    /// A request awaiting consent with a start time is refused when read
    /// back, and so is an active one without one.
    #[test]
    fn a_stored_state_is_read_only_with_the_time_it_has() {
        let now = crate::shared::clock::now();

        assert!(
            ImpersonationState::from_stored(ImpersonationStatus::AwaitingConsent, Some(now))
                .is_err()
        );
        assert!(ImpersonationState::from_stored(ImpersonationStatus::Active, None).is_err());
        assert_eq!(
            ImpersonationState::from_stored(ImpersonationStatus::Active, Some(now)).unwrap(),
            ImpersonationState::Active { since: now }
        );
    }
}
