//! Attack mode: an app checked harder for a while, during an attack.
//!
//! The Orders app turns away thousands of requests in an hour. Ann's
//! workflow, or Ann herself, turns attack mode on for an hour. Until it
//! ends, the gateway checks every request to Orders before the app's own
//! pipeline: an address any tenant's decoys or recon scoring caught is
//! refused, and each address is held to [`ATTACK_REQUESTS_PER_WINDOW`]
//! requests in [`ATTACK_WINDOW_SECONDS`] seconds. It ends on its own, so a
//! forgotten attack mode never keeps people out for good.

use time::{Duration, OffsetDateTime};

use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::events::{RouteAttackModeEnded, RouteAttackModeStarted};
use crate::domains::routing::route::Route;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;

/// The most requests one address may send an app in attack mode within
/// one window.
pub const ATTACK_REQUESTS_PER_WINDOW: u32 = 60;

/// How long one window of that count is, in seconds.
pub const ATTACK_WINDOW_SECONDS: u32 = 60;

/// The fewest minutes attack mode may be turned on for.
pub const SHORTEST_ATTACK_MINUTES: u32 = 5;

/// The most minutes attack mode may be turned on for at once: a day.
pub const LONGEST_ATTACK_MINUTES: u32 = 1_440;

/// Whether an app is in attack mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttackMode {
    /// It is checked as its pipeline says, and no harder.
    #[default]
    Off,
    /// It is checked harder until this moment; then it is off again.
    Until(OffsetDateTime),
}

impl AttackMode {
    /// Whether it is in force at `now`.
    #[must_use]
    pub fn in_force_at(self, now: OffsetDateTime) -> bool {
        matches!(self, Self::Until(until) if now < until)
    }
}

/// How long attack mode is turned on for, in whole minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttackLength(u32);

impl AttackLength {
    /// `minutes` of attack mode.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] outside [`SHORTEST_ATTACK_MINUTES`]
    ///   to [`LONGEST_ATTACK_MINUTES`].
    pub fn minutes(minutes: u32) -> Result<Self, DomainError> {
        validate_range(
            "minutes",
            minutes,
            SHORTEST_ATTACK_MINUTES..=LONGEST_ATTACK_MINUTES,
        )?;
        Ok(Self(minutes))
    }

    /// The length as a span of time.
    #[must_use]
    pub fn span(self) -> Duration {
        Duration::minutes(i64::from(self.0))
    }
}

impl<T: TenantScope> Route<T> {
    /// Whether the route is in attack mode, and until when.
    #[must_use]
    pub fn attack_mode(&self) -> AttackMode {
        self.attack_mode
    }

    /// Checks the route harder for `length` from now, or from now on for
    /// that long when it was in attack mode already. Raises
    /// `routing.route_attack_mode_started`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn start_attack_mode(
        &mut self,
        by: &RoutingControl<'_>,
        length: AttackLength,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        let now = crate::shared::clock::now();
        let until = now.saturating_add(length.span());
        self.attack_mode = AttackMode::Until(until);
        self.touch();
        self.raised.raise(RouteAttackModeStarted {
            route_id: self.id,
            name: self.name.clone(),
            until,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Ends attack mode before its time. Raises
    /// `routing.route_attack_mode_ended`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] when it is not in attack mode.
    pub fn end_attack_mode(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        if !self.attack_mode.in_force_at(crate::shared::clock::now()) {
            return Err(DomainError::invalid_transition(message!(
                "routing-the-route-is-not-in-attack-mode",
                "the route is not in attack mode"
            )));
        }
        self.attack_mode = AttackMode::Off;
        self.touch();
        self.raised.raise(RouteAttackModeEnded {
            route_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }
}
