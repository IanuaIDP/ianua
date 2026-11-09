/// Operational status of a tenant route.
///
/// Allowed moves:
/// - `Active` to `Disabled`: an admin disables it, and the proxy stops
///   matching it.
/// - `Disabled` to `Active`: an admin turns it back on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RouteStatus {
    /// Route is active and accepting traffic.
    Active,
    /// Route is disabled. The proxy does not match it, so callers get a 404.
    Disabled,
}

/// A route status move that is not allowed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a route from {from:?} to {to:?}")]
pub struct InvalidRouteTransition {
    /// The current state.
    pub from: RouteStatus,
    /// The attempted target state.
    pub to: RouteStatus,
}

impl RouteStatus {
    /// Moves to `to`, when [`RouteStatus`] lists that move.
    ///
    /// # Errors
    ///
    /// - [`InvalidRouteTransition`] when the move is not one listed, such as
    ///   to the status the route already has.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidRouteTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Active, Self::Disabled) | (Self::Disabled, Self::Active)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidRouteTransition { from: self, to })
        }
    }

    /// Whether this route is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidRouteTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// An active route reads as active and a disabled one does not. The proxy
    /// asks this before matching, so switched-off traffic is never forwarded.
    #[test]
    fn only_the_active_state_reads_as_active() {
        assert!(RouteStatus::Active.is_active());
        assert!(!RouteStatus::Disabled.is_active());
    }

    /// An admin disables an active route. The move is allowed.
    #[test]
    fn active_to_disabled() {
        assert!(
            RouteStatus::Active
                .try_transition(RouteStatus::Disabled)
                .is_ok()
        );
    }

    /// An admin turns a disabled route back on. The move is allowed.
    #[test]
    fn disabled_to_active() {
        assert!(
            RouteStatus::Disabled
                .try_transition(RouteStatus::Active)
                .is_ok()
        );
    }

    /// An admin activates an active route, or disables a disabled one. Both
    /// moves are refused.
    #[test]
    fn no_self_transitions() {
        assert!(
            RouteStatus::Active
                .try_transition(RouteStatus::Active)
                .is_err()
        );
        assert!(
            RouteStatus::Disabled
                .try_transition(RouteStatus::Disabled)
                .is_err()
        );
    }

    /// Each status is written to JSON as `"Active"` or `"Disabled"` and read
    /// back from it. A renamed variant fails here before it breaks saved
    /// routes.
    #[cfg(feature = "serde")]
    #[test]
    fn route_status_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&RouteStatus::Active).unwrap(),
            r#""Active""#
        );
        assert_eq!(
            serde_json::to_string(&RouteStatus::Disabled).unwrap(),
            r#""Disabled""#
        );
        assert_eq!(
            serde_json::from_str::<RouteStatus>(r#""Active""#).unwrap(),
            RouteStatus::Active
        );
        assert_eq!(
            serde_json::from_str::<RouteStatus>(r#""Disabled""#).unwrap(),
            RouteStatus::Disabled
        );
    }

    /// Activating an active route is refused and the refusal becomes a
    /// domain error. It keeps the message "cannot move a route from Active
    /// to Active", which is what the caller is told.
    #[test]
    fn a_status_refusal_becomes_an_invalid_transition_keeping_its_message() {
        let refusal = RouteStatus::Active
            .try_transition(RouteStatus::Active)
            .unwrap_err();
        let message = refusal.to_string();

        let error = crate::shared::errors::DomainError::from(refusal);

        assert!(matches!(
            error,
            crate::shared::errors::DomainError::InvalidTransition(m) if m.as_str() == message
        ));
        assert_eq!(message, "cannot move a route from Active to Active");
    }
}
