event_types! {
    /// The events the routing context publishes.
    pub enum RoutingEvent {
        /// A route was created.
        RouteCreated => "routing.route_created",
        /// A route was updated.
        RouteUpdated => "routing.route_updated",
        /// A route was deleted.
        RouteDeleted => "routing.route_deleted",
        /// A route was enabled.
        RouteActivated => "routing.route_activated",
        /// A route was disabled.
        RouteDisabled => "routing.route_disabled",
        /// Workflows may now call a route, as its run's person.
        RouteOpenedToWorkflows => "routing.route_opened_to_workflows",
        /// Workflows may call a route no more.
        RouteClosedToWorkflows => "routing.route_closed_to_workflows",
        /// A route went into attack mode, checked harder until it ends.
        RouteAttackModeStarted => "routing.route_attack_mode_started",
        /// A route's attack mode was ended before its time.
        RouteAttackModeEnded => "routing.route_attack_mode_ended",
        /// A service was created.
        ServiceCreated => "routing.service_created",
        /// A service was updated.
        ServiceUpdated => "routing.service_updated",
        /// A service was deleted.
        ServiceDeleted => "routing.service_deleted",
        /// Where and how people sign in on a service's hosts changed.
        AppSignInChanged => "routing.app_sign_in_changed",
        /// A stream route was created. The proxy now listens on its port.
        StreamRouteCreated => "routing.stream_route_created",
        /// A stream route was updated.
        StreamRouteUpdated => "routing.stream_route_updated",
        /// A stream route was deleted, and its port released.
        StreamRouteDeleted => "routing.stream_route_deleted",
        /// A stream route was enabled. Its port starts accepting connections.
        StreamRouteActivated => "routing.stream_route_activated",
        /// A stream route was disabled. Its port stops accepting connections.
        StreamRouteDisabled => "routing.stream_route_disabled",
        /// Workflows may now reach a stream route, as their run's person,
        /// signing in with the login kept for them.
        StreamRouteOpenedToWorkflows => "routing.stream_route_opened_to_workflows",
        /// Workflows may reach a stream route no more, and its login is
        /// forgotten.
        StreamRouteClosedToWorkflows => "routing.stream_route_closed_to_workflows",
        /// A service was given somewhere it may send traffic.
        EgressPolicyCreated => "routing.egress_policy_created",
        /// Where a service may send traffic changed.
        EgressPolicyUpdated => "routing.egress_policy_updated",
        /// A service may send traffic nowhere any more.
        EgressPolicyDeleted => "routing.egress_policy_deleted",
        /// A configuration document was applied to the gateway.
        GatewayConfigImported => "routing.gateway_config_imported",
        /// A private-network connector was created, awaiting enrollment.
        ConnectorCreated => "routing.connector_created",
        /// A connector's agent enrolled and holds its tunnel.
        ConnectorEnrolled => "routing.connector_enrolled",
        /// What a connector may be asked to dial changed.
        ConnectorUpdated => "routing.connector_updated",
        /// A connector was revoked, and its link is refused.
        ConnectorRevoked => "routing.connector_revoked",
        /// A connector was removed.
        ConnectorDeleted => "routing.connector_deleted",
        /// A connector's agent was given the next day's certificate for the
        /// key it enrolled with.
        ConnectorRenewed => "routing.connector_renewed",
    }
}

impl RoutingEvent {
    /// Whether other members hear about this event.
    ///
    /// Every connector renews its certificate once a day by itself. It goes
    /// in the audit trail but not in colleagues' feeds, or each connector
    /// would fill them with a line a day that nobody did.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(self, Self::ConnectorRenewed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acme's office connector renews its certificate overnight. It is
    /// audited, but no colleague is told.
    #[test]
    fn a_renewal_is_not_notified() {
        assert!(!RoutingEvent::ConnectorRenewed.is_notifiable());
    }

    /// Ann revokes a connector. Colleagues are told.
    #[test]
    fn a_revocation_is_notified() {
        assert!(RoutingEvent::ConnectorRevoked.is_notifiable());
    }
}
