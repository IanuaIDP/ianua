//! Events about who the gateway let in: a signed-in person turned away.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::scoped;
use crate::types::{CorrelationId, EventLabel, RouteId, TenantId, UserId};

/// The gateway turned a signed-in person away from an app.
///
/// Pat opens the payroll app his role does not reach and is refused. A
/// workflow can start from this: tell his manager, or offer him the access
/// request. It names the app, why the gateway refused and the request, so
/// the request's own record can be found. Anonymous refusals are not
/// recorded here: nobody is known to tell.
#[derive(Debug)]
pub struct PersonTurnedAway {
    /// The person refused.
    pub(crate) user_id: UserId,
    /// The route the request matched.
    pub(crate) route_id: RouteId,
    /// The app's name, as its route was named when it refused.
    pub(crate) route_label: EventLabel,
    /// Why it refused, as the request's record names the reason.
    pub(crate) reason: &'static str,
    /// The request that was refused.
    pub(crate) correlation_id: CorrelationId,
    /// When it refused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PersonTurnedAway => crate::types::event_type::ProxyEvent::PersonTurnedAway,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(RefKind::USER, self.user_id.to_string(), self.user_id.to_string()),
            )
            .reference(
                "route",
                Reference::new(
                    RefKind::ROUTE,
                    self.route_id.to_string(),
                    self.route_label.as_str(),
                ),
            )
            .field("reason", self.reason)
            .field("correlation_id", self.correlation_id.to_string())
    }
}

/// What the gateway saw when it turned a person away.
pub struct Refused {
    /// The person refused.
    pub user_id: UserId,
    /// The route the request matched.
    pub route_id: RouteId,
    /// The app's name.
    pub route_label: EventLabel,
    /// Why it refused.
    pub reason: &'static str,
    /// The request that was refused.
    pub correlation_id: CorrelationId,
}

impl PersonTurnedAway {
    /// The record that `tenant_id`'s gateway refused `refused`.
    ///
    /// The gateway sees this in traffic: no aggregate changes, so nothing
    /// raises it.
    #[must_use]
    pub fn observed(tenant_id: TenantId, refused: Refused) -> DomainEvent {
        scoped(
            tenant_id,
            Self {
                user_id: refused.user_id,
                route_id: refused.route_id,
                route_label: refused.route_label,
                reason: refused.reason,
                correlation_id: refused.correlation_id,
                occurred_at: crate::shared::clock::now(),
            },
        )
    }
}
