//! Services: the backends a tenant's routes forward to.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::routing::backend::assertion::AssertionAudienceClaim;
use crate::domains::routing::backend::health_check::HealthCheckPolicy;
use crate::domains::routing::backend::upstream::Upstream;
use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::events::{
    AppSignInChanged, ServiceCreated, ServiceDeleted, ServiceUpdated,
};
use crate::domains::routing::route::Route;
use crate::domains::routing::route_status::RouteStatus;
use crate::domains::routing::sign_in::accepted::AcceptedSignIn;
use crate::domains::routing::sign_in::app::AppSignIn;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::event_type::RoutingEvent;
use crate::types::{Label, ServiceId, Setting};

/// A backend, named once and forwarded to by any number of routes.
///
/// Tenant-scoped: read and written only through stores opened for the
/// resolved tenant (see [`crate::isolation`]).
///
/// The backend's address, timeout, pinned audience and client-cert need live
/// here once. Twenty routes to one backend share one copy, and one view of
/// whether it is healthy.
///
/// A service holds no path, method or policy. Those stay on the route,
/// because two routes to the same backend often need different ones. A
/// public read and an admin delete use the same service but expose very
/// different things.
///
/// Every change needs the routing right, held by a person signed in to the
/// tenant, so an agent never makes one. Without this rule, Sam points the
/// service at his own server, and every request on its routes goes there
/// with the caller's signed identity.
#[derive(Debug, Clone)]
pub struct Service<T: TenantScope> {
    id: ServiceId,
    name: Label,
    upstream: Upstream,
    health_check: HealthCheckPolicy,
    app_sign_in: Setting<AppSignIn>,
    accepted_sign_in: Setting<AcceptedSignIn>,
    status: RouteStatus,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// What a new service is created with.
pub struct CreateServiceParams {
    /// The id the service is kept under, chosen before it is made so its
    /// upstream's client key can be sealed for it.
    pub id: ServiceId,
    /// Service name, shown in the dashboard and unique within the tenant.
    pub name: Label,
    /// Where requests go, and how they are addressed.
    pub upstream: Upstream,
    /// How its backends are probed.
    pub health_check: HealthCheckPolicy,
}

/// A [`Service`] as storage holds it, read back through
/// [`Service::reconstitute`].
pub struct ServiceRow {
    /// The service's id.
    pub id: ServiceId,
    /// Service name, unique within the tenant.
    pub name: Label,
    /// Where requests go, and how they are addressed.
    pub upstream: Upstream,
    /// How the service's backends are probed.
    pub health_check: HealthCheckPolicy,
    /// How people sign in on the service's hosts, if the gateway answers
    /// sign-in addresses for it.
    pub app_sign_in: Setting<AppSignIn>,
    /// Whose app sign-in the service accepts and how it reaches it, if any.
    pub accepted_sign_in: Setting<AcceptedSignIn>,
    /// Whether the service is accepting traffic.
    pub status: RouteStatus,
    /// When the service was created.
    pub created_at: OffsetDateTime,
    /// When the service last changed.
    pub updated_at: OffsetDateTime,
}

impl<T: TenantScope> Service<T> {
    /// Creates a new active service, on behalf of `by`. Raises
    /// `routing.service_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not create routing.
    /// - [`DomainError::Validation`] when the upstream's settings contradict
    ///   each other, as [`Upstream::ensure_consistent`] says.
    pub fn create(
        params: CreateServiceParams,
        by: &RoutingControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(RoutingRight::Create)?;
        params.upstream.ensure_consistent()?;
        let now = crate::shared::clock::now();
        let mut service = Self {
            id: params.id,
            name: params.name,
            upstream: params.upstream,
            health_check: params.health_check,
            app_sign_in: Setting::Unset,
            accepted_sign_in: Setting::Unset,
            status: RouteStatus::Active,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        service.raised.raise(ServiceCreated {
            service_id: service.id,
            name: service.name.clone(),
            occurred_at: now,
        });
        Ok(service)
    }

    /// Rebuilds a service from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row has its own app sign-in
    ///   and accepts another's.
    /// - [`DomainError::Infrastructure`] when it has sign-in without the
    ///   audience it needs.
    /// - [`DomainError::Infrastructure`] when it accepts its own sign-in as
    ///   another's.
    /// - [`DomainError::Infrastructure`] when its upstream's settings
    ///   contradict each other.
    /// - [`DomainError::Infrastructure`] when it changed before it was created.
    pub fn reconstitute(row: ServiceRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            upstream: row.upstream,
            health_check: row.health_check,
            app_sign_in: row.app_sign_in,
            accepted_sign_in: row.accepted_sign_in,
            status: row.status,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &ServiceRow) -> Result<(), DomainError> {
        RowCheck::of("service")
            .holds(
                sign_in_fits(row),
                "sign-in settings that contradict each other or its upstream",
            )
            .holds(
                row.upstream.ensure_consistent().is_ok(),
                "upstream settings that contradict each other",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The service's id.
    #[must_use]
    pub fn id(&self) -> &ServiceId {
        &self.id
    }

    /// Service name, unique within the tenant.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Where requests go, and how they are addressed.
    #[must_use]
    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// How this service's backends are probed.
    #[must_use]
    pub fn health_check(&self) -> &HealthCheckPolicy {
        &self.health_check
    }

    /// The `aud` the gateway's signed assertion carries on requests to this
    /// service, so an assertion sent here is refused by any other service.
    #[must_use]
    pub fn assertion_audience(&self) -> AssertionAudienceClaim<'_> {
        AssertionAudienceClaim::of(&self.id, self.upstream.assertion_audience())
    }

    /// How people sign in on the hosts this service is served on, if the
    /// gateway answers sign-in addresses for it.
    #[must_use]
    pub fn app_sign_in(&self) -> Option<&AppSignIn> {
        self.app_sign_in.value()
    }

    /// The service whose app sign-in this one also accepts, if any.
    #[must_use]
    pub fn accepts_app_sign_in_of(&self) -> Option<&ServiceId> {
        self.accepted_sign_in.value().map(AcceptedSignIn::owner)
    }

    /// Whose app sign-in this service accepts and how it reaches it, if any.
    #[must_use]
    pub fn accepted_sign_in(&self) -> Option<&AcceptedSignIn> {
        self.accepted_sign_in.value()
    }

    /// Whether this service is accepting traffic.
    #[must_use]
    pub fn status(&self) -> RouteStatus {
        self.status
    }

    /// Whether this service is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == RouteStatus::Active
    }

    /// When this service was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this service last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Replaces the upstream.
    ///
    /// Every route pointing at this service takes the change at once. A route
    /// that needs sign-in relies on this upstream pinning an audience.
    /// `routes` are every route forwarding to this service, and each must
    /// still work with the new upstream. A list holding another service's
    /// route is refused, so the check cannot be skipped by passing routes
    /// that never reach here.
    ///
    /// Raises `routing.service_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] without routing update rights, or
    /// [`DomainError::Conflict`] for a route forwarding to another service.
    /// Returns [`DomainError::Validation`] for inconsistent upstream settings or no
    /// audience when app sign-in, accepted external sign-in issuing this service's
    /// sessions or tokens, or a route requiring sign-in needs one.
    pub fn replace_upstream(
        &mut self,
        upstream: Upstream,
        routes: &[Route<T>],
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.ensure_own(routes)?;
        upstream.ensure_consistent()?;
        if self.needs_audience() && upstream.expected_audience().is_none() {
            return Err(audience_required());
        }
        routes
            .iter()
            .try_for_each(|route| route.ensure_served_by(&upstream))?;
        self.upstream = upstream;
        self.record_update();
        Ok(())
    }

    /// Turns app sign-in on with `app_sign_in`, or off when unset.
    ///
    /// The session a person gets by signing in names this service's audience.
    /// So a service without one cannot hand any out.
    ///
    /// Raises `routing.app_sign_in_changed` with the hosts sign-in answers
    /// on afterwards, once for all the sign-in changes made before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] if turned on while the upstream pins no
    ///   audience.
    /// - [`DomainError::Validation`] if turned on while this service accepts
    ///   another's app sign-in.
    pub fn change_app_sign_in(
        &mut self,
        app_sign_in: Setting<AppSignIn>,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        let turning_on = !app_sign_in.is_unset();
        if turning_on && self.upstream.expected_audience().is_none() {
            return Err(audience_required());
        }
        if turning_on && !self.accepted_sign_in.is_unset() {
            return Err(own_or_borrowed());
        }
        self.app_sign_in = app_sign_in;
        self.sign_in_changed();
        Ok(())
    }

    /// Accepts another service's app sign-in as `accepted` says, or stops
    /// accepting one when it is unset.
    ///
    /// A person signed in on a host holds a session for the service whose
    /// sign-in they used. Another service accepts it only when told to here.
    /// So turning on app sign-in for one app never opens a second one too.
    ///
    /// Raises `routing.app_sign_in_changed` with the hosts sign-in answers
    /// on afterwards, once for all the sign-in changes made before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] if the owner is this service.
    /// - [`DomainError::Validation`] if this service has app sign-in of its
    ///   own.
    /// - [`DomainError::Validation`] if the sign-in reaches it with sessions
    ///   or tokens for its own audience, and it pins none.
    pub fn accept_app_sign_in_of(
        &mut self,
        accepted: Setting<AcceptedSignIn>,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        let Setting::Set(accepted) = accepted else {
            self.accepted_sign_in = Setting::Unset;
            self.sign_in_changed();
            return Ok(());
        };
        if *accepted.owner() == self.id {
            return Err(DomainError::invalid(message!(
                "routing-a-service-cannot-accept-its-own",
                "a service cannot accept its own app sign-in as another's"
            )));
        }
        if !self.app_sign_in.is_unset() {
            return Err(own_or_borrowed());
        }
        if accepted.needs_own_audience() && self.upstream.expected_audience().is_none() {
            return Err(audience_required());
        }
        self.accepted_sign_in = Setting::Set(accepted);
        self.sign_in_changed();
        Ok(())
    }

    /// Whether sessions or tokens are made for this service's own audience.
    fn needs_audience(&self) -> bool {
        !self.app_sign_in.is_unset()
            || self
                .accepted_sign_in
                .value()
                .is_some_and(AcceptedSignIn::needs_own_audience)
    }

    /// Replaces how the backends are probed.
    ///
    /// Raises `routing.service_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn change_health_check(
        &mut self,
        health_check: HealthCheckPolicy,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.health_check = health_check;
        self.record_update();
        Ok(())
    }

    /// Renames the service.
    ///
    /// Raises `routing.service_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn rename(&mut self, name: Label, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.name = name;
        self.record_update();
        Ok(())
    }

    /// Enables the service.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] if already active.
    pub fn activate(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.status = self.status.try_transition(RouteStatus::Active)?;
        self.touch();
        Ok(())
    }

    /// Disables the service. Routes pointing at it stop being served.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] if already disabled.
    pub fn disable(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.status = self.status.try_transition(RouteStatus::Disabled)?;
        self.touch();
        Ok(())
    }

    /// Deletes this service once `by` may delete routing, no route forwards
    /// to it, and no other service accepts its app sign-in. Raises
    /// `routing.service_deleted`, taken once the service is removed from
    /// storage.
    ///
    /// `routes` are every route that forwards to this service, and
    /// `accepting` every service that accepts its app sign-in, as stored. The
    /// caller passes all of them. Deleting a service a route still forwards
    /// to would leave the route with no backend, or delete the live route
    /// along with it. Deleting one whose sign-in another accepts would leave
    /// that one trusting sessions nothing can issue or end.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete routing.
    /// - [`DomainError::Conflict`] if a route in `routes` forwards to another
    ///   service.
    /// - [`DomainError::Conflict`] if a route still forwards to this service.
    /// - [`DomainError::Conflict`] if a service in `accepting` accepts
    ///   another service's sign-in.
    /// - [`DomainError::Conflict`] if another service still accepts this
    ///   one's app sign-in.
    pub fn delete(
        &mut self,
        routes: &[Route<T>],
        accepting: &[Service<T>],
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Delete)?;
        self.ensure_own(routes)?;
        if accepting
            .iter()
            .any(|other| other.accepts_app_sign_in_of() != Some(&self.id))
        {
            return Err(DomainError::conflict(message!(
                "routing-a-service-given-as-accepting-this",
                "a service given as accepting this one's sign-in accepts another's"
            )));
        }
        if !routes.is_empty() {
            return Err(DomainError::conflict(message!(
                "routing-routes-still-forward-to-this-service",
                "routes still forward to this service, so it cannot be deleted"
            )));
        }
        if !accepting.is_empty() {
            return Err(DomainError::conflict(message!(
                "routing-another-service-still-accepts-this-service",
                "another service still accepts this service's app sign-in"
            )));
        }
        self.raised.raise(ServiceDeleted {
            service_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Refuses `routes` unless every one forwards to this service.
    fn ensure_own(&self, routes: &[Route<T>]) -> Result<(), DomainError> {
        if routes.iter().any(|route| *route.service_id() != self.id) {
            return Err(DomainError::conflict(message!(
                "routing-a-route-given-for-this-service",
                "a route given for this service forwards to another one"
            )));
        }
        Ok(())
    }

    /// Sets `updated_at` to now.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }

    /// Whether the service is new and not yet saved. What it is set up with
    /// before its first save is part of its creation and raises nothing
    /// more.
    fn is_unsaved(&self) -> bool {
        self.raised.holds(RoutingEvent::ServiceCreated.into())
    }

    /// Marks a change to the service's name, upstream or health checks,
    /// raising `routing.service_updated` with the service as it now is.
    fn record_update(&mut self) {
        self.touch();
        if self.is_unsaved() {
            return;
        }
        self.raised.raise_latest(ServiceUpdated {
            service_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
    }

    /// Marks a change to how people sign in on the service, raising
    /// `routing.app_sign_in_changed` with the hosts its sign-in now answers
    /// on.
    fn sign_in_changed(&mut self) {
        self.touch();
        if self.is_unsaved() {
            return;
        }
        self.raised.raise_latest(AppSignInChanged {
            service_id: self.id,
            name: self.name.clone(),
            hosts: self
                .app_sign_in
                .value()
                .map(|sign_in| sign_in.hosts().to_vec())
                .unwrap_or_default(),
            occurred_at: self.updated_at,
        });
    }
}

impl<T: TenantScope> Raises for Service<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

fn audience_required() -> DomainError {
    DomainError::invalid(message!(
        "routing-a-service-with-app-sign-in",
        "a service with app sign-in, or reached by its own cookie or tokens, must pin an \
         expected JWT audience"
    ))
}

fn own_or_borrowed() -> DomainError {
    DomainError::invalid(message!(
        "routing-a-service-either-has-app-sign",
        "a service either has app sign-in of its own or accepts another's, not both"
    ))
}

impl<T: TenantScope> Aggregate for Service<T> {
    type Id = ServiceId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Whether a stored service's sign-in settings agree:
/// - It has its own app sign-in or accepts another's, never both.
/// - Its own needs a pinned audience.
/// - Another's must come from a different service, and needs a pinned
///   audience when sessions or tokens are made for this one.
fn sign_in_fits(row: &ServiceRow) -> bool {
    let pins_audience = row.upstream.expected_audience().is_some();
    match (&row.app_sign_in, &row.accepted_sign_in) {
        (Setting::Set(_), Setting::Set(_)) => false,
        (Setting::Set(_), Setting::Unset) => pins_audience,
        (Setting::Unset, Setting::Set(accepted)) => {
            *accepted.owner() != row.id && (pins_audience || !accepted.needs_own_audience())
        }
        (Setting::Unset, Setting::Unset) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::routing::backend::tls::{UpstreamTls, UpstreamTlsParams, UpstreamTrust};
    use crate::domains::routing::backend::upstream::{HostHeader, UpstreamTimeout};
    use crate::domains::routing::fixtures::{
        plain_pipeline, routing_admin, routing_editor, routing_viewer,
    };
    use crate::domains::routing::matching::host::RouteHosts;
    use crate::domains::routing::matching::path_rewrite::PathRewrite;
    use crate::domains::routing::policy::RoutePolicy;
    use crate::domains::routing::route::CreateRouteParams;
    use crate::domains::routing::sign_in::accepted::SignInDelivery;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{HttpUrl, Seconds, Setting};

    fn params() -> CreateServiceParams {
        CreateServiceParams {
            id: ServiceId::new(),
            name: Label::new("name", "projects-api").unwrap(),
            upstream: Upstream::new(
                HttpUrl::new("https://projects.internal:8080").unwrap(),
                UpstreamTimeout::DEFAULT,
                HostHeader::Rewrite,
            ),
            health_check: HealthCheckPolicy::default(),
        }
    }

    fn service() -> Service<ResolvedTenant> {
        Service::create(params(), &routing_admin()).unwrap()
    }

    /// A viewer cannot replace the upstream, clear app sign-in or disable
    /// the service. Its pinned audience and active status remain.
    #[test]
    fn a_viewer_cannot_repoint_or_switch_off_a_service() {
        let mut service = service();
        service
            .replace_upstream(pinned(), &[], &routing_admin())
            .unwrap();

        let upstream = service.replace_upstream(unpinned(), &[], &routing_viewer());
        let sign_in = service.change_app_sign_in(Setting::Unset, &routing_viewer());
        let disabled = service.disable(&routing_viewer());

        assert!(matches!(upstream, Err(DomainError::Forbidden(_))));
        assert!(matches!(sign_in, Err(DomainError::Forbidden(_))));
        assert!(matches!(disabled, Err(DomainError::Forbidden(_))));
        assert!(service.upstream().expected_audience().is_some());
        assert!(service.is_active());
    }

    /// A viewer cannot change accepted sign-in or health checks, rename the
    /// service or activate it. It remains disabled with health checks and
    /// no accepted sign-in.
    #[test]
    fn a_viewer_cannot_edit_a_service() {
        let mut service = service();
        service.disable(&routing_admin()).unwrap();
        let accepted = Setting::Set(AcceptedSignIn::new(
            ServiceId::new(),
            SignInDelivery::SameHost,
        ));

        let borrowed = service.accept_app_sign_in_of(accepted, &routing_viewer());
        let health = service.change_health_check(HealthCheckPolicy::Disabled, &routing_viewer());
        let renamed = service.rename(Label::new("name", "mine").unwrap(), &routing_viewer());
        let activated = service.activate(&routing_viewer());

        for result in [borrowed, health, renamed, activated] {
            assert!(matches!(result, Err(DomainError::Forbidden(_))));
        }
        assert!(service.accepts_app_sign_in_of().is_none());
        assert!(service.health_check().active().is_some());
        assert!(!service.is_active());
    }

    /// Routing update permission alone cannot create a service.
    #[test]
    fn creating_a_service_needs_the_create_right() {
        let created = Service::<ResolvedTenant>::create(params(), &routing_editor());

        assert!(matches!(created, Err(DomainError::Forbidden(_))));
    }

    /// A plain HTTP upstream with explicit TLS settings is invalid both
    /// when creating a service and when replacing its upstream.
    #[test]
    fn a_service_refuses_an_upstream_whose_settings_contradict() {
        let tls = UpstreamTls::new(UpstreamTlsParams {
            trust: UpstreamTrust::PublicRoots,
            client_certificate: Setting::Unset,
            server_name: Setting::Unset,
        })
        .unwrap();
        let in_the_clear = Upstream::new(
            HttpUrl::new("http://projects.internal:8080").unwrap(),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
        .with_tls(tls);
        let mut service = service();

        let created = Service::<ResolvedTenant>::create(
            CreateServiceParams {
                upstream: in_the_clear.clone(),
                ..params()
            },
            &routing_admin(),
        );
        let replaced = service.replace_upstream(in_the_clear, &[], &routing_admin());

        assert!(matches!(created, Err(DomainError::Validation(_))));
        assert!(matches!(replaced, Err(DomainError::Validation(_))));
    }

    /// Two services' assertions name two different audiences, each the
    /// service's own id, so one's assertion is no good at the other.
    #[test]
    fn each_service_names_itself_in_its_assertions() {
        let (projects, billing) = (service(), service());

        assert_ne!(
            projects.assertion_audience().to_string(),
            billing.assertion_audience().to_string()
        );
    }

    /// A tenant creates "projects-api". It starts active, keeps its name and
    /// has health checks on by default.
    #[test]
    fn create_produces_an_active_service() {
        let service = service();

        assert!(service.is_active());
        assert_eq!(service.name().as_str(), "projects-api");
        assert!(service.health_check().active().is_some());
    }

    /// Fay may delete routing and deletes a service no route forwards to. It
    /// is allowed.
    #[test]
    fn a_service_no_route_forwards_to_may_be_deleted() {
        let mut service = service();

        assert!(service.delete(&[], &[], &routing_admin()).is_ok());
    }

    /// An editor cannot delete a service even when no dependants are supplied.
    #[test]
    fn deleting_a_service_needs_the_delete_right() {
        let mut service = service();

        let deleted = service.delete(&[], &[], &routing_editor());

        assert!(matches!(deleted, Err(DomainError::Forbidden(_))));
    }

    /// Deleting a service conflicts while a route still forwards to it.
    #[test]
    fn a_service_a_route_forwards_to_is_not_deleted() {
        let mut service = service();
        let routes = [route_to(&service, RoutePolicy::Public)];

        let deleted = service.delete(&routes, &[], &routing_admin());

        assert!(matches!(deleted, Err(DomainError::Conflict(_))));
    }

    /// Deletion rejects a dependency list containing another service's route.
    #[test]
    fn deleting_a_service_refuses_another_services_routes() {
        let other = service();
        let unrelated = [route_to(&other, RoutePolicy::Public)];
        let mut service = service();

        let deleted = service.delete(&unrelated, &[], &routing_admin());

        assert!(matches!(deleted, Err(DomainError::Conflict(_))));
    }

    /// Deleting a sign-in owner conflicts while another service accepts it.
    /// Supplying an unrelated service as an accepting dependant also conflicts.
    #[test]
    fn a_service_whose_sign_in_another_accepts_is_not_deleted() {
        let mut portal = service();
        let mut admin_api = service();
        admin_api
            .replace_upstream(pinned(), &[], &routing_admin())
            .unwrap();
        admin_api
            .accept_app_sign_in_of(
                Setting::Set(AcceptedSignIn::new(*portal.id(), SignInDelivery::SameHost)),
                &routing_admin(),
            )
            .unwrap();
        let unrelated = service();

        let deleted = portal.delete(&[], std::slice::from_ref(&admin_api), &routing_admin());
        let wrong_list = portal.delete(&[], std::slice::from_ref(&unrelated), &routing_admin());

        assert!(matches!(deleted, Err(DomainError::Conflict(_))));
        assert!(matches!(wrong_list, Err(DomainError::Conflict(_))));
    }

    /// An admin disables a service and then turns it back on. Each change
    /// shows in whether it is active.
    #[test]
    fn disable_and_reactivate() {
        let mut service = service();

        service.disable(&routing_admin()).unwrap();
        assert!(!service.is_active());

        service.activate(&routing_admin()).unwrap();
        assert!(service.is_active());
    }

    /// An admin points the service at `projects-v2` with a 15 second timeout.
    /// The service holds the new address and timeout, so every route using
    /// it changes in one edit.
    #[test]
    fn the_upstream_is_replaced_in_one_place() {
        let mut service = service();

        service
            .replace_upstream(
                Upstream::new(
                    HttpUrl::new("https://projects-v2.internal:8080").unwrap(),
                    UpstreamTimeout::seconds(15).unwrap(),
                    HostHeader::Preserve,
                ),
                &[],
                &routing_admin(),
            )
            .unwrap();

        assert_eq!(
            service.upstream().url().as_str(),
            "https://projects-v2.internal:8080"
        );
        assert_eq!(service.upstream().timeout_secs(), Seconds::new(15));
    }

    fn pinned() -> Upstream {
        Upstream::new(
            HttpUrl::new("https://projects.internal:8080").unwrap(),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
        .with_audience(crate::types::Audience::new("projects").unwrap())
    }

    fn unpinned() -> Upstream {
        service().upstream.clone()
    }

    fn route_to(service: &Service<ResolvedTenant>, policy: RoutePolicy) -> Route<ResolvedTenant> {
        Route::create(
            CreateRouteParams {
                name: Label::new("name", "projects").unwrap(),
                path_pattern: crate::types::UrlPath::new("/projects/*").unwrap(),
                methods: Vec::new(),
                policy,
                hosts: RouteHosts::Any,
                path_rewrite: PathRewrite::StripPrefix,
                priority: 100,
            },
            service,
            &plain_pipeline(),
            &routing_admin(),
        )
        .unwrap()
    }

    /// A service used by an authenticated route cannot drop its audience.
    /// The refused upstream replacement leaves an audience pinned.
    #[test]
    fn the_audience_cannot_be_dropped_while_a_signed_in_route_uses_the_service() {
        let mut service = service();
        service
            .replace_upstream(pinned(), &[], &routing_admin())
            .unwrap();
        let routes = [route_to(&service, RoutePolicy::Authenticated)];

        let dropped = service.replace_upstream(unpinned(), &routes, &routing_admin());

        assert!(matches!(dropped, Err(DomainError::Validation(_))));
        assert!(service.upstream().expected_audience().is_some());
    }

    /// The service serves only a public route. Dropping its audience is
    /// allowed.
    #[test]
    fn a_service_serving_only_public_routes_may_drop_its_audience() {
        let mut service = service();
        service
            .replace_upstream(pinned(), &[], &routing_admin())
            .unwrap();
        let routes = [route_to(&service, RoutePolicy::Public)];

        assert!(
            service
                .replace_upstream(unpinned(), &routes, &routing_admin())
                .is_ok()
        );
    }

    /// Upstream replacement conflicts when its supplied route belongs to
    /// another service.
    #[test]
    fn replacing_the_upstream_refuses_another_services_routes() {
        let mut service = service();
        let other = Service::<ResolvedTenant>::create(
            CreateServiceParams {
                id: ServiceId::new(),
                name: Label::new("name", "billing").unwrap(),
                upstream: pinned(),
                health_check: HealthCheckPolicy::default(),
            },
            &routing_admin(),
        )
        .unwrap();
        let routes = [route_to(&other, RoutePolicy::Public)];

        let replaced = service.replace_upstream(unpinned(), &routes, &routing_admin());

        assert!(matches!(replaced, Err(DomainError::Conflict(_))));
    }

    /// An admin turns health checks off for a service. It then has no
    /// active probe.
    #[test]
    fn health_checking_can_be_turned_off() {
        let mut service = service();

        service
            .change_health_check(HealthCheckPolicy::Disabled, &routing_admin())
            .unwrap();

        assert!(service.health_check().active().is_none());
    }

    /// An admin renames the service five minutes after creating it. Its
    /// update time moves to then and its creation time stays, so caches see
    /// the change.
    #[test]
    fn mutations_move_the_timestamp() {
        let mut service = service();
        let before = service.updated_at();
        let later = before + time::Duration::minutes(5);

        let _frozen = crate::shared::clock::freeze(later);
        service
            .rename(Label::new("name", "renamed").unwrap(), &routing_admin())
            .unwrap();

        assert_eq!(service.updated_at(), later);
        assert_eq!(service.created_at(), before);
        assert_eq!(service.name().as_str(), "renamed");
    }

    mod app_sign_in {
        use super::*;
        use crate::domains::routing::sign_in::accepted::{CookieHosts, SignInDelivery};
        use crate::domains::routing::sign_in::app::{AppSignInParams, SignedOutBrowsers};
        use crate::types::DomainName;

        fn sign_in() -> AppSignIn {
            AppSignIn::new(AppSignInParams {
                hosts: vec![DomainName::new("app.example.com").unwrap()],
                prefix: Setting::Unset,
                moved: std::collections::BTreeMap::new(),
                after_sign_in: Setting::Unset,
                signed_out_browsers: SignedOutBrowsers::Refuse,
            })
            .unwrap()
        }

        fn signing_in() -> Service<ResolvedTenant> {
            let mut service = service();
            service
                .replace_upstream(pinned(), &[], &routing_admin())
                .unwrap();
            service
                .change_app_sign_in(Setting::Set(sign_in()), &routing_admin())
                .unwrap();
            service
        }

        fn stored(service: &Service<ResolvedTenant>) -> ServiceRow {
            ServiceRow {
                id: service.id,
                name: service.name.clone(),
                upstream: service.upstream.clone(),
                health_check: service.health_check.clone(),
                app_sign_in: service.app_sign_in.clone(),
                accepted_sign_in: service.accepted_sign_in.clone(),
                status: service.status,
                created_at: service.created_at,
                updated_at: service.updated_at,
            }
        }

        /// One stored service has app sign-in but no audience. Another both
        /// has its own sign-in and accepts another's. Both are refused as
        /// corrupt rows, while a valid one reads back.
        #[test]
        fn a_stored_service_with_contradicting_sign_in_is_refused() {
            let mut no_audience = stored(&signing_in());
            no_audience.upstream = service().upstream.clone();
            let mut both = stored(&signing_in());
            both.accepted_sign_in = accepting(ServiceId::new(), own_cookie());

            assert!(Service::<ResolvedTenant>::reconstitute(stored(&signing_in())).is_ok());
            for row in [no_audience, both] {
                assert!(crate::shared::model::row_check::refused_as_corrupt(
                    &Service::<ResolvedTenant>::reconstitute(row)
                ));
            }
        }

        /// An admin turns on app sign-in for a service that pins no
        /// audience. It is refused, since the session would name no audience.
        #[test]
        fn app_sign_in_needs_a_pinned_audience() {
            let mut service = service();

            assert!(
                service
                    .change_app_sign_in(Setting::Set(sign_in()), &routing_admin())
                    .is_err()
            );
            assert!(service.app_sign_in().is_none());
        }

        /// A service with app sign-in refuses an upstream without an audience
        /// and retains its pinned audience.
        #[test]
        fn the_audience_cannot_be_dropped_while_app_sign_in_is_on() {
            let mut service = signing_in();

            let dropped = service.replace_upstream(unpinned(), &[], &routing_admin());

            assert!(dropped.is_err());
            assert!(service.upstream().expected_audience().is_some());
        }

        /// An admin turns app sign-in off. The service then has none.
        #[test]
        fn app_sign_in_can_be_turned_off() {
            let mut service = signing_in();

            service
                .change_app_sign_in(Setting::Unset, &routing_admin())
                .unwrap();

            assert!(service.app_sign_in().is_none());
        }

        fn accepting(owner: ServiceId, delivery: SignInDelivery) -> Setting<AcceptedSignIn> {
            Setting::Set(AcceptedSignIn::new(owner, delivery))
        }

        fn own_cookie() -> SignInDelivery {
            SignInDelivery::OwnCookie(
                CookieHosts::new(vec![DomainName::new("api.example.com").unwrap()]).unwrap(),
            )
        }

        /// A service with its own sign-in cannot accept another's. A service
        /// that accepts another's cannot turn on its own.
        #[test]
        fn a_service_cannot_both_own_and_borrow_app_sign_in() {
            let mut owner = signing_in();
            assert!(
                owner
                    .accept_app_sign_in_of(
                        accepting(ServiceId::new(), SignInDelivery::SameHost),
                        &routing_admin(),
                    )
                    .is_err()
            );

            let mut borrower = service();
            borrower
                .replace_upstream(pinned(), &[], &routing_admin())
                .unwrap();
            borrower
                .accept_app_sign_in_of(
                    accepting(*owner.id(), SignInDelivery::SameHost),
                    &routing_admin(),
                )
                .unwrap();
            assert!(
                borrower
                    .change_app_sign_in(Setting::Set(sign_in()), &routing_admin())
                    .is_err()
            );
        }

        /// An admin sets a service to accept the sign-in of itself. It is
        /// refused.
        #[test]
        fn a_service_cannot_accept_its_own_sign_in_as_anothers() {
            let mut service = service();
            let own = *service.id();

            assert!(
                service
                    .accept_app_sign_in_of(
                        accepting(own, SignInDelivery::SameHost),
                        &routing_admin()
                    )
                    .is_err()
            );
        }

        /// A service with no audience accepts another's sign-in through its
        /// own cookie or through tokens. Both are refused, since each names
        /// this service's audience.
        #[test]
        fn a_cookie_or_tokens_of_its_own_need_a_pinned_audience() {
            for delivery in [own_cookie(), SignInDelivery::Tokens] {
                let mut service = service();

                assert!(
                    service
                        .accept_app_sign_in_of(
                            accepting(ServiceId::new(), delivery),
                            &routing_admin()
                        )
                        .is_err()
                );
            }
        }

        /// A service with no audience accepts another's sign-in on the
        /// owner's hosts. That is allowed, since no session names this
        /// service.
        #[test]
        fn on_the_owners_hosts_no_audience_of_its_own_is_needed() {
            let mut service = service();

            assert!(
                service
                    .accept_app_sign_in_of(
                        accepting(ServiceId::new(), SignInDelivery::SameHost),
                        &routing_admin(),
                    )
                    .is_ok()
            );
        }

        /// A service accepts another's sign-in through tokens for its own
        /// audience. Dropping that audience is refused.
        #[test]
        fn the_audience_cannot_be_dropped_while_tokens_are_made_for_it() {
            let mut service = service();
            service
                .replace_upstream(pinned(), &[], &routing_admin())
                .unwrap();
            service
                .accept_app_sign_in_of(
                    accepting(ServiceId::new(), SignInDelivery::Tokens),
                    &routing_admin(),
                )
                .unwrap();

            let dropped = service.replace_upstream(unpinned(), &[], &routing_admin());

            assert!(dropped.is_err());
        }

        /// A service with app sign-in, as it was saved: its creation and
        /// setup taken out.
        fn saved_signing_in() -> Service<ResolvedTenant> {
            let mut service =
                Service::<ResolvedTenant>::reconstitute(stored(&signing_in())).unwrap();
            raised_names(&mut service);
            service
        }

        /// Ann turns app sign-in off on a saved service, which also stops
        /// it accepting another's. One change is raised, with no hosts left.
        #[test]
        fn turning_sign_in_off_raises_one_change_with_no_hosts() {
            let mut service = saved_signing_in();

            service
                .change_app_sign_in(Setting::Unset, &routing_admin())
                .unwrap();
            service
                .accept_app_sign_in_of(Setting::Unset, &routing_admin())
                .unwrap();

            let events = raised(&mut service);
            assert_eq!(events.len(), 1);
            assert_eq!(
                events[0].event_type().to_string(),
                "routing.app_sign_in_changed"
            );
            assert_eq!(
                events[0].payload().value("hosts"),
                Some(&FieldValue::Text(String::new()))
            );
        }

        /// A saved service with app sign-in is read back from storage.
        /// Loading it is no change, so it has raised nothing.
        #[test]
        fn a_service_read_back_from_storage_has_raised_nothing() {
            let mut service =
                Service::<ResolvedTenant>::reconstitute(stored(&signing_in())).unwrap();

            assert!(raised_names(&mut service).is_empty());
        }
    }

    /// "projects-api" as it was saved, its creation taken out.
    fn saved_service() -> Service<ResolvedTenant> {
        let mut service = service();
        raised_names(&mut service);
        service
    }

    /// Ann creates "projects-api" and points it at a pinned upstream before
    /// its first save. Only the creation is raised.
    #[test]
    fn creating_raises_only_routing_service_created() {
        let mut service = service();

        service
            .replace_upstream(pinned(), &[], &routing_admin())
            .unwrap();

        assert_eq!(raised_names(&mut service), ["routing.service_created"]);
    }

    /// Ann renames a saved service and turns its health checks off in one
    /// edit. One update is raised.
    #[test]
    fn several_edits_before_a_save_raise_one_routing_service_updated() {
        let mut service = saved_service();

        service
            .rename(Label::new("name", "projects").unwrap(), &routing_admin())
            .unwrap();
        service
            .change_health_check(HealthCheckPolicy::Disabled, &routing_admin())
            .unwrap();

        assert_eq!(raised_names(&mut service), ["routing.service_updated"]);
    }

    /// Ann deletes a service nothing uses. The deletion is raised.
    #[test]
    fn deleting_raises_routing_service_deleted() {
        let mut service = saved_service();

        service.delete(&[], &[], &routing_admin()).unwrap();

        assert_eq!(raised_names(&mut service), ["routing.service_deleted"]);
    }

    /// An editor's deletion and a viewer's rename fail without raising events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut service = saved_service();

        let deleted = service.delete(&[], &[], &routing_editor());
        let renamed = service.rename(Label::new("name", "mine").unwrap(), &routing_viewer());

        assert!(deleted.is_err());
        assert!(renamed.is_err());
        assert!(raised_names(&mut service).is_empty());
    }

    /// A new service has a real id, and its aggregate id is the same one.
    /// Routes name their service by it.
    #[test]
    fn a_service_carries_its_own_id() {
        let service = service();

        assert_ne!(*service.id().as_uuid(), uuid::Uuid::nil());
        assert_eq!(
            Aggregate::id(&service),
            service.id(),
            "the aggregate identity is the service's own id"
        );
    }
}
