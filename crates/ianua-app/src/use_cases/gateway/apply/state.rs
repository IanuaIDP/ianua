//! What an apply works through: the document, who applies it, and the
//! tenant's services, pipelines and routes as written so far, by name.

use std::collections::HashMap;

use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::domains::proxy::pipeline::{Pipeline, PipelineError};
use ianua_domain::domains::routing::connector::PrivateConnector;
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::egress::{EgressPolicy, ServiceIdentity};
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Label;

use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::limits::ResourceKind;
use crate::services::hosts::PlatformAddresses;
use crate::tenancy::ScopedTenant;
use crate::use_cases::gateway::ImportConfigPorts;
use crate::use_cases::gateway::document::GatewayConfig;
use crate::use_cases::gateway::lookup::LiveGateway;

/// Who applies a document, and through which ports.
#[derive(Clone, Copy)]
pub(crate) struct Applier<'a> {
    /// The platform namespace when platform addresses are configured.
    pub(crate) platform: Option<&'a PlatformAddresses>,
    /// The ports the import works through.
    pub(crate) ports: &'a ImportConfigPorts,
    /// Who applies the document.
    pub(crate) caller: &'a CallerContext,
    /// What they may change in routing.
    pub(crate) by: RoutingControl<'a>,
    /// What they may change among consumers.
    pub(crate) consumers: ConsumerControl<'a>,
}

/// An apply in progress.
pub(crate) struct Apply<'a> {
    /// Who applies it, and through which ports.
    pub(crate) applier: Applier<'a>,
    /// What the document asks for, as the gateway would hold it.
    pub(crate) desired: &'a GatewayConfig,
    /// Every service, as written so far.
    pub(crate) services: HashMap<Label, Service<ResolvedTenant>>,
    /// Every pipeline, as written so far.
    pub(crate) pipelines: HashMap<Label, Pipeline<ResolvedTenant>>,
    /// Every route, as written so far.
    pub(crate) routes: HashMap<Label, Route<ResolvedTenant>>,
    /// Every stream route, as written so far.
    pub(crate) stream_routes: HashMap<Label, StreamRoute<ResolvedTenant>>,
    /// Every egress policy, as written so far, by the service it is for.
    pub(crate) egress_policies: HashMap<ServiceIdentity, EgressPolicy<ResolvedTenant>>,
    /// Every consumer, as written so far.
    pub(crate) consumers: HashMap<Label, Consumer<ResolvedTenant>>,
    /// Every connector, which services name and the document never writes.
    pub(crate) connectors: Vec<PrivateConnector<ResolvedTenant>>,
}

impl<'a> Apply<'a> {
    /// An apply of `desired` by `applier` that has written nothing yet, over
    /// the gateway `live` describes.
    pub(crate) fn starting(
        applier: Applier<'a>,
        desired: &'a GatewayConfig,
        live: LiveGateway,
    ) -> Self {
        Self {
            applier,
            desired,
            services: by_name(live.services, |service| service.name()),
            pipelines: by_name(live.pipelines, |pipeline| pipeline.name()),
            routes: by_name(live.routes, |route| route.name()),
            stream_routes: by_name(live.stream_routes, |route| route.name()),
            egress_policies: live
                .egress_policies
                .into_iter()
                .map(|policy| (policy.service().clone(), policy))
                .collect(),
            consumers: by_name(live.consumers, |consumer| consumer.name()),
            connectors: live.connectors,
        }
    }

    /// The tenant the document is applied to.
    pub(crate) fn tenant(&self) -> ScopedTenant {
        self.applier.caller.tenant()
    }
}

/// Refuses a create that would take the tenant past its plan.
///
/// # Errors
///
/// - `AppError::Forbidden` when the plan holds no more of `resource`.
pub(crate) async fn ensure_within_limit(
    applier: Applier<'_>,
    resource: ResourceKind,
) -> Result<(), AppError> {
    applier
        .ports
        .checks
        .limit_enforcer
        .check_tenant_limit(
            applier.caller.plan_limits(),
            &applier.caller.tenant(),
            resource,
        )
        .await
        .map_err(AppError::from_domain)
}

/// The declaration the plan is about.
///
/// # Errors
///
/// - `AppError::Domain` when the document holds no declaration by `name`.
pub(crate) fn declared<'d, T>(
    declarations: &'d [T],
    name: &Label,
    name_of: impl Fn(&T) -> &Label,
) -> Result<&'d T, AppError> {
    declarations
        .iter()
        .find(|declaration| name_of(declaration) == name)
        .ok_or_else(|| invalid(format!("'{name}' is planned but not in the document")))
}

/// The one error for "this route points at something that is not there".
pub(crate) fn missing_reference(route: &Label, kind: &str, name: &Label) -> AppError {
    invalid(format!(
        "route '{route}' names {kind} '{name}', which the configuration does not define"
    ))
}

/// The error for a service accepting the sign-in of one that is not there.
pub(crate) fn missing_sign_in_owner(service: &Label, owner: &Label) -> AppError {
    invalid(format!(
        "service '{service}' accepts the sign-in of '{owner}', which does not exist"
    ))
}

/// What a caller is told when a pipeline refuses a change.
///
/// Someone without the pipeline right is forbidden, a pipeline still in use
/// is a conflict, a move its status does not allow is an invalid
/// transition, and anything else is a document the caller can correct.
pub(crate) fn pipeline_refused(error: PipelineError) -> AppError {
    match error {
        PipelineError::NotAllowed => AppError::Forbidden(error.to_string().into()),
        PipelineError::InUse => AppError::Conflict(error.to_string().into()),
        PipelineError::InvalidTransition(transition) => {
            AppError::Domain(DomainError::invalid_transition(transition.to_string()))
        }
        other => invalid(other.to_string()),
    }
}

/// A refusal of the document itself.
pub(crate) fn invalid(message: String) -> AppError {
    AppError::Domain(DomainError::invalid(message))
}

/// A routing record a document turns on or off: a service or a route.
pub(crate) trait Switchable {
    /// Whether it is on or off now.
    fn status(&self) -> RouteStatus;

    /// Turns it on, as `by` may.
    ///
    /// # Errors
    ///
    /// The domain's refusal of the move.
    fn activate(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError>;

    /// Turns it off, as `by` may.
    ///
    /// # Errors
    ///
    /// The domain's refusal of the move.
    fn disable(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError>;
}

impl Switchable for Service<ResolvedTenant> {
    fn status(&self) -> RouteStatus {
        Service::status(self)
    }

    fn activate(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        Service::activate(self, by)
    }

    fn disable(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        Service::disable(self, by)
    }
}

impl Switchable for Route<ResolvedTenant> {
    fn status(&self) -> RouteStatus {
        Route::status(self)
    }

    fn activate(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        Route::activate(self, by)
    }

    fn disable(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        Route::disable(self, by)
    }
}

impl Switchable for StreamRoute<ResolvedTenant> {
    fn status(&self) -> RouteStatus {
        StreamRoute::status(self)
    }

    fn activate(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        StreamRoute::activate(self, by)
    }

    fn disable(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        StreamRoute::disable(self, by)
    }
}

/// Moves `record` to `status`, where it is not there already.
///
/// # Errors
///
/// The domain's refusal of the move, such as `by` lacking the right.
pub(crate) fn settle_status(
    record: &mut impl Switchable,
    status: RouteStatus,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    match (record.status(), status) {
        (RouteStatus::Active, RouteStatus::Active)
        | (RouteStatus::Disabled, RouteStatus::Disabled) => Ok(()),
        (RouteStatus::Disabled, RouteStatus::Active) => record.activate(by),
        (RouteStatus::Active, RouteStatus::Disabled) => record.disable(by),
    }
}

/// Resources keyed by their name.
fn by_name<T>(items: Vec<T>, name_of: impl Fn(&T) -> &Label) -> HashMap<Label, T> {
    items
        .into_iter()
        .map(|item| (name_of(&item).clone(), item))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::test_support::authority::anyone_holding;

    use super::*;
    use crate::test_support::routing::routing_admin;
    use crate::test_support::{RejectingLimitEnforcer, block_on, test_ctx};
    use crate::use_cases::gateway::ImportCheckPorts;

    /// Acme's plan holds no more routes. A route the document would add is
    /// refused.
    #[test]
    fn a_create_past_the_plan_is_refused() {
        let ports = ImportConfigPorts {
            checks: ImportCheckPorts {
                limit_enforcer: Arc::new(RejectingLimitEnforcer),
                ..ImportCheckPorts::fakes()
            },
            ..ImportConfigPorts::fakes()
        };
        let caller = test_ctx();
        let applier = Applier {
            platform: None,
            ports: &ports,
            caller: &caller,
            by: routing_admin(),
            consumers: ConsumerControl::new(anyone_holding(&[SystemPermission::ManageConsumers])),
        };

        let result = block_on(ensure_within_limit(applier, ResourceKind::Routes));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A pipeline that is still in use refuses its deletion. The caller is
    /// told of a conflict, not of a bad document.
    #[test]
    fn a_pipeline_in_use_is_a_conflict() {
        assert!(matches!(
            pipeline_refused(PipelineError::InUse),
            AppError::Conflict(_)
        ));
    }
}
