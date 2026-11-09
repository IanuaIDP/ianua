//! What applying a configuration document would change.
//!
//! Pure: two documents in, a list of changes out. No ports, no async, no
//! database. That is the point. The diff is what an operator reads before
//! deciding to apply, so it has to be what the apply then does, and the only
//! way to be sure of that is for both to be driven by this one function.

use ianua_domain::domains::routing::egress::ServiceIdentity;
/// Whether an apply may remove what the document does not mention. The
/// domain owns it, since the record of an apply names it; it is offered
/// here beside the plan it shapes.
pub use ianua_domain::domains::routing::import::ImportMode;
use ianua_domain::types::Label;

use crate::use_cases::gateway::document::{
    ConsumerDeclaration, EgressPolicyDeclaration, GatewayConfig, PipelineDeclaration,
    RouteDeclaration, ServiceDeclaration, StreamRouteDeclaration,
};

/// What an apply would do to one named resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// Does not exist yet.
    Create,
    /// Exists and differs.
    Update,
    /// Exists, is not in the document, and [`ImportMode::Replace`] is in
    /// force.
    Delete,
    /// Exists and matches; the apply will not touch it.
    Unchanged,
}

/// Which kind of resource a change is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// A backend.
    Service,
    /// A request-processing stage sequence in the gateway configuration.
    Pipeline,
    /// An HTTP matching rule in the gateway configuration.
    Route,
    /// A non-human caller.
    Consumer,
    /// A port below HTTP.
    StreamRoute,
    /// Where a service may send traffic.
    EgressPolicy,
}

/// One line of the diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceChange {
    /// What kind of thing changed.
    pub resource: ResourceKind,
    /// Its name, as the document gives it.
    pub name: Label,
    /// What would happen to it.
    pub kind: ChangeKind,
}

/// Everything an apply would do, in the order it would do it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigDiff {
    /// Changes, in apply order: creates and updates with dependencies before
    /// dependents (services, pipelines, routes, consumers, stream routes,
    /// egress policies), then deletions in the reverse, since a service
    /// cannot go while a route still names it.
    pub changes: Vec<ResourceChange>,
}

impl ConfigDiff {
    /// Whether applying this would alter anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes
            .iter()
            .all(|change| change.kind == ChangeKind::Unchanged)
    }

    /// The changes that are not [`ChangeKind::Unchanged`].
    #[must_use]
    pub fn effective(&self) -> Vec<&ResourceChange> {
        self.changes
            .iter()
            .filter(|change| change.kind != ChangeKind::Unchanged)
            .collect()
    }

    /// How many resources would actually change.
    #[must_use]
    pub fn effective_count(&self) -> usize {
        self.effective().len()
    }
}

/// A declaration the diff matches against the live one by its key.
pub(crate) trait Declared: PartialEq {
    /// What tells one apart from every other of its kind.
    type Key: PartialEq + ?Sized;

    /// The kind of resource it declares.
    const RESOURCE: ResourceKind;

    /// The stable identity used to pair current and proposed resources.
    fn key(&self) -> &Self::Key;

    /// Its name, as a change reports it.
    fn name(&self) -> &Label;
}

/// Implements [`Declared`] for a declaration keyed by its name.
macro_rules! keyed_by_name {
    ($declaration:ty, $resource:expr) => {
        impl Declared for $declaration {
            type Key = Label;
            const RESOURCE: ResourceKind = $resource;

            fn key(&self) -> &Label {
                &self.name
            }

            fn name(&self) -> &Label {
                &self.name
            }
        }
    };
}

keyed_by_name!(ServiceDeclaration, ResourceKind::Service);
keyed_by_name!(PipelineDeclaration, ResourceKind::Pipeline);
keyed_by_name!(RouteDeclaration, ResourceKind::Route);
keyed_by_name!(ConsumerDeclaration, ResourceKind::Consumer);
keyed_by_name!(StreamRouteDeclaration, ResourceKind::StreamRoute);

impl Declared for EgressPolicyDeclaration {
    type Key = ServiceIdentity;
    const RESOURCE: ResourceKind = ResourceKind::EgressPolicy;

    fn key(&self) -> &ServiceIdentity {
        &self.service
    }

    fn name(&self) -> &Label {
        &self.name
    }
}

/// What applying `desired` to `current` would do.
///
/// The result is in apply order, which is why it is worth reading before
/// applying: creates and updates run dependency-first, then deletions run
/// dependency-last, because a service cannot be removed while a route still
/// names it.
#[must_use]
pub fn diff(desired: &GatewayConfig, current: &GatewayConfig, mode: ImportMode) -> ConfigDiff {
    let mut changes = upserts_of(desired, current);
    if mode == ImportMode::Replace {
        changes.extend(deletions_of(desired, current));
    }
    ConfigDiff { changes }
}

/// Every create, update and unchanged resource, dependencies first:
/// services, pipelines, routes, consumers, stream routes, egress policies.
fn upserts_of(desired: &GatewayConfig, current: &GatewayConfig) -> Vec<ResourceChange> {
    [
        upserts(&desired.services, &current.services),
        upserts(&desired.pipelines, &current.pipelines),
        upserts(&desired.routes, &current.routes),
        upserts(&desired.consumers, &current.consumers),
        upserts(&desired.stream_routes, &current.stream_routes),
        upserts(&desired.egress_policies, &current.egress_policies),
    ]
    .concat()
}

/// Every deletion, dependents first: egress policies, stream routes,
/// consumers, routes, pipelines, services.
fn deletions_of(desired: &GatewayConfig, current: &GatewayConfig) -> Vec<ResourceChange> {
    [
        deletions(&desired.egress_policies, &current.egress_policies),
        deletions(&desired.stream_routes, &current.stream_routes),
        deletions(&desired.consumers, &current.consumers),
        deletions(&desired.routes, &current.routes),
        deletions(&desired.pipelines, &current.pipelines),
        deletions(&desired.services, &current.services),
    ]
    .concat()
}

/// What the document asks for, matched against what exists by key.
fn upserts<T: Declared>(desired: &[T], current: &[T]) -> Vec<ResourceChange> {
    desired
        .iter()
        .map(|want| {
            let kind = match current.iter().find(|have| have.key() == want.key()) {
                None => ChangeKind::Create,
                Some(have) if have == want => ChangeKind::Unchanged,
                Some(_) => ChangeKind::Update,
            };
            change(want, kind)
        })
        .collect()
}

/// What exists and the document does not mention.
fn deletions<T: Declared>(desired: &[T], current: &[T]) -> Vec<ResourceChange> {
    current
        .iter()
        .filter(|have| !desired.iter().any(|want| want.key() == have.key()))
        .map(|have| change(have, ChangeKind::Delete))
        .collect()
}

/// The change `kind` to `declared`.
fn change<T: Declared>(declared: &T, kind: ChangeKind) -> ResourceChange {
    ResourceChange {
        resource: T::RESOURCE,
        name: declared.name().clone(),
        kind,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
    use ianua_domain::domains::routing::matching::host::RouteHosts;
    use ianua_domain::domains::routing::matching::parameter::RouteReach;
    use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
    use ianua_domain::domains::routing::matching::request_match::RouteConditions;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::route_status::RouteStatus;
    use ianua_domain::types::{DeclaredAction, Setting, UrlPath};

    use super::*;
    use crate::test_support::routing::{github, routing_label, unpinned_upstream};

    const FETCHER: &str = "spiffe://ianua.test/ns/svc/sa/fetcher";

    fn service(name: &str, url: &str) -> ServiceDeclaration {
        ServiceDeclaration {
            name: routing_label(name),
            upstream: unpinned_upstream(url),
            client_certificate: Setting::Unset,
            connector: Setting::Unset,
            health_check: HealthCheckPolicy::Disabled,
            app_sign_in: Setting::Unset,
            accepts_app_sign_in: Setting::Unset,
            status: RouteStatus::Active,
        }
    }

    fn egress(name: &str) -> EgressPolicyDeclaration {
        EgressPolicyDeclaration {
            name: routing_label(name),
            service: ServiceIdentity::new(FETCHER).unwrap(),
            destinations: vec![github()],
            max_data_class: DataClassLevel::Internal,
        }
    }

    fn config(services: Vec<ServiceDeclaration>) -> GatewayConfig {
        GatewayConfig {
            services,
            ..GatewayConfig::default()
        }
    }

    fn kinds(diff: &ConfigDiff) -> Vec<(ChangeKind, String)> {
        diff.changes
            .iter()
            .map(|c| (c.kind, c.name.as_str().to_owned()))
            .collect()
    }

    /// The document names a service Acme does not have. The plan creates
    /// it.
    #[test]
    fn a_resource_the_gateway_does_not_have_is_created() {
        let desired = config(vec![service("api", "https://api.internal:8443")]);

        let diff = diff(&desired, &GatewayConfig::default(), ImportMode::Merge);

        assert_eq!(kinds(&diff), vec![(ChangeKind::Create, "api".to_owned())]);
    }

    /// The document says what Acme already has. The plan leaves it alone and
    /// changes nothing.
    #[test]
    fn an_identical_resource_is_unchanged() {
        let existing = config(vec![service("api", "https://api.internal:8443")]);

        let diff = diff(&existing, &existing, ImportMode::Merge);

        assert_eq!(
            kinds(&diff),
            vec![(ChangeKind::Unchanged, "api".to_owned())]
        );
        assert!(diff.is_empty());
        assert_eq!(diff.effective_count(), 0);
    }

    /// The document points the API somewhere new. The plan updates it.
    #[test]
    fn a_resource_that_differs_is_updated() {
        let current = config(vec![service("api", "https://api.internal:8443")]);
        let desired = config(vec![service("api", "https://api-v2.internal:8443")]);

        let diff = diff(&desired, &current, ImportMode::Merge);

        assert_eq!(kinds(&diff), vec![(ChangeKind::Update, "api".to_owned())]);
        assert!(!diff.is_empty());
    }

    /// A merge of a document that omits the API leaves the API alone. An
    /// omission is far more often an incomplete file than a demand to take
    /// it down.
    #[test]
    fn merge_leaves_alone_what_the_document_does_not_mention() {
        let current = config(vec![service("api", "https://api.internal:8443")]);

        let diff = diff(&GatewayConfig::default(), &current, ImportMode::Merge);

        assert!(diff.changes.is_empty());
    }

    /// A replace with a document that omits the API deletes it.
    #[test]
    fn replace_deletes_what_the_document_does_not_mention() {
        let current = config(vec![service("api", "https://api.internal:8443")]);

        let diff = diff(&GatewayConfig::default(), &current, ImportMode::Replace);

        assert_eq!(kinds(&diff), vec![(ChangeKind::Delete, "api".to_owned())]);
    }

    /// A replace drops only the omitted legacy service. Dropping what the
    /// document still names would take live traffic down with it.
    #[test]
    fn replace_keeps_what_the_document_still_names() {
        let current = config(vec![
            service("api", "https://api.internal:8443"),
            service("legacy", "https://legacy.internal:8443"),
        ]);
        let desired = config(vec![service("api", "https://api.internal:8443")]);

        let diff = diff(&desired, &current, ImportMode::Replace);

        assert_eq!(
            kinds(&diff),
            vec![
                (ChangeKind::Unchanged, "api".to_owned()),
                (ChangeKind::Delete, "legacy".to_owned()),
            ]
        );
    }

    /// Ann renames the fetcher's egress policy in the document. The policy
    /// is kept once per service, so the plan updates it rather than making
    /// a second one beside it.
    #[test]
    fn an_egress_policy_is_matched_by_its_service() {
        let current = GatewayConfig {
            egress_policies: vec![egress("fetcher")],
            ..GatewayConfig::default()
        };
        let desired = GatewayConfig {
            egress_policies: vec![egress("github-fetcher")],
            ..GatewayConfig::default()
        };

        let diff = diff(&desired, &current, ImportMode::Replace);

        assert_eq!(
            kinds(&diff),
            vec![(ChangeKind::Update, "github-fetcher".to_owned())]
        );
    }

    /// The plan lists the service and pipeline before the route naming them,
    /// the order a reader needs and the apply creates them in.
    #[test]
    fn services_and_pipelines_come_before_routes() {
        let desired = GatewayConfig {
            services: vec![service("api", "https://api.internal:8443")],
            pipelines: vec![PipelineDeclaration {
                name: routing_label("edge"),
                stages: Vec::new(),
                status: PipelineStatus::Draft,
            }],
            routes: vec![RouteDeclaration {
                name: routing_label("public"),
                path_pattern: UrlPath::new("/v1/*").unwrap(),
                methods: Vec::new(),
                service: routing_label("api"),
                pipeline: routing_label("edge"),
                policy: RoutePolicy::Public,
                path_rewrite: PathRewrite::Keep,
                priority: 100,
                hosts: RouteHosts::Any,
                conditions: RouteConditions::default(),
                data_class: DataClassLevel::Internal,
                action_class: DeclaredAction::Undeclared,
                reach: RouteReach::Fixed,
                parameter_rules: Vec::new(),
                status: RouteStatus::Active,
            }],
            egress_policies: vec![egress("fetcher")],
            ..GatewayConfig::default()
        };

        let diff = diff(&desired, &GatewayConfig::default(), ImportMode::Merge);

        let order: Vec<ResourceKind> = diff.changes.iter().map(|c| c.resource).collect();
        assert_eq!(
            order,
            vec![
                ResourceKind::Service,
                ResourceKind::Pipeline,
                ResourceKind::Route,
                ResourceKind::EgressPolicy,
            ]
        );
    }

    /// Ann exports Acme's gateway and applies the file back with a replace.
    /// Nothing happens.
    #[test]
    fn a_document_exported_from_a_gateway_applies_as_no_change() {
        let current = GatewayConfig {
            egress_policies: vec![egress("fetcher")],
            ..config(vec![
                service("api", "https://api.internal:8443"),
                service("web", "https://web.internal:8443"),
            ])
        };

        let diff = diff(&current, &current, ImportMode::Replace);

        assert!(diff.is_empty(), "{diff:?}");
    }
}
