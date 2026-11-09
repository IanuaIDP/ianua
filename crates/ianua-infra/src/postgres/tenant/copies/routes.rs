//! The routes part of a clone: proxy routes, the services they forward
//! to, and the pipelines they run.
//!
//! A service, route or pipeline the target has by the same name keeps its
//! id; the source's values are written over a service or route, so a copy
//! made again lands where the first did. A pipeline the target already has
//! is used as it is, since someone may have set it up there since. One it
//! has not is copied as a draft: a draft pipeline refuses traffic, so the
//! copied routes stay shut until someone in the target turns it on.
//! A stage that reads a classification rule set reads the target's own,
//! or a copy of the source's made for it when the target has none, so a
//! copied Redact stage never points at a rule set the target cannot read.
//!
//! A service that accepts another's sign-in names it, so the services that
//! own their sign-in are written first. Hosts are copied as they are: a
//! host belongs to the tenant that proved it, never to two, so a copied
//! route or sign-in bound to the source's hosts answers nothing in the
//! target until it is pointed at the target's own.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_app::listing::SortOrder;
use ianua_app::ports::data_classification::ClassificationStore as _;
use ianua_app::ports::proxy::PipelineStore as _;
use ianua_app::ports::routing::{RouteStore as _, ServiceStore as _};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::data_classification::classification::{
    ClassificationRuleSet, ClassificationRuleSetRow,
};
use ianua_domain::domains::proxy::pipeline::{Pipeline, PipelineRow};
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::proxy::stages::stage::{StageConfig, StageConfigRow, StageRemoval};
use ianua_domain::domains::routing::route::{Route, RouteRow};
use ianua_domain::domains::routing::service::{Service, ServiceRow};
use ianua_domain::domains::routing::sign_in::accepted::AcceptedSignIn;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ClassificationRuleSetId, Enablement, PipelineId, RouteId, ServiceId, Setting,
};
use time::OffsetDateTime;

use crate::postgres::data_classification::PgClassificationStore;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::proxy::PgPipelineStore;
use crate::postgres::routing::{PgRouteStore, PgServiceStore};
use crate::postgres::tenant::copies::{Pair, all_of, whole_part};

/// Copies a tenant's routes, services and pipelines.
pub(crate) struct RouteCopy {
    classification: PgClassificationStore,
    pipelines: PgPipelineStore,
    services: PgServiceStore,
    routes: PgRouteStore,
}

/// What the source's pipelines and services are called in the target, and
/// when the copy is made.
struct Renames {
    pipelines: HashMap<PipelineId, PipelineId>,
    services: HashMap<ServiceId, ServiceId>,
    now: OffsetDateTime,
}

/// The target rule set and timestamp used when creating a draft pipeline.
#[derive(Clone, Copy)]
struct DraftSettings {
    rule_set: Option<ClassificationRuleSetId>,
    now: OffsetDateTime,
}

impl RouteCopy {
    /// A copy reading and writing the tenants of `databases`.
    pub(crate) fn new(databases: &Arc<Databases>) -> Self {
        Self {
            classification: PgClassificationStore::new(Arc::clone(databases)),
            pipelines: PgPipelineStore::new(Arc::clone(databases)),
            services: PgServiceStore::new(Arc::clone(databases)),
            routes: PgRouteStore::new(Arc::clone(databases)),
        }
    }

    /// Gives `pair`'s target the source's routes, with the services and
    /// pipelines they need.
    pub(crate) async fn copy(&self, pair: &Pair) -> Result<(), DomainError> {
        let routes = self.routes_of(&pair.source).await?;
        let now = clock::now();
        let pipelines = self.copy_pipelines(pair, &routes, now).await?;
        let mut renames = Renames {
            pipelines,
            services: HashMap::new(),
            now,
        };
        renames.services = self.copy_services(pair, &renames).await?;
        self.copy_routes(pair, &routes, &renames).await
    }

    /// Every route of `tenant`.
    async fn routes_of(
        &self,
        tenant: &ScopedTenant,
    ) -> Result<Vec<Route<ResolvedTenant>>, DomainError> {
        let page = self
            .routes
            .list_all(tenant, None, &SortOrder::default(), &whole_part())
            .await?;
        all_of(page, "routes")
    }

    /// Every service of `tenant`.
    async fn services_of(
        &self,
        tenant: &ScopedTenant,
    ) -> Result<Vec<Service<ResolvedTenant>>, DomainError> {
        let page = self
            .services
            .list_all(tenant, &SortOrder::default(), &whole_part())
            .await?;
        all_of(page, "services")
    }

    /// Gives the target a pipeline of each name `routes` run, as a draft
    /// where it has none, and answers what each is called there.
    async fn copy_pipelines(
        &self,
        pair: &Pair,
        routes: &[Route<ResolvedTenant>],
        now: OffsetDateTime,
    ) -> Result<HashMap<PipelineId, PipelineId>, DomainError> {
        let source = self.pipelines.list(&pair.source).await?;
        let target = self.pipelines.list(&pair.target).await?;
        let held: HashMap<&str, &Pipeline<ResolvedTenant>> = target
            .iter()
            .map(|pipeline| (pipeline.name().as_str(), pipeline))
            .collect();
        let run = pipelines_in_use(&source, routes);
        let needs_rules = run
            .iter()
            .filter(|pipeline| !held.contains_key(pipeline.name().as_str()))
            .any(|pipeline| reads_rules(pipeline));
        let rule_set = if needs_rules {
            self.rule_set_in_target(pair, now).await?
        } else {
            None
        };
        let mut renamed = HashMap::new();
        for pipeline in &run {
            let copied = match held.get(pipeline.name().as_str()) {
                Some(kept) => *kept.id(),
                None => {
                    self.add_draft(pair, pipeline, DraftSettings { rule_set, now })
                        .await?
                }
            };
            renamed.insert(*pipeline.id(), copied);
        }
        Ok(renamed)
    }

    /// The classification rule set the target's copied stages read: the
    /// target's own, or else a copy of the source's, made for it. `None`
    /// when neither tenant has one.
    async fn rule_set_in_target(
        &self,
        pair: &Pair,
        now: OffsetDateTime,
    ) -> Result<Option<ClassificationRuleSetId>, DomainError> {
        if let Some(own) = self.classification.find(&pair.target).await? {
            return Ok(Some(*own.id()));
        }
        let Some(source) = self.classification.find(&pair.source).await? else {
            return Ok(None);
        };
        let copy = ClassificationRuleSet::reconstitute(ClassificationRuleSetRow {
            id: ClassificationRuleSetId::new(),
            rules: source.rules().to_vec(),
            created_at: now,
            updated_at: now,
        })?;
        self.classification.save(&pair.target, &copy).await?;
        Ok(Some(*copy.id()))
    }

    /// Adds `pipeline` to the target as a draft with the selected rule set
    /// and timestamp, and answers its id there.
    async fn add_draft(
        &self,
        pair: &Pair,
        pipeline: &Pipeline<ResolvedTenant>,
        settings: DraftSettings,
    ) -> Result<PipelineId, DomainError> {
        let stages = pipeline
            .stages()
            .iter()
            .map(|stage| reading_in_target(stage, settings.rule_set))
            .collect::<Result<Vec<_>, _>>()?;
        let draft = Pipeline::reconstitute(PipelineRow {
            id: PipelineId::new(),
            name: pipeline.name().clone(),
            status: PipelineStatus::Draft,
            stages,
            created_at: settings.now,
            updated_at: settings.now,
        })?;
        self.pipelines.save(&pair.target, &draft).await?;
        Ok(*draft.id())
    }

    /// Writes the source's services over the target's, those owning their
    /// sign-in first, and answers what each is called there.
    async fn copy_services(
        &self,
        pair: &Pair,
        renames: &Renames,
    ) -> Result<HashMap<ServiceId, ServiceId>, DomainError> {
        let mut source = self.services_of(&pair.source).await?;
        source.sort_by_key(|service| service.accepted_sign_in().is_some());
        let target = self.services_of(&pair.target).await?;
        let held: HashMap<&str, &Service<ResolvedTenant>> = target
            .iter()
            .map(|service| (service.name().as_str(), service))
            .collect();
        let mut placed = HashMap::with_capacity(source.len());
        for service in &source {
            let kept = held.get(service.name().as_str()).copied();
            let accepted = accepted_in_target(service, &placed)?;
            let copy = renames.service(service, kept, accepted)?;
            self.services.save(&pair.target, &copy).await?;
            placed.insert(*service.id(), *copy.id());
        }
        Ok(placed)
    }

    /// Writes the source's routes over the target's.
    async fn copy_routes(
        &self,
        pair: &Pair,
        routes: &[Route<ResolvedTenant>],
        renames: &Renames,
    ) -> Result<(), DomainError> {
        let target = self.routes_of(&pair.target).await?;
        let held: HashMap<&str, &Route<ResolvedTenant>> = target
            .iter()
            .map(|route| (route.name().as_str(), route))
            .collect();
        for route in routes {
            let copy = renames.route(route, held.get(route.name().as_str()).copied())?;
            self.routes.save(&pair.target, &copy).await?;
        }
        Ok(())
    }
}

impl Renames {
    /// `service` as the target keeps it, accepting `accepted`, under the id
    /// of `kept` when the target has it.
    fn service(
        &self,
        service: &Service<ResolvedTenant>,
        kept: Option<&Service<ResolvedTenant>>,
        accepted: Setting<AcceptedSignIn>,
    ) -> Result<Service<ResolvedTenant>, DomainError> {
        Service::reconstitute(ServiceRow {
            id: kept.map_or_else(ServiceId::new, |held| *held.id()),
            name: service.name().clone(),
            upstream: service.upstream().clone(),
            health_check: service.health_check().clone(),
            app_sign_in: Setting::from_stored(service.app_sign_in().cloned()),
            accepted_sign_in: accepted,
            status: service.status(),
            created_at: kept.map_or(self.now, Service::created_at),
            updated_at: self.now,
        })
    }

    /// `route` as the target keeps it, forwarding to the copy of its
    /// service and running the target's pipeline, under the id of `kept`
    /// when the target has it.
    fn route(
        &self,
        route: &Route<ResolvedTenant>,
        kept: Option<&Route<ResolvedTenant>>,
    ) -> Result<Route<ResolvedTenant>, DomainError> {
        let service_id = self.service_id(route.service_id())?;
        let pipeline_id = self.pipeline_id(route.pipeline_id())?;
        Route::reconstitute(RouteRow {
            id: kept.map_or_else(RouteId::new, |held| *held.id()),
            name: route.name().clone(),
            path_pattern: route.path_pattern().clone(),
            methods: route.methods().to_vec(),
            service_id,
            policy: route.policy().clone(),
            hosts: route.hosts().clone(),
            conditions: route.conditions().clone(),
            pipeline_id,
            path_rewrite: route.path_rewrite().clone(),
            status: route.status(),
            priority: route.priority(),
            data_class: route.data_class(),
            action_class: route.declared_action_class(),
            reach: route.reach(),
            parameter_rules: route.parameter_rules().to_vec(),
            workflow_use: route.workflow_use(),
            attack_mode: route.attack_mode(),
            created_at: kept.map_or(self.now, Route::created_at),
            updated_at: self.now,
        })
    }

    /// Resolves the copied service before a route may reference it.
    fn service_id(&self, source: &ServiceId) -> Result<ServiceId, DomainError> {
        self.services.get(source).copied().ok_or_else(|| {
            DomainError::infra_msg("a route forwards to a service the copy did not carry over")
        })
    }

    /// Resolves the target pipeline and rejects a missing source dependency.
    fn pipeline_id(&self, source: &PipelineId) -> Result<PipelineId, DomainError> {
        self.pipelines.get(source).copied().ok_or_else(|| {
            DomainError::infra_msg("a route runs a pipeline the source does not have")
        })
    }
}

/// Selects source pipelines referenced by the routes, preserving their source order.
fn pipelines_in_use<'a>(
    source: &'a [Pipeline<ResolvedTenant>],
    routes: &[Route<ResolvedTenant>],
) -> Vec<&'a Pipeline<ResolvedTenant>> {
    source
        .iter()
        .filter(|pipeline| {
            routes
                .iter()
                .any(|route| route.pipeline_id() == pipeline.id())
        })
        .collect()
}

/// Whose sign-in `service` accepts, in the target's terms: the copy of the
/// service it names, written before it.
fn accepted_in_target(
    service: &Service<ResolvedTenant>,
    placed: &HashMap<ServiceId, ServiceId>,
) -> Result<Setting<AcceptedSignIn>, DomainError> {
    let Some(accepted) = service.accepted_sign_in() else {
        return Ok(Setting::Unset);
    };
    let owner = placed.get(accepted.owner()).copied().ok_or_else(|| {
        DomainError::infra_msg("a service accepts the sign-in of one the copy has not written")
    })?;
    Ok(Setting::Set(AcceptedSignIn::new(
        owner,
        accepted.delivery().clone(),
    )))
}

/// Whether a stage of `pipeline` reads a classification rule set.
fn reads_rules(pipeline: &Pipeline<ResolvedTenant>) -> bool {
    pipeline
        .stages()
        .iter()
        .any(|stage| stage.kind().rule_set().is_some())
}

/// `stage` as the target keeps it: reading `rule_set` when it reads one,
/// so a Redact stage never points at a rule set of another tenant, which
/// the target cannot read. With no rule set in either tenant it keeps the
/// one it named, as the source had it.
fn reading_in_target(
    stage: &StageConfig,
    rule_set: Option<ClassificationRuleSetId>,
) -> Result<StageConfig, DomainError> {
    let (Some(rule_set), Some(_)) = (rule_set, stage.kind().rule_set()) else {
        return Ok(stage.clone());
    };
    let kind = stage.kind().reading(rule_set);
    StageConfig::reconstitute(StageConfigRow {
        id: *stage.id(),
        removal: StageRemoval::of(&kind),
        kind,
        position: stage.position(),
        enabled: Enablement::from(stage.enabled()),
    })
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::tenant::ClonePartCopier as _;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::proxy::stages::stage::{RedactConfig, StageKind};
    use ianua_domain::domains::tenant::clone::{ClonePart, TenantClone};
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::tenant::copies::tests::{clone_between, copier};
    use crate::test_support::TestDb;
    use crate::test_support::rows::data_classification::rule_set_row;
    use crate::test_support::rows::proxy::{pipeline_row, saved_route_on};

    /// Two tenants of one clone, and the copy's stores over them.
    struct Tenants {
        db: TestDb,
        copy: RouteCopy,
        clone: TenantClone,
        source: ScopedTenant,
        target: ScopedTenant,
    }

    /// Two new tenants, the source holding the route `orders` on an active
    /// pipeline named `standard`, and its service.
    async fn tenants() -> Tenants {
        let db = TestDb::fresh().await;
        let clone = clone_between(TenantId::new(), TenantId::new());
        let at = Tenants {
            copy: RouteCopy::new(&db.databases),
            source: ScopedTenant::for_background(*clone.source()),
            target: ScopedTenant::for_background(*clone.target()),
            clone,
            db,
        };
        let pipeline = Pipeline::reconstitute(PipelineRow {
            status: PipelineStatus::Active,
            ..pipeline_row("standard", 0)
        })
        .unwrap();
        at.copy.pipelines.save(&at.source, &pipeline).await.unwrap();
        saved_route_on(&at.db.databases, &at.source, *pipeline.id(), "orders").await;
        at
    }

    impl Tenants {
        async fn copied(&self) {
            copier(&self.db)
                .copy(&self.clone, ClonePart::Routes)
                .await
                .unwrap();
        }
    }

    /// Builds a pipeline whose redaction stage reads the supplied classification rules.
    fn redacting_pipeline(
        rules: &ClassificationRuleSet<ResolvedTenant>,
    ) -> Pipeline<ResolvedTenant> {
        let kind = StageKind::Redact(RedactConfig {
            rule_set_id: *rules.id(),
            min_class: DataClassLevel::Confidential,
        });
        let redact = StageConfig::new(kind.clone(), 300, StageRemoval::of(&kind)).unwrap();
        let mut row = pipeline_row("redacting", 0);
        row.stages.push(redact);
        Pipeline::reconstitute(row).unwrap()
    }

    /// The target takes the route, forwarding to the copy of its service.
    #[tokio::test]
    async fn a_route_arrives_with_its_service() {
        let at = tenants().await;

        at.copied().await;

        let routes = at.copy.routes_of(&at.target).await.unwrap();
        let services = at.copy.services_of(&at.target).await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(services.len(), 1);
        assert_eq!(routes[0].service_id(), services[0].id());
        assert_eq!(routes[0].name().as_str(), "orders");
    }

    /// A pipeline absent from the target is copied as a draft, and the
    /// copied route references that target pipeline.
    #[tokio::test]
    async fn a_pipeline_the_target_lacks_arrives_as_a_draft() {
        let at = tenants().await;

        at.copied().await;

        let pipelines = at.copy.pipelines.list(&at.target).await.unwrap();
        let routes = at.copy.routes_of(&at.target).await.unwrap();
        assert_eq!(pipelines.len(), 1);
        assert_eq!(pipelines[0].status(), PipelineStatus::Draft);
        assert_eq!(routes[0].pipeline_id(), pipelines[0].id());
    }

    /// A copied Redact stage references the target's new classification
    /// rule set, whose id differs from the source's.
    #[tokio::test]
    async fn a_redacting_stage_reads_a_rule_set_the_target_has() {
        let at = tenants().await;
        let rules = ClassificationRuleSet::reconstitute(rule_set_row(Vec::new())).unwrap();
        at.copy
            .classification
            .save(&at.source, &rules)
            .await
            .unwrap();
        let pipeline = redacting_pipeline(&rules);
        at.copy.pipelines.save(&at.source, &pipeline).await.unwrap();
        saved_route_on(&at.db.databases, &at.source, *pipeline.id(), "records").await;

        at.copied().await;

        let theirs = at
            .copy
            .classification
            .find(&at.target)
            .await
            .unwrap()
            .unwrap();
        let copied = at.copy.pipelines.list(&at.target).await.unwrap();
        let read: Vec<_> = copied
            .iter()
            .flat_map(Pipeline::stages)
            .filter_map(|stage| stage.kind().rule_set())
            .collect();
        assert_ne!(theirs.id(), rules.id());
        assert_eq!(read, [theirs.id()]);
    }

    /// A copy made twice leaves one route, one service and one pipeline.
    #[tokio::test]
    async fn copying_twice_leaves_one_copy() {
        let at = tenants().await;

        at.copied().await;
        at.copied().await;

        assert_eq!(at.copy.routes_of(&at.target).await.unwrap().len(), 1);
        assert_eq!(at.copy.services_of(&at.target).await.unwrap().len(), 1);
        assert_eq!(at.copy.pipelines.list(&at.target).await.unwrap().len(), 1);
    }

    /// A pipeline the target already has by the name is used as it is,
    /// not replaced.
    #[tokio::test]
    async fn a_pipeline_the_target_has_is_used_as_it_is() {
        let at = tenants().await;
        let own = Pipeline::reconstitute(pipeline_row("standard", 5)).unwrap();
        at.copy.pipelines.save(&at.target, &own).await.unwrap();

        at.copied().await;

        let routes = at.copy.routes_of(&at.target).await.unwrap();
        assert_eq!(routes[0].pipeline_id(), own.id());
    }
}
