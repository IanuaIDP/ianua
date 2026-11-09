//! Fakes for the pipeline use cases: pipelines, their stages, WASM modules
//! and the stage executor.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::proxy::pipeline::{Pipeline, PipelineRow};
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::{
    MandatoryStage, ModuleRef, RateLimitConfig, RateLimitKey, StageConfig, StageKind, StageRemoval,
};
use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::domains::routing::backend::upstream::{HostHeader, Upstream, UpstreamTimeout};
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::{CreateRouteParams, Route};
use ianua_domain::domains::routing::service::{CreateServiceParams, Service};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::authority::anyone_holding;
use ianua_domain::types::{
    Audience, HttpUrl, Label, PipelineId, Seconds, StageId, TenantId, UrlPath,
};

use crate::ports::TenantScoped;
use crate::ports::proxy::{PipelineStore, StageExecutor, WasmModuleStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::routing::FakeRouteStore;

/// A route on `/api/*` under `policy` that `pipeline` runs, forwarding to a
/// service of its own.
///
/// # Panics
///
/// Panics if the domain refuses the route, as it does a shared cache on a
/// route that needs sign-in.
#[must_use]
pub fn test_route_on(
    pipeline: &Pipeline<ResolvedTenant>,
    policy: RoutePolicy,
) -> Route<ResolvedTenant> {
    let control = RoutingControl::new(anyone_holding(SystemPermission::all()));
    let upstream = Upstream::new(
        HttpUrl::new("https://backend:8080").expect("a valid upstream"),
        UpstreamTimeout::DEFAULT,
        HostHeader::Rewrite,
    )
    .with_audience(Audience::new("api").expect("a valid audience"));
    let service = Service::create(
        CreateServiceParams {
            id: ianua_domain::types::ServiceId::new(),
            name: Label::new("name", "api").expect("a valid name"),
            upstream,
            health_check: HealthCheckPolicy::default(),
        },
        &control,
    )
    .expect("an admin makes a service");
    Route::create(
        CreateRouteParams {
            name: Label::new("name", "api").expect("a valid name"),
            path_pattern: UrlPath::new("/api/*").expect("a valid path"),
            methods: Vec::new(),
            policy,
            hosts: RouteHosts::Any,
            path_rewrite: PathRewrite::Keep,
            priority: 100,
        },
        &service,
        pipeline,
        &control,
    )
    .expect("the route fits the pipeline")
}

/// The id [`test_pipeline`] carries, so a test can name the pipeline it
/// seeded without threading the value through every call.
#[must_use]
pub fn test_pipeline_id() -> PipelineId {
    PipelineId::from_uuid(uuid::Uuid::nil())
}

/// A `Draft` pipeline named `Default`, carrying the mandatory Identity and
/// Policy stages and the well-known [`test_pipeline_id`].
///
/// # Panics
///
/// Panics if the domain refuses the row, which it never does.
#[must_use]
pub fn test_pipeline() -> Pipeline<ResolvedTenant> {
    test_pipeline_in(PipelineStatus::Draft)
}

/// [`test_pipeline`], in `status`.
///
/// # Panics
///
/// Panics if the domain refuses the row, which it never does.
#[must_use]
pub fn test_pipeline_in(status: PipelineStatus) -> Pipeline<ResolvedTenant> {
    pipeline_of(status, Vec::new())
}

/// [`test_pipeline_in`], also running [`rate_limit_stage`] after the
/// mandatory stages.
///
/// # Panics
///
/// Panics if the domain refuses the row, which it never does.
#[must_use]
pub fn test_pipeline_with_rate_limit(status: PipelineStatus) -> Pipeline<ResolvedTenant> {
    pipeline_of(status, vec![rate_limit_stage(300)])
}

/// [`test_pipeline_in`], also running `extra` after the mandatory stages.
///
/// # Panics
///
/// Panics if the domain refuses the row, as it does a stage list that
/// does not start with the mandatory stages.
#[must_use]
pub fn test_pipeline_running(
    status: PipelineStatus,
    extra: Vec<StageConfig>,
) -> Pipeline<ResolvedTenant> {
    pipeline_of(status, extra)
}

/// The id of the first stage of `pipeline` whose kind is `wanted`.
///
/// # Panics
///
/// Panics if the pipeline runs no such stage.
#[must_use]
pub fn stage_of(
    pipeline: &Pipeline<ResolvedTenant>,
    wanted: impl Fn(&StageKind) -> bool,
) -> StageId {
    *pipeline
        .stages()
        .iter()
        .find(|stage| wanted(stage.kind()))
        .expect("the pipeline runs such a stage")
        .id()
}

/// A rate limit of 100 requests a minute per user, at `position`.
///
/// # Panics
///
/// Panics if the domain refuses the stage, which it never does.
#[must_use]
pub fn rate_limit_stage(position: u16) -> StageConfig {
    StageConfig::new(
        StageKind::RateLimit(RateLimitConfig {
            max_requests: 100,
            window_seconds: Seconds::new(60),
            key_by: RateLimitKey::UserId,
        }),
        position,
        StageRemoval::Allowed,
    )
    .expect("a rate limit of 100 a minute is a valid stage")
}

fn pipeline_of(status: PipelineStatus, extra: Vec<StageConfig>) -> Pipeline<ResolvedTenant> {
    let now = clock::now();
    let mut stages = vec![
        StageConfig::locked(MandatoryStage::Identity),
        StageConfig::locked(MandatoryStage::Policy),
    ];
    stages.extend(extra);
    Pipeline::reconstitute(PipelineRow {
        id: test_pipeline_id(),
        name: Label::new("pipeline_name", "Default").expect("`Default` is a valid label"),
        status,
        stages,
        created_at: now,
        updated_at: now,
    })
    .expect("a pipeline running the mandatory stages first holds")
}

/// In-memory pipeline store for tests.
///
/// Keeps each pipeline under the tenant it was saved for, and refuses a
/// second pipeline by the same name in one tenant: the same rules the
/// Postgres store keeps, so a use case that passes here fails the same way
/// against the real one.
#[derive(Default)]
pub struct FakePipelineStore {
    pipelines: Mutex<Vec<(TenantId, Pipeline<ResolvedTenant>)>>,
    routes: Mutex<Option<Arc<FakeRouteStore>>>,
    count_reads: AtomicUsize,
}

impl TenantScoped for FakePipelineStore {}

impl FakePipelineStore {
    /// The number of route-count reads, so listing tests can bound storage
    /// calls independently of the number of pipelines returned.
    #[must_use]
    pub fn count_reads(&self) -> usize {
        self.count_reads.load(Ordering::SeqCst)
    }

    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `pipeline` in `tenant`.
    #[must_use]
    pub fn holding(tenant: TenantId, pipeline: Pipeline<ResolvedTenant>) -> Self {
        Self {
            pipelines: Mutex::new(vec![(tenant, pipeline)]),
            ..Self::default()
        }
    }

    /// Points `route_count` at the route store this test also uses, so a
    /// pipeline a route names cannot be deleted. Without it a pipeline is
    /// never in use and every delete goes through.
    pub fn tracking_routes(&self, routes: Arc<FakeRouteStore>) {
        *self.routes.lock().unwrap() = Some(routes);
    }

    fn in_tenant(
        &self,
        tenant: &ScopedTenant,
        wanted: impl Fn(&Pipeline<ResolvedTenant>) -> bool,
    ) -> Vec<Pipeline<ResolvedTenant>> {
        self.pipelines
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, pipeline)| owner == &**tenant && wanted(pipeline))
            .map(|(_, pipeline)| pipeline.clone())
            .collect()
    }
}

fn holds_name_of(held: &Pipeline<ResolvedTenant>, pipeline: &Pipeline<ResolvedTenant>) -> bool {
    held.name() == pipeline.name() && held.id() != pipeline.id()
}

#[async_trait]
impl PipelineStore for FakePipelineStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<Option<Pipeline<ResolvedTenant>>, DomainError> {
        Ok(self
            .in_tenant(tenant_id, |pipeline| pipeline.id() == pipeline_id)
            .into_iter()
            .next())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Pipeline<ResolvedTenant>>, DomainError> {
        let mut all = self.in_tenant(tenant_id, |_| true);
        all.sort_by_key(Pipeline::created_at);
        Ok(all)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        pipeline: &Pipeline<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut stored = self.pipelines.lock().unwrap();
        let name_taken = stored
            .iter()
            .any(|(owner, held)| owner == &**tenant_id && holds_name_of(held, pipeline));
        if name_taken {
            return Err(DomainError::conflict(format!(
                "a pipeline named '{}' already exists in this tenant",
                pipeline.name().as_str()
            )));
        }
        stored.retain(|(owner, held)| !(owner == &**tenant_id && held.id() == pipeline.id()));
        stored.push((**tenant_id, pipeline.clone()));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<(), DomainError> {
        let in_use = self.route_count(tenant_id, pipeline_id).await?;
        if in_use > 0 {
            return Err(DomainError::conflict(format!(
                "{in_use} route(s) still run this pipeline; move them to another one first"
            )));
        }
        self.pipelines
            .lock()
            .unwrap()
            .retain(|(owner, held)| !(owner == &**tenant_id && held.id() == pipeline_id));
        Ok(())
    }

    async fn route_counts(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_ids: &[PipelineId],
    ) -> Result<HashMap<PipelineId, u64>, DomainError> {
        self.count_reads.fetch_add(1, Ordering::SeqCst);
        let routes = self.routes.lock().unwrap().clone();
        Ok(pipeline_ids
            .iter()
            .map(|id| {
                (
                    *id,
                    routes
                        .as_ref()
                        .map_or(0, |routes| routes.running_through(tenant_id, id)),
                )
            })
            .collect())
    }

    async fn route_count(
        &self,
        tenant_id: &ScopedTenant,
        pipeline_id: &PipelineId,
    ) -> Result<u64, DomainError> {
        self.count_reads.fetch_add(1, Ordering::SeqCst);
        let routes = self.routes.lock().unwrap().clone();
        Ok(routes.map_or(0, |routes| routes.running_through(tenant_id, pipeline_id)))
    }
}

/// In-memory WASM module store for tests, keeping each module under the
/// tenant it was uploaded for.
pub struct FakeWasmModuleStore {
    modules: Mutex<HashMap<(TenantId, ModuleRef), Vec<u8>>>,
    max_bytes: usize,
}

impl FakeWasmModuleStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::limited_to(usize::MAX)
    }

    /// Creates an empty store that refuses modules over `max_bytes`.
    #[must_use]
    pub fn limited_to(max_bytes: usize) -> Self {
        Self {
            modules: Mutex::new(HashMap::new()),
            max_bytes,
        }
    }
}

impl TenantScoped for FakeWasmModuleStore {}

#[async_trait]
impl WasmModuleStore for FakeWasmModuleStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        bytecode: &[u8],
    ) -> Result<ModuleRef, DomainError> {
        if bytecode.len() > self.max_bytes {
            return Err(DomainError::invalid("module too large"));
        }
        let module_ref = ModuleRef::new(format!("sha256:test-{}", bytecode.len()))?;
        self.modules
            .lock()
            .unwrap()
            .insert((**tenant_id, module_ref.clone()), bytecode.to_vec());
        Ok(module_ref)
    }

    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        module_ref: &ModuleRef,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        Ok(self
            .modules
            .lock()
            .unwrap()
            .get(&(**tenant_id, module_ref.clone()))
            .cloned())
    }
}

/// Stage executor that passes every stage, and lets the request through at
/// the Policy stage.
pub struct FakeStageExecutor;

#[async_trait]
impl StageExecutor for FakeStageExecutor {
    async fn execute(
        &self,
        stage: &StageConfig,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        if matches!(stage.kind(), StageKind::Policy) {
            ctx.authorize();
        }
        Ok(StageDecision::Pass {
            reason: "fake pass".to_owned(),
        })
    }
}

impl Fake for Arc<dyn PipelineStore> {
    fn fake() -> Self {
        Arc::new(FakePipelineStore::empty())
    }
}

impl Fake for Arc<dyn StageExecutor> {
    fn fake() -> Self {
        Arc::new(FakeStageExecutor)
    }
}

impl Fake for Arc<dyn WasmModuleStore> {
    fn fake() -> Self {
        Arc::new(FakeWasmModuleStore::empty())
    }
}
