//! Code runs on Kubernetes: one pod per run in the sandboxes' namespace,
//! under the runtime class the operator names, such as gVisor's.
//!
//! A run claims a pod of its kind waiting warm, or else one is made for it
//! and waited on until its container starts. The pod is attached to and
//! handed the version's bundle and its own files on its input; what it
//! writes is read within bounds while it runs, and how its container ended
//! is read from the pod. The pod is deleted however the run went, and once
//! the code ran, its kind's warm pods are topped up. The worker holds a
//! fixed number of runs at once, and the namespace's quota bounds every
//! worker's pods together, warm ones included; a pod the cluster will not
//! take or cannot start is reported as no sandbox being free, so the run is
//! tried again. A company's image gets a pod of its own instead, pulled with
//! its registry's login (`image`).

mod image;
mod pod;
mod pool;
mod running;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{CodeRan, CodeRequest, CodeRunner};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use ianua_domain::domains::workflows::sandbox::image::OwnImage;
use ianua_domain::domains::workflows::sandbox::network::NetworkAccess;
use ianua_domain::domains::workflows::sandbox::recipe::{Program, Recipe};
use ianua_domain::types::{CodeRunId, UntrustedText};
use k8s_openapi::api::core::v1::{Pod, Secret};
use kube::api::{Api, DeleteParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use tokio::sync::{OnceCell, Semaphore};

use crate::files::{FileName, FileStore, StoredFile};
use crate::sandbox::cluster::pod::{PodKind, PodNetwork, PodPlan, PodState, pod_of};
pub use crate::sandbox::cluster::pool::WarmPods;
use crate::sandbox::cluster::pool::WarmPool;
use crate::sandbox::cluster::running::{Run, Sent};
use crate::sandbox::entry::entry_of;
use crate::sandbox::output::Ended;
use crate::sandbox::proxy::{ProxyAccess, RunNetwork, run_network};
use crate::sandbox::streamed::run_files;

/// How code runs are made on the cluster.
#[derive(Debug, Clone)]
pub struct ClusterSettings {
    /// The namespace the pods are made in, which holds nothing else.
    pub namespace: String,
    /// The runtime class pods run under, such as `gvisor`; `None` for the
    /// cluster's default.
    pub runtime_class: Option<String>,
    /// The kubeconfig context to reach the cluster through, for a worker
    /// outside it; `None` for the worker's own service account, inside it.
    pub context: Option<String>,
    /// How long a pod may take to start, or its image to be pulled,
    /// beyond the version's own time limit.
    pub start_grace: Duration,
    /// The most runs this worker holds at once.
    pub most_at_once: usize,
    /// How many pods wait warm, and for how long.
    pub warm: WarmPods,
}

/// Runs each version's code in a pod of its own.
pub struct ClusterCodeRunner {
    files: Arc<dyn FileStore>,
    settings: ClusterSettings,
    client: OnceCell<Client>,
    slots: Semaphore,
    pool: Arc<WarmPool>,
    network: Option<ProxyAccess>,
}

/// The pod requirements and streamed files resolved for one code request.
struct PlannedRun {
    run_id: CodeRunId,
    seconds: u32,
    kind: PodKind,
    proxy: Option<String>,
    files: Vec<u8>,
}

impl ClusterCodeRunner {
    /// A runner reading bundles from `files`, making pods as `settings`
    /// says, and giving runs whose versions name hosts the network filter
    /// `network` reaches; with none, such runs do not run. It reaches the
    /// cluster at its first run.
    #[must_use]
    pub fn new(
        files: Arc<dyn FileStore>,
        settings: ClusterSettings,
        network: Option<ProxyAccess>,
    ) -> Self {
        let slots = Semaphore::new(settings.most_at_once.max(1));
        let pool = WarmPool::new(
            settings.warm,
            settings.start_grace,
            settings.runtime_class.clone(),
        );
        Self {
            files,
            settings,
            client: OnceCell::new(),
            slots,
            pool: Arc::new(pool),
            network,
        }
    }

    /// The pods of the sandboxes' namespace, through the client made once.
    async fn pods(&self) -> Result<Api<Pod>, String> {
        let client = self.client().await?;
        Ok(Api::namespaced(client.clone(), &self.settings.namespace))
    }

    /// The client of the cluster, made at the first run.
    async fn client(&self) -> Result<&Client, String> {
        self.client
            .get_or_try_init(|| connected(self.settings.context.as_deref()))
            .await
    }

    /// How long a run of `recipe` may hold its network ticket: its time
    /// limit and the start-up grace twice over.
    fn lasts(&self, recipe: &Recipe) -> Duration {
        Duration::from_secs(u64::from(recipe.budget().seconds()))
            .saturating_add(self.settings.start_grace.saturating_mul(2))
    }

    /// The namespace's secrets, where an image run's pull secret is made.
    async fn secrets(&self) -> Result<Api<Secret>, String> {
        let client = self.client().await?;
        Ok(Api::namespaced(client.clone(), &self.settings.namespace))
    }

    /// Runs `own`, the company's image of `request`'s version, in a pod of
    /// its own, pulled with the request's login.
    async fn in_an_image_pod(
        &self,
        pods: &Api<Pod>,
        request: &CodeRequest<'_>,
        own: &OwnImage,
    ) -> CodeRan {
        let recipe = request.version.recipe();
        let network = match self.network_of(recipe.network(), self.lasts(recipe)).await {
            Ok(network) => network,
            Err(answer) => return answer,
        };
        let secrets = match self.secrets().await {
            Ok(secrets) => secrets,
            Err(why) => return unavailable(&why),
        };
        let name = image_pod_name(request.run_id);
        let run = image::ImageRun {
            name: &name,
            image: own.image(),
            memory_mib: recipe.budget().memory_mib(),
            seconds: recipe.budget().seconds(),
            proxy: proxy_of(&network),
            runtime_class: self.settings.runtime_class.as_deref(),
            grace: self.settings.start_grace,
        };
        let objects = image::Objects {
            pods,
            secrets: &secrets,
        };
        match image::ran(&objects, &run, request.login, &request.input.render()).await {
            Ended::Ran(outcome) => CodeRan::Ran(outcome),
            Ended::NotStarted(why) => unavailable(&why),
        }
    }

    /// The version's bundle, or what to answer without it.
    async fn bundle(
        &self,
        tenant: &ScopedTenant,
        request: &CodeRequest<'_>,
    ) -> Result<StoredFile, CodeRan> {
        let name = FileName::sandbox_bundle(tenant, request.version.id());
        match self.files.open(&name).await {
            Ok(Some(bundle)) => Ok(bundle),
            Ok(None) => Err(CodeRan::Ran(CodeOutcome::Failed(CodeFailure::NotRun(
                UntrustedText::record("the version's bundle is not kept"),
            )))),
            Err(error) => Err(unavailable(&format!(
                "the bundle could not be read: {error}"
            ))),
        }
    }

    /// Runs `request` with `bundle` in a warm pod of its kind, or in one
    /// made for it, deleting the pod afterwards however the run went; once
    /// the code ran, the kind's warm pods are topped up.
    async fn in_a_pod(
        &self,
        pods: &Api<Pod>,
        request: &CodeRequest<'_>,
        bundle: StoredFile,
    ) -> CodeRan {
        let planned = match self.plan_run(request).await {
            Ok(planned) => planned,
            Err(answer) => return answer,
        };
        let (name, ready) = self.pod_for(pods, &planned).await;
        let run = Run {
            pod: &name,
            seconds: planned.seconds,
            grace: self.settings.start_grace,
            proxy: planned.proxy,
        };
        let sent = Sent {
            bundle,
            files: &planned.files,
        };
        let ended = match ready {
            Ok(()) => running::ran(pods, &run, sent).await,
            Err(why) => Ended::NotStarted(why),
        };
        delete_run_pod(pods, &name).await;
        match ended {
            Ended::Ran(outcome) => {
                self.pool.refill(pods, &planned.kind);
                CodeRan::Ran(outcome)
            }
            Ended::NotStarted(why) => unavailable(&why),
        }
    }

    /// Resolves the network and packs the input before a pod is claimed or created.
    async fn plan_run(&self, request: &CodeRequest<'_>) -> Result<PlannedRun, CodeRan> {
        let recipe = request.version.recipe();
        let seconds = recipe.budget().seconds();
        let network = self
            .network_of(recipe.network(), self.lasts(recipe))
            .await?;
        let Some(code) = recipe.program().code() else {
            return Err(unavailable("the version holds no code"));
        };
        let entry = entry_of(code.runtime());
        let Ok(files) = run_files(&entry, code.code().as_str(), &request.input.render()) else {
            return Err(unavailable("the run's files could not be packed"));
        };
        let (pod_network, proxy) = match network {
            RunNetwork::Closed => (PodNetwork::Closed, None),
            RunNetwork::Proxied(proxy) => (PodNetwork::Proxied, Some(proxy)),
        };
        Ok(PlannedRun {
            run_id: request.run_id,
            seconds,
            kind: PodKind {
                runtime: code.runtime(),
                image: code.image().as_str().to_owned(),
                memory_mib: recipe.budget().memory_mib(),
                network: pod_network,
            },
            proxy,
            files,
        })
    }

    /// Claims a compatible warm pod, creating one only when none can be claimed.
    async fn pod_for(&self, pods: &Api<Pod>, planned: &PlannedRun) -> (String, Result<(), String>) {
        match self
            .pool
            .claimed(pods, &planned.kind, planned.seconds)
            .await
        {
            Some(name) => (name, Ok(())),
            None => self.made_for(pods, planned).await,
        }
    }

    /// The network a run of a version reaching `network` gets, for `lasts`:
    /// the filter at its address, which a pod cannot look up itself.
    async fn network_of(
        &self,
        network: &NetworkAccess,
        lasts: Duration,
    ) -> Result<RunNetwork, CodeRan> {
        let access = match &self.network {
            Some(access) if !network.is_closed() => {
                Some(access.resolved().await.map_err(|why| unavailable(&why))?)
            }
            _ => None,
        };
        run_network(access.as_ref(), network, lasts)
    }

    /// A pod made for the planned run, with whether its
    /// container started.
    async fn made_for(
        &self,
        pods: &Api<Pod>,
        planned: &PlannedRun,
    ) -> (String, Result<(), String>) {
        let name = format!(
            "ianua-code-{}-{:08x}",
            planned.run_id,
            rand::random::<u32>()
        );
        let plan = PodPlan {
            name: &name,
            kind: &planned.kind,
            runtime_class: self.settings.runtime_class.as_deref(),
            state: PodState::Claimed,
            deadline: Duration::from_secs(u64::from(planned.seconds))
                .saturating_add(self.settings.start_grace),
        };
        let started = match pod_of(&plan) {
            Ok(pod) => running::create_and_start(pods, &pod, self.settings.start_grace).await,
            Err(error) => Err(format!("the pod could not be described: {error}")),
        };
        (name, started)
    }
}

impl TenantScoped for ClusterCodeRunner {}

#[async_trait]
impl CodeRunner for ClusterCodeRunner {
    async fn run(&self, tenant_id: &ScopedTenant, request: CodeRequest<'_>) -> CodeRan {
        let waited = tokio::time::timeout(self.settings.start_grace, self.slots.acquire()).await;
        let Ok(Ok(_slot)) = waited else {
            return unavailable("every code run this worker may hold is under way");
        };
        let pods = match self.pods().await {
            Ok(pods) => pods,
            Err(why) => return unavailable(&why),
        };
        if let Program::Image(own) = request.version.recipe().program() {
            return self.in_an_image_pod(&pods, &request, own).await;
        }
        let bundle = match self.bundle(tenant_id, &request).await {
            Ok(bundle) => bundle,
            Err(answer) => return answer,
        };
        self.in_a_pod(&pods, &request, bundle).await
    }
}

/// Deletes a finished or unstarted pod, logging cleanup failures without replacing its outcome.
async fn delete_run_pod(pods: &Api<Pod>, name: &str) {
    if let Err(error) = pods.delete(name, &DeleteParams::background()).await {
        tracing::warn!(%error, pod = %name, "a code run's pod could not be deleted");
    }
}

/// A client of the cluster: through the named kubeconfig `context`, or the
/// worker's own service account when none is named.
async fn connected(context: Option<&str>) -> Result<Client, String> {
    let config = match context {
        Some(context) => from_context(context).await?,
        None => Config::incluster().map_err(|error| format!("not inside a cluster: {error}"))?,
    };
    Client::try_from(config).map_err(|error| format!("no client for the cluster: {error}"))
}

/// The configuration of kubeconfig context `context`, and only that one,
/// so a worker outside the cluster never reaches whichever cluster happens
/// to be current.
async fn from_context(context: &str) -> Result<Config, String> {
    let kubeconfig =
        Kubeconfig::read().map_err(|error| format!("no kubeconfig could be read: {error}"))?;
    let options = KubeConfigOptions {
        context: Some(context.to_owned()),
        ..KubeConfigOptions::default()
    };
    Config::from_custom_kubeconfig(kubeconfig, &options)
        .await
        .map_err(|error| format!("the kubeconfig context {context} cannot be used: {error}"))
}

/// The network filter's address a run reaching `network` is given; `None`
/// for one that reaches no network.
fn proxy_of(network: &RunNetwork) -> Option<&str> {
    match network {
        RunNetwork::Proxied(proxy) => Some(proxy.as_str()),
        RunNetwork::Closed => None,
    }
}

/// A run no pod could take, for `why`.
fn unavailable(why: &str) -> CodeRan {
    CodeRan::Unavailable(UntrustedText::record(why))
}
/// A fresh pod name for an image run of `run_id`, unlike any before it.
fn image_pod_name(run_id: CodeRunId) -> String {
    format!("ianua-code-{run_id}-{:08x}", rand::random::<u32>())
}
