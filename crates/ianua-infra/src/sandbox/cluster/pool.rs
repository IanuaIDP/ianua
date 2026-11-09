//! Pods kept warm, so a run starts without waiting for its pod.
//!
//! Once a run of a kind started, the pool tops that kind's waiting pods up
//! to how many are kept, in the background. A run claims a waiting pod by
//! changing its state label on the version it read, so two workers never
//! claim one pod: the second change is refused. The claim also shortens
//! the pod's deadline to its run's, counted from when the pod started.
//! Each pod serves one run and is deleted after it. A pod waits at most as
//! long as the settings say; each top-up removes pods waiting longer,
//! pods whose image will not start, and pods that ended, and Kubernetes
//! ends a waiting pod nobody removed soon after.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ianua_domain::domains::workflows::sandbox::recipe::MAX_RUN_SECONDS;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::chrono::Utc;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams, Preconditions};
use serde_json::json;

use crate::sandbox::cluster::pod::{
    KEY_LABEL, PodKind, PodPlan, PodState, SANDBOX_LABEL, STATE_LABEL, pod_of,
};
use crate::sandbox::cluster::running::{refusal_to_start, state_of};

/// How long one call to the cluster made for the pool may take.
const CALL_WITHIN: Duration = Duration::from_secs(10);

/// How many pods wait warm, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarmPods {
    /// How many pods of each kind wait, once a run of that kind started;
    /// zero keeps none.
    pub per_kind: usize,
    /// How long a pod waits to be claimed before it is removed.
    pub waiting_for: Duration,
}

/// The pods waiting warm in the sandboxes' namespace.
pub(super) struct WarmPool {
    warm: WarmPods,
    start_grace: Duration,
    runtime_class: Option<String>,
    refilling: Mutex<HashSet<String>>,
}

impl WarmPool {
    /// A pool keeping `warm` pods, under `runtime_class`, each given
    /// `start_grace` to start and to be handed its run.
    pub(super) fn new(
        warm: WarmPods,
        start_grace: Duration,
        runtime_class: Option<String>,
    ) -> Self {
        Self {
            warm,
            start_grace,
            runtime_class,
            refilling: Mutex::new(HashSet::new()),
        }
    }

    /// The name of a waiting pod of `kind`, now claimed for a run of
    /// `seconds`, or `None` when none could be claimed.
    pub(super) async fn claimed(
        &self,
        pods: &Api<Pod>,
        kind: &PodKind,
        seconds: u32,
    ) -> Option<String> {
        if self.warm.per_kind == 0 {
            return None;
        }
        let selector = ListParams::default().labels(&waiting_for_kind(kind));
        let Ok(Ok(listed)) = tokio::time::timeout(CALL_WITHIN, pods.list(&selector)).await else {
            return None;
        };
        for pod in listed.items.iter().filter(|pod| self.is_claimable(pod)) {
            if let Some(name) = self.claim(pods, pod, seconds).await {
                return Some(name);
            }
        }
        None
    }

    /// Tops `kind`'s waiting pods up in the background, and removes the
    /// pods done with, unless a top-up of `kind` is under way already.
    pub(super) fn refill(self: &Arc<Self>, pods: &Api<Pod>, kind: &PodKind) {
        if self.warm.per_kind == 0 {
            return;
        }
        let Some(refilling) = Refilling::of(Arc::clone(self), kind.label()) else {
            return;
        };
        let pods = pods.clone();
        let kind = kind.clone();
        tokio::spawn(async move {
            let pool = &refilling.pool;
            let topped = tokio::time::timeout(pool.start_grace, pool.top_up(&pods, &kind)).await;
            if topped.is_err() {
                tracing::warn!("the warm code pods were not topped up in time");
            }
        });
    }

    /// Claims `pod` for a run of `seconds`: its state changed on the
    /// version read, and its deadline shortened to the run's.
    async fn claim(&self, pods: &Api<Pod>, pod: &Pod, seconds: u32) -> Option<String> {
        let name = pod.metadata.name.as_deref()?;
        let version = pod.metadata.resource_version.as_deref()?;
        let deadline = age_of(pod)?
            .saturating_add(Duration::from_secs(u64::from(seconds)))
            .saturating_add(self.start_grace);
        let change = json!({
            "metadata": {
                "resourceVersion": version,
                "labels": {STATE_LABEL: PodState::Claimed.as_str()},
            },
            "spec": {"activeDeadlineSeconds": deadline.as_secs().max(1)},
        });
        let parameters = PatchParams::default();
        let change = Patch::Merge(&change);
        let patched = pods.patch(name, &parameters, &change);
        let Ok(Ok(_)) = tokio::time::timeout(CALL_WITHIN, patched).await else {
            return None;
        };
        Some(name.to_owned())
    }

    /// Removes the pods done with, then makes `kind`'s missing waiting pods.
    async fn top_up(&self, pods: &Api<Pod>, kind: &PodKind) {
        let everyone = ListParams::default().labels(&every_code_pod());
        let listed = match pods.list(&everyone).await {
            Ok(listed) => listed.items,
            Err(error) => {
                tracing::warn!(%error, "the code pods could not be listed");
                return;
            }
        };
        self.remove_finished(pods, &listed).await;
        let waiting = listed
            .iter()
            .filter(|pod| is_waiting_as(pod, kind) && !self.is_done_with(pod))
            .count();
        for _ in waiting..self.warm.per_kind {
            if let Err(why) = self.create_waiting(pods, kind).await {
                tracing::warn!(%why, "a warm code pod could not be made");
                return;
            }
        }
    }

    /// Deletes each of `listed` done with, unless it changed since.
    async fn remove_finished(&self, pods: &Api<Pod>, listed: &[Pod]) {
        let done = listed.iter().filter(|pod| self.is_done_with(pod));
        for pod in done {
            let Some(name) = pod.metadata.name.as_deref() else {
                continue;
            };
            if let Err(error) = pods.delete(name, &as_read(pod)).await {
                tracing::warn!(%error, pod = %name, "a code pod done with was not deleted");
            }
        }
    }

    /// Makes one waiting pod of `kind`.
    async fn create_waiting(&self, pods: &Api<Pod>, kind: &PodKind) -> Result<(), String> {
        let name = format!("ianua-code-warm-{:016x}", rand::random::<u64>());
        let plan = PodPlan {
            name: &name,
            kind,
            runtime_class: self.runtime_class.as_deref(),
            state: PodState::Warm,
            deadline: self.waiting_deadline(),
        };
        let pod =
            pod_of(&plan).map_err(|error| format!("the pod could not be described: {error}"))?;
        pods.create(&PostParams::default(), &pod)
            .await
            .map_err(|error| format!("the cluster did not take the pod: {error}"))?;
        Ok(())
    }

    /// When Kubernetes ends a waiting pod: past the longest it waits, the
    /// longest run, and the grace, so a claim only ever shortens it.
    fn waiting_deadline(&self) -> Duration {
        self.warm
            .waiting_for
            .saturating_add(Duration::from_secs(u64::from(MAX_RUN_SECONDS)))
            .saturating_add(self.start_grace)
    }

    /// Whether `pod` waits with its container running, young enough to be
    /// claimed.
    fn is_claimable(&self, pod: &Pod) -> bool {
        pod.metadata.deletion_timestamp.is_none()
            && state_of(pod).is_some_and(|state| state.running.is_some())
            && age_of(pod).is_some_and(|age| age < self.warm.waiting_for)
    }

    /// Whether `pod` is done with: it ended, or it waits too long or for an
    /// image that will not start.
    fn is_done_with(&self, pod: &Pod) -> bool {
        let phase = pod
            .status
            .as_ref()
            .and_then(|status| status.phase.as_deref());
        if matches!(phase, Some("Succeeded" | "Failed")) {
            return true;
        }
        state_label(pod) == Some(PodState::Warm.as_str())
            && (refusal_to_start(pod).is_some()
                || age_of(pod).is_some_and(|age| age >= self.warm.waiting_for))
    }
}

/// A top-up of one kind under way, which ends when this is dropped.
struct Refilling {
    pool: Arc<WarmPool>,
    label: String,
}

impl Refilling {
    /// The top-up of kind `label`, unless one is under way already.
    fn of(pool: Arc<WarmPool>, label: String) -> Option<Self> {
        let added = pool
            .refilling
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(label.clone());
        added.then_some(Self { pool, label })
    }
}

impl Drop for Refilling {
    fn drop(&mut self) {
        self.pool
            .refilling
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.label);
    }
}

/// The label selector of every code pod.
fn every_code_pod() -> String {
    format!("{}={}", SANDBOX_LABEL.0, SANDBOX_LABEL.1)
}

/// The label selector of the pods waiting for a run of `kind`.
fn waiting_for_kind(kind: &PodKind) -> String {
    format!(
        "{},{STATE_LABEL}={},{KEY_LABEL}={}",
        every_code_pod(),
        PodState::Warm.as_str(),
        kind.label()
    )
}

/// Deleting a pod only as it was read, so a waiting pod claimed since is
/// left to its run.
fn as_read(pod: &Pod) -> DeleteParams {
    DeleteParams {
        preconditions: Some(Preconditions {
            resource_version: pod.metadata.resource_version.clone(),
            uid: pod.metadata.uid.clone(),
        }),
        ..DeleteParams::background()
    }
}

/// Whether `pod` waits warm for a run of `kind`.
fn is_waiting_as(pod: &Pod, kind: &PodKind) -> bool {
    pod.metadata.deletion_timestamp.is_none()
        && state_label(pod) == Some(PodState::Warm.as_str())
        && label_of(pod, KEY_LABEL) == Some(kind.label().as_str())
}

/// `pod`'s state label.
fn state_label(pod: &Pod) -> Option<&str> {
    label_of(pod, STATE_LABEL)
}

/// The value of `pod`'s label `name`.
fn label_of<'p>(pod: &'p Pod, name: &str) -> Option<&'p str> {
    pod.metadata.labels.as_ref()?.get(name).map(String::as_str)
}

/// How long ago `pod` started, which its deadline counts from; zero when
/// the cluster's clock is ahead of this one.
fn age_of(pod: &Pod) -> Option<Duration> {
    let started = pod.status.as_ref()?.start_time.as_ref()?;
    let age = Utc::now().signed_duration_since(started.0);
    Some(age.to_std().unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::sandbox::runtime::Runtime;
    use k8s_openapi::chrono::TimeDelta;
    use serde_json::Value;

    use super::*;
    use crate::sandbox::cluster::pod::PodNetwork;

    fn pool() -> WarmPool {
        let warm = WarmPods {
            per_kind: 2,
            waiting_for: Duration::from_secs(900),
        };
        WarmPool::new(warm, Duration::from_secs(120), None)
    }

    fn kind() -> PodKind {
        PodKind {
            runtime: Runtime::Python313,
            image: "python:3.13-slim@sha256:ab".to_owned(),
            memory_mib: 256,
            network: PodNetwork::Closed,
        }
    }

    fn pod(state: PodState, minutes_old: i64, container: &Value) -> Pod {
        let started = Utc::now()
            .checked_sub_signed(TimeDelta::minutes(minutes_old))
            .unwrap();
        serde_json::from_value(json!({
            "metadata": {
                "name": "ianua-code-warm-1",
                "labels": {STATE_LABEL: state.as_str(), KEY_LABEL: kind().label()},
            },
            "status": {
                "phase": "Running",
                "startTime": started.to_rfc3339(),
                "containerStatuses": [{
                    "name": "code", "image": "i", "imageID": "", "ready": true,
                    "restartCount": 0, "state": container,
                }],
            },
        }))
        .unwrap()
    }

    fn running() -> Value {
        json!({"running": {}})
    }

    /// A young waiting pod whose container runs may be claimed; one that
    /// waited too long, or whose container has not started, may not.
    #[test]
    fn only_a_young_running_pod_is_claimable() {
        let young = pod(PodState::Warm, 2, &running());
        let old = pod(PodState::Warm, 20, &running());
        let pulling = pod(
            PodState::Warm,
            1,
            &json!({"waiting": {"reason": "ContainerCreating"}}),
        );

        assert!(pool().is_claimable(&young));
        assert!(!pool().is_claimable(&old));
        assert!(!pool().is_claimable(&pulling));
    }

    /// A pod that waited too long or whose image will not start is done
    /// with; a claimed pod, however old, belongs to its run.
    #[test]
    fn stale_and_broken_waiting_pods_are_done_with() {
        let old = pod(PodState::Warm, 20, &running());
        let broken = pod(
            PodState::Warm,
            1,
            &json!({"waiting": {"reason": "ErrImagePull"}}),
        );
        let serving = pod(PodState::Claimed, 20, &running());

        assert!(pool().is_done_with(&old));
        assert!(pool().is_done_with(&broken));
        assert!(!pool().is_done_with(&serving));
    }

    /// A pod that ended is done with, whatever its state.
    #[test]
    fn an_ended_pod_is_done_with() {
        let mut ended = pod(
            PodState::Claimed,
            1,
            &json!({"terminated": {"exitCode": 0}}),
        );
        if let Some(status) = ended.status.as_mut() {
            status.phase = Some("Succeeded".to_owned());
        }

        assert!(pool().is_done_with(&ended));
    }

    /// A waiting pod's deadline lies past the longest wait, the longest run
    /// and the grace, so shortening it to any run's is always allowed.
    #[test]
    fn a_claim_only_ever_shortens_the_deadline() {
        let longest_claim = Duration::from_secs(900 + u64::from(MAX_RUN_SECONDS) + 120);

        assert!(pool().waiting_deadline() >= longest_claim);
    }

    /// The pool asks only for waiting pods of the run's kind.
    #[test]
    fn the_claim_asks_for_its_kind_only() {
        let selector = waiting_for_kind(&kind());

        assert_eq!(
            selector,
            format!(
                "ianua.io/sandbox=code,ianua.io/state=warm,ianua.io/warm-key={}",
                kind().label()
            )
        );
        assert!(is_waiting_as(&pod(PodState::Warm, 1, &running()), &kind()));
    }
}
