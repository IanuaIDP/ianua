//! The pod a run gets: the version's image, its files streamed in, and
//! everything else closed.
//!
//! The pod holds no Kubernetes key and no service links, runs as nobody
//! with no capabilities, no way to gain any and the runtime's system-call
//! filter, keeps a read-only root, and is held to its memory, one CPU and a
//! little disk. The namespace's network policy lets nothing in or out, name
//! lookups included.
//!
//! The pod knows nothing of the run it will serve, so one can be started
//! ahead and kept warm: its run is streamed in as `streamed` describes.
//! Kubernetes ends a pod that outlives its deadline, which a claimed pod
//! has shortened to its run's.

use std::time::Duration;

use k8s_openapi::api::core::v1::Pod;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::sandbox::entry::{Entry, MOUNTED_AT, entry_of};
use crate::sandbox::streamed::start_script;

/// The label every code pod carries, so the namespace's policies and the
/// pool's sweep find them.
pub(super) const SANDBOX_LABEL: (&str, &str) = ("ianua.io/sandbox", "code");

/// The label saying whether a pod waits warm or serves a run.
pub(super) const STATE_LABEL: &str = "ianua.io/state";

/// The label naming the runtime, image and memory a pod was made for.
pub(super) const KEY_LABEL: &str = "ianua.io/warm-key";

/// The label saying whether a pod may reach the network filter, which the
/// namespace's policy lets such a pod reach and nothing else.
pub(super) const NETWORK_LABEL: &str = "ianua.io/network";

/// The one container's name.
pub(super) const CONTAINER: &str = "code";

/// Whether a pod reaches the network filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum PodNetwork {
    /// No network at all.
    Closed,
    /// The network filter alone.
    Proxied,
}

impl PodNetwork {
    /// The label value.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Proxied => "proxied",
        }
    }
}

/// What a pod is made for: the runtime that starts the code, the exact
/// image, the memory it is held to, and whether it reaches the network
/// filter. A run takes only a pod made for exactly its own.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PodKind {
    /// The runtime's name, such as `python-3.13`, which picks its entry.
    pub(super) runtime: ianua_domain::domains::workflows::sandbox::runtime::Runtime,
    /// The image it runs in, named by its content.
    pub(super) image: String,
    /// The memory it is held to, in MiB.
    pub(super) memory_mib: u32,
    /// Whether it reaches the network filter.
    pub(super) network: PodNetwork,
}

impl PodKind {
    /// A label value naming this kind: a digest, since an image reference
    /// is no label value.
    pub(super) fn label(&self) -> String {
        let named = format!(
            "{}|{}|{}|{}",
            self.runtime.as_str(),
            self.image,
            self.memory_mib,
            self.network.as_str()
        );
        let digest = Sha256::digest(named.as_bytes());
        let hex: String = digest
            .iter()
            .take(12)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("k{hex}")
    }

    /// How the runtime starts its code.
    fn entry(&self) -> Entry {
        entry_of(self.runtime)
    }
}

/// Whether a pod waits for a run or serves one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PodState {
    /// Started ahead, waiting for a run to claim it.
    Warm,
    /// Serving one run.
    Claimed,
}

impl PodState {
    /// The label value.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Warm => "warm",
            Self::Claimed => "claimed",
        }
    }
}

/// What one pod is made of.
pub(super) struct PodPlan<'a> {
    /// Its name, unique to it.
    pub(super) name: &'a str,
    /// What it is made for.
    pub(super) kind: &'a PodKind,
    /// The runtime class the pod runs under, such as `gvisor`.
    pub(super) runtime_class: Option<&'a str>,
    /// Whether it waits warm or serves a run now.
    pub(super) state: PodState,
    /// How long after it starts Kubernetes ends it.
    pub(super) deadline: Duration,
}

/// The pod `plan` describes.
///
/// # Errors
///
/// When the description does not read as a pod, which it always does.
pub(super) fn pod_of(plan: &PodPlan<'_>) -> Result<Pod, serde_json::Error> {
    serde_json::from_value(pod_json(plan))
}

/// Describes the pod's identity and labels alongside its isolated execution spec.
fn pod_json(plan: &PodPlan<'_>) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": plan.name,
            "labels": {
                SANDBOX_LABEL.0: SANDBOX_LABEL.1,
                STATE_LABEL: plan.state.as_str(),
                KEY_LABEL: plan.kind.label(),
                NETWORK_LABEL: plan.kind.network.as_str(),
                "app.kubernetes.io/managed-by": "ianua",
            },
        },
        "spec": pod_spec(plan),
    })
}

/// Applies pod-wide isolation, lifetime and scratch-volume limits.
fn pod_spec(plan: &PodPlan<'_>) -> Value {
    json!({
        "restartPolicy": "Never",
        "runtimeClassName": plan.runtime_class,
        "automountServiceAccountToken": false,
        "enableServiceLinks": false,
        "activeDeadlineSeconds": plan.deadline.as_secs().max(1),
        "terminationGracePeriodSeconds": 0,
        "securityContext": {
            "runAsNonRoot": true,
            "runAsUser": 65534,
            "runAsGroup": 65534,
            "fsGroup": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [container_json(plan.kind)],
        "volumes": [
            {"name": "sandbox", "emptyDir": {"sizeLimit": "300Mi"}},
            {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
        ],
    })
}

/// Describes the code container's streamed entry, limits and read-only root.
fn container_json(kind: &PodKind) -> Value {
    let memory = format!("{}Mi", kind.memory_mib);
    let entry = kind.entry();
    json!({
        "name": CONTAINER,
        "image": kind.image,
        "command": ["sh", "-c", start_script(&entry)],
        "stdin": true,
        "stdinOnce": true,
        "tty": false,
        "workingDir": "/tmp",
        "env": environment(&entry),
        "resources": {
            "limits": {"memory": memory, "cpu": "1", "ephemeral-storage": "512Mi"},
            "requests": {"memory": memory, "cpu": "100m", "ephemeral-storage": "256Mi"},
        },
        "securityContext": {
            "allowPrivilegeEscalation": false,
            "privileged": false,
            "readOnlyRootFilesystem": true,
            "capabilities": {"drop": ["ALL"]},
        },
        "volumeMounts": [
            {"name": "sandbox", "mountPath": MOUNTED_AT},
            {"name": "tmp", "mountPath": "/tmp"},
        ],
    })
}

/// Gives the runtime its entry-specific variables and a writable temporary home.
fn environment(entry: &Entry) -> Vec<Value> {
    let mut environment = vec![json!({"name": "HOME", "value": "/tmp"})];
    environment.extend(
        entry
            .environment
            .iter()
            .map(|(name, value)| json!({"name": name, "value": value})),
    );
    environment
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::sandbox::runtime::Runtime;

    use super::*;

    fn kind() -> PodKind {
        PodKind {
            runtime: Runtime::Python313,
            image: "python:3.13-slim@sha256:ab".to_owned(),
            memory_mib: 256,
            network: PodNetwork::Closed,
        }
    }

    fn planned(state: PodState) -> Value {
        pod_json(&PodPlan {
            name: "ianua-code-1",
            kind: &kind(),
            runtime_class: Some("gvisor"),
            state,
            deadline: Duration::from_secs(150),
        })
    }

    /// A pod holds no Kubernetes key, runs as nobody under the runtime
    /// class, with no capabilities, a read-only root and its memory, and
    /// Kubernetes ends it at its deadline.
    #[test]
    fn a_pod_is_made_locked_down() {
        let pod = planned(PodState::Claimed);
        let spec = &pod["spec"];
        let container = &spec["containers"][0];

        assert_eq!(spec["runtimeClassName"], "gvisor");
        assert_eq!(spec["automountServiceAccountToken"], false);
        assert_eq!(spec["enableServiceLinks"], false);
        assert_eq!(spec["activeDeadlineSeconds"], 150);
        assert_eq!(spec["securityContext"]["runAsUser"], 65534);
        assert_eq!(container["securityContext"]["readOnlyRootFilesystem"], true);
        assert_eq!(
            container["securityContext"]["allowPrivilegeEscalation"],
            false
        );
        assert_eq!(
            container["securityContext"]["capabilities"]["drop"][0],
            "ALL"
        );
        assert_eq!(container["resources"]["limits"]["memory"], "256Mi");
        assert_eq!(pod["metadata"]["labels"]["ianua.io/sandbox"], "code");
    }

    /// A pod starts with the script that reads its run from its input, so
    /// it knows nothing of the run beforehand.
    #[test]
    fn the_pod_starts_with_the_streamed_script() {
        let command = &planned(PodState::Warm)["spec"]["containers"][0]["command"];

        assert_eq!(command[0], "sh");
        assert_eq!(command[2], start_script(&entry_of(Runtime::Python313)));
    }

    /// A warm pod and a claimed one carry their state, and both the label of
    /// what they were made for and whether they reach the network filter;
    /// another memory, or reaching the filter, is another kind.
    #[test]
    fn a_pod_is_labelled_with_its_state_and_kind() {
        let warm = planned(PodState::Warm);
        let larger = PodKind {
            memory_mib: 512,
            ..kind()
        };
        let proxied = PodKind {
            network: PodNetwork::Proxied,
            ..kind()
        };

        assert_eq!(warm["metadata"]["labels"]["ianua.io/state"], "warm");
        assert_eq!(warm["metadata"]["labels"]["ianua.io/network"], "closed");
        assert_eq!(
            warm["metadata"]["labels"]["ianua.io/warm-key"],
            kind().label()
        );
        assert_ne!(kind().label(), larger.label());
        assert_ne!(kind().label(), proxied.label());
        assert!(kind().label().len() <= 63);
    }

    /// The description reads as a Kubernetes pod.
    #[test]
    fn the_description_is_a_pod() {
        let plan = PodPlan {
            name: "ianua-code-2",
            kind: &PodKind {
                runtime: Runtime::Node22,
                image: "node:22-slim@sha256:cd".to_owned(),
                memory_mib: 128,
                network: PodNetwork::Proxied,
            },
            runtime_class: None,
            state: PodState::Claimed,
            deadline: Duration::from_secs(65),
        };

        let pod = pod_of(&plan).unwrap();

        assert_eq!(pod.metadata.name.as_deref(), Some("ianua-code-2"));
    }
}
