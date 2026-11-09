//! A company's own image on the cluster: one pod made for its run, never a
//! warm one, locked down as a code pod is, as the image's own entry point
//! starts it.
//!
//! The registry's login goes in a pull secret of the run's own, made just
//! before the pod and then owned by it, so Kubernetes deletes it with the
//! pod; one a stopped worker left without an owner is removed by the next
//! image run. The image is pulled for every run, so a copy the node keeps
//! never stands in for the login. The pod has the start-up grace to pull its image; one that
//! cannot be pulled, or does not start in time, did not run. Its input is
//! handed over on its attached input, which is then closed; it is read
//! while it runs and stopped a moment after its time limit.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;
use ianua_app::ports::workflows::PullLogin;
use ianua_domain::domains::workflows::data::MAX_SIZE;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use ianua_domain::domains::workflows::sandbox::image::PinnedImage;
use ianua_domain::types::UntrustedText;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{Pod, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
use k8s_openapi::chrono::{DateTime, Utc};
use kube::api::{Api, AttachParams, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt as _;

use crate::sandbox::cluster::pod::{
    CONTAINER, NETWORK_LABEL, PodNetwork, PodState, SANDBOX_LABEL, STATE_LABEL,
};
use crate::sandbox::cluster::running::{ended, wait_for_start};
use crate::sandbox::container::IMAGE_KILL_MARGIN;
use crate::sandbox::output::{ERRORS_HELD, Ended, bounded, ignore_closed_input, last_of};

/// The label every pull secret of an image run carries.
const PULL_LABEL: (&str, &str) = ("ianua.io/sandbox", "pull");

/// One run of a company's image, to make.
pub(super) struct ImageRun<'a> {
    /// The pod's name, which its pull secret shares.
    pub(super) name: &'a str,
    /// The image, pinned to its digest.
    pub(super) image: &'a PinnedImage,
    /// The memory it is held to, in MiB.
    pub(super) memory_mib: u32,
    /// How long it may run, in seconds.
    pub(super) seconds: u32,
    /// The network filter, its ticket in it; `None` for no network.
    pub(super) proxy: Option<&'a str>,
    /// The runtime class the pod runs under.
    pub(super) runtime_class: Option<&'a str>,
    /// How long its image may take to be pulled and the pod to start.
    pub(super) grace: Duration,
}

/// Where an image run's objects are made.
pub(super) struct Objects<'a> {
    /// The namespace's pods.
    pub(super) pods: &'a Api<Pod>,
    /// The namespace's secrets.
    pub(super) secrets: &'a Api<Secret>,
}

/// Runs `run` with `input` and `login`, deleting its pod however it went;
/// its pull secret goes with the pod.
pub(super) async fn ran(
    objects: &Objects<'_>,
    run: &ImageRun<'_>,
    login: &PullLogin,
    input: &str,
) -> Ended {
    remove_orphaned_secrets(objects.secrets, run.grace).await;
    let ended = match start(objects, run, login).await {
        Ok(()) => in_pod(objects.pods, run, input).await,
        Err(why) => Ended::Ran(CodeOutcome::Failed(CodeFailure::NotRun(
            UntrustedText::record(&format!("the image was not pulled or did not start: {why}")),
        ))),
    };
    if let Err(error) = objects
        .pods
        .delete(run.name, &DeleteParams::background())
        .await
    {
        tracing::warn!(%error, pod = %run.name, "an image run's pod could not be deleted");
    }
    ended
}

/// Makes `run`'s pull secret and pod, hands the secret to the pod, and
/// waits for its container to start.
async fn start(objects: &Objects<'_>, run: &ImageRun<'_>, login: &PullLogin) -> Result<(), String> {
    let secret = pull_secret(run, login);
    if let Some(secret) = &secret {
        objects
            .secrets
            .create(&PostParams::default(), secret)
            .await
            .map_err(|error| format!("the pull secret was not made: {error}"))?;
    }
    let pod = serde_json::from_value::<Pod>(pod_json(run, secret.as_ref()))
        .map_err(|error| format!("the pod could not be described: {error}"))?;
    let made = objects
        .pods
        .create(&PostParams::default(), &pod)
        .await
        .map_err(|error| format!("the cluster did not take the pod: {error}"))?;
    if secret.is_some() {
        own_secret(objects.secrets, run.name, made.metadata.uid.as_deref()).await;
    }
    wait_for_start(objects.pods, run.name, run.grace).await
}

/// Hands the started pod its input, closes it, reads what it writes and
/// how it ended.
async fn in_pod(pods: &Api<Pod>, run: &ImageRun<'_>, input: &str) -> Ended {
    let limit = Duration::from_secs(u64::from(run.seconds)).saturating_add(IMAGE_KILL_MARGIN);
    let Ok(streamed) = tokio::time::timeout(limit, attached(pods, run.name, input)).await else {
        return Ended::Ran(CodeOutcome::Failed(CodeFailure::TimedOut));
    };
    match streamed {
        Ok((answer, errors)) => ended(pods, run.name, answer, errors).await,
        Err(why) => Ended::NotStarted(why),
    }
}

/// Attaches to pod `name`, writes `input` and closes its input, and reads
/// its answer and the end of its errors until its streams end.
async fn attached(pods: &Api<Pod>, name: &str, input: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let parameters = AttachParams::default()
        .container(CONTAINER)
        .stdin(true)
        .stdout(true)
        .stderr(true);
    let mut process = pods
        .attach(name, &parameters)
        .await
        .map_err(|error| format!("the pod could not be attached to: {error}"))?;
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (process.stdin(), process.stdout(), process.stderr())
    else {
        return Err("the pod's streams were not opened".to_owned());
    };
    let written = async move {
        stdin.write_all(input.as_bytes()).await?;
        stdin.shutdown().await
    };
    let (written, answer, errors) = tokio::join!(
        written,
        bounded(stdout, MAX_SIZE),
        last_of(stderr, ERRORS_HELD)
    );
    written
        .or_else(ignore_closed_input)
        .map_err(|error| format!("the pod's input could not be written: {error}"))?;
    let read = |error: std::io::Error| format!("the pod's output could not be read: {error}");
    Ok((answer.map_err(read)?, errors.map_err(read)?))
}

/// The pod `run` gets, naming its pull secret `secret` when it has one.
fn pod_json(run: &ImageRun<'_>, secret: Option<&Secret>) -> Value {
    let network = match run.proxy {
        Some(_) => PodNetwork::Proxied,
        None => PodNetwork::Closed,
    };
    let secrets: Vec<Value> = secret
        .map(|_| json!({"name": run.name}))
        .into_iter()
        .collect();
    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": run.name,
            "labels": {
                SANDBOX_LABEL.0: SANDBOX_LABEL.1,
                STATE_LABEL: PodState::Claimed.as_str(),
                NETWORK_LABEL: network.as_str(),
                "app.kubernetes.io/managed-by": "ianua",
            },
        },
        "spec": pod_spec(run, &secrets),
    })
}

/// The pod's spec: locked down, ended at its run's time and grace, pulling
/// with `secrets`.
fn pod_spec(run: &ImageRun<'_>, secrets: &[Value]) -> Value {
    json!({
            "restartPolicy": "Never",
            "runtimeClassName": run.runtime_class,
            "automountServiceAccountToken": false,
            "enableServiceLinks": false,
            "activeDeadlineSeconds": Duration::from_secs(u64::from(run.seconds))
                .saturating_add(run.grace)
                .as_secs()
                .max(1),
            "terminationGracePeriodSeconds": 0,
            "imagePullSecrets": secrets,
            "securityContext": {
                "runAsNonRoot": true,
                "runAsUser": 65534,
                "runAsGroup": 65534,
                "fsGroup": 65534,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [container_json(run)],
            "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}],
    })
}

/// The image's one container: its memory, a read-only root, no
/// capabilities, its input attached, and the filter as its proxy.
fn container_json(run: &ImageRun<'_>) -> Value {
    let memory = format!("{}Mi", run.memory_mib);
    let mut environment = vec![json!({"name": "HOME", "value": "/tmp"})];
    if let Some(proxy) = run.proxy {
        environment.extend(
            ["HTTPS_PROXY", "https_proxy"].map(|name| json!({"name": name, "value": proxy})),
        );
    }
    json!({
        "name": CONTAINER,
        "image": run.image.as_str(),
        "imagePullPolicy": "Always",
        "stdin": true,
        "stdinOnce": true,
        "tty": false,
        "workingDir": "/tmp",
        "env": environment,
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
        "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
    })
}

/// The pull secret holding `login` for `run`'s registry; `None` for no
/// login.
fn pull_secret(run: &ImageRun<'_>, login: &PullLogin) -> Option<Secret> {
    let PullLogin::Password { username, password } = login else {
        return None;
    };
    let pair = format!("{}:{}", username.as_str(), password.expose());
    let auth = base64::engine::general_purpose::STANDARD.encode(pair);
    let config = json!({"auths": {run.image.registry().as_str(): {"auth": auth}}});
    let labels = BTreeMap::from([
        (PULL_LABEL.0.to_owned(), PULL_LABEL.1.to_owned()),
        (
            "app.kubernetes.io/managed-by".to_owned(),
            "ianua".to_owned(),
        ),
    ]);
    Some(Secret {
        metadata: ObjectMeta {
            name: Some(run.name.to_owned()),
            labels: Some(labels),
            ..ObjectMeta::default()
        },
        type_: Some("kubernetes.io/dockerconfigjson".to_owned()),
        data: Some(BTreeMap::from([(
            ".dockerconfigjson".to_owned(),
            ByteString(config.to_string().into_bytes()),
        )])),
        ..Secret::default()
    })
}

/// Makes pod `name`, of `uid`, the owner of its pull secret, so Kubernetes
/// deletes the secret with the pod.
async fn own_secret(secrets: &Api<Secret>, name: &str, uid: Option<&str>) {
    let Some(uid) = uid else {
        tracing::warn!(pod = %name, "the pod was made without an id; its pull secret is removed later");
        return;
    };
    let owner = json!({"metadata": {"ownerReferences": [
        {"apiVersion": "v1", "kind": "Pod", "name": name, "uid": uid},
    ]}});
    if let Err(error) = secrets
        .patch(name, &PatchParams::default(), &Patch::Merge(&owner))
        .await
    {
        tracing::warn!(%error, pod = %name, "a pull secret was not handed to its pod");
    }
}

/// Removes pull secrets no pod owns that are older than twice `grace`: left
/// by a worker that stopped between making one and its pod.
async fn remove_orphaned_secrets(secrets: &Api<Secret>, grace: Duration) {
    let selector = format!("{}={}", PULL_LABEL.0, PULL_LABEL.1);
    let Ok(listed) = secrets.list(&ListParams::default().labels(&selector)).await else {
        return;
    };
    for secret in listed
        .items
        .iter()
        .filter(|secret| is_orphaned(secret, grace))
    {
        let Some(name) = secret.metadata.name.as_deref() else {
            continue;
        };
        if let Err(error) = secrets.delete(name, &DeleteParams::background()).await {
            tracing::warn!(%error, secret = %name, "an orphaned pull secret could not be removed");
        }
    }
}

/// Whether `secret` has no owner and is older than twice `grace`.
fn is_orphaned(secret: &Secret, grace: Duration) -> bool {
    let owned = secret
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| !owners.is_empty());
    let old = secret
        .metadata
        .creation_timestamp
        .as_ref()
        .is_some_and(|Time(made)| older_than(made, grace.saturating_mul(2)));
    !owned && old
}

/// Whether `made` lies more than `age` ago.
fn older_than(made: &DateTime<Utc>, age: Duration) -> bool {
    Utc::now()
        .signed_duration_since(*made)
        .to_std()
        .is_ok_and(|since| since > age)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::sandbox::registry::RegistryUsername;
    use ianua_domain::shared::security::secret::Secret as Password;

    use super::*;

    fn image() -> PinnedImage {
        PinnedImage::parse(&format!(
            "registry.acme.example/codegen@sha256:{}",
            "ab".repeat(32)
        ))
        .unwrap()
    }

    fn run(image: &PinnedImage) -> ImageRun<'_> {
        ImageRun {
            name: "ianua-code-7",
            image,
            memory_mib: 512,
            seconds: 60,
            proxy: None,
            runtime_class: Some("gvisor"),
            grace: Duration::from_secs(120),
        }
    }

    /// The image's pod holds no Kubernetes key, runs as nobody under the
    /// runtime class with a read-only root and no capabilities, as its own
    /// entry point starts it, and names its pull secret.
    #[test]
    fn an_image_pod_is_made_locked_down() {
        let image = image();

        let pod = pod_json(&run(&image), Some(&Secret::default()));
        let spec = &pod["spec"];
        let container = &spec["containers"][0];

        assert_eq!(spec["runtimeClassName"], "gvisor");
        assert_eq!(spec["automountServiceAccountToken"], false);
        assert_eq!(spec["securityContext"]["runAsUser"], 65534);
        assert_eq!(spec["imagePullSecrets"][0]["name"], "ianua-code-7");
        assert_eq!(spec["activeDeadlineSeconds"], 180);
        assert_eq!(container["securityContext"]["readOnlyRootFilesystem"], true);
        assert_eq!(
            container["securityContext"]["capabilities"]["drop"][0],
            "ALL"
        );
        assert!(container.get("command").is_none());
        assert_eq!(container["imagePullPolicy"], "Always");
        assert!(serde_json::from_value::<Pod>(pod).is_ok());
    }

    /// A pull secret names the image's registry with the login; an
    /// anonymous pull makes none.
    #[test]
    fn the_pull_secret_holds_the_registry_login() {
        let image = image();
        let login = PullLogin::Password {
            username: RegistryUsername::new("robot").unwrap(),
            password: Password::new("s3cret"),
        };

        let secret = pull_secret(&run(&image), &login).unwrap();

        let held = &secret.data.unwrap()[".dockerconfigjson"].0;
        let held = String::from_utf8(held.clone()).unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode("robot:s3cret");
        assert!(held.contains(&format!(r#""registry.acme.example":{{"auth":"{auth}"}}"#)));
        assert_eq!(
            secret.type_.as_deref(),
            Some("kubernetes.io/dockerconfigjson")
        );
        assert!(pull_secret(&run(&image), &PullLogin::Anonymous).is_none());
    }
}
