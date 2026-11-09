//! One run in its pod: a pod made for it waited on until its container
//! starts, or a warm one claimed; then attached to and handed its input,
//! read while it runs, and its end read from the pod's status.

use std::time::Duration;

use ianua_domain::domains::workflows::data::MAX_SIZE;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use k8s_openapi::api::core::v1::{ContainerState, Pod};
use kube::api::{Api, AttachParams, PostParams};
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::files::StoredFile;
use crate::sandbox::cluster::pod::CONTAINER;
use crate::sandbox::output::{
    ERRORS_HELD, Ended, Exit, Memory, bounded, code_outcome, ignore_closed_input, last_of,
};
use crate::sandbox::streamed::Header;

/// How often the pod is read while it starts and after its streams end.
const ASK_EVERY: Duration = Duration::from_millis(250);

/// How long the pod's status may take to show its container ended, once
/// its streams have.
const END_SHOWN_WITHIN: Duration = Duration::from_secs(30);

/// Waiting reasons that mean the container will not start as asked: its
/// image cannot be had, or its description is refused.
const WILL_NOT_START: [&str; 6] = [
    "ErrImagePull",
    "ImagePullBackOff",
    "InvalidImageName",
    "CreateContainerConfigError",
    "CreateContainerError",
    "RunContainerError",
];

/// What a pod is sent on its input: the bundle, then the run's own files.
pub(super) struct Sent<'a> {
    /// The version's bundle, read from the file store as it streams.
    pub(super) bundle: StoredFile,
    /// The run's code, entry and input, packed.
    pub(super) files: &'a [u8],
}

/// One run in a pod whose container has started.
pub(super) struct Run<'a> {
    /// The pod's name.
    pub(super) pod: &'a str,
    /// How long the code may run.
    pub(super) seconds: u32,
    /// How long handing the pod its input may take, beyond that.
    pub(super) grace: Duration,
    /// The network filter the code reaches its hosts through; `None` when
    /// it reaches no network.
    pub(super) proxy: Option<String>,
}

/// Makes `pod` and waits until its container has started, for up to
/// `grace`.
pub(super) async fn create_and_start(
    pods: &Api<Pod>,
    pod: &Pod,
    grace: Duration,
) -> Result<(), String> {
    pods.create(&PostParams::default(), pod)
        .await
        .map_err(|error| format!("the cluster did not take the pod: {error}"))?;
    let Some(name) = pod.metadata.name.as_deref() else {
        return Err("the pod has no name".to_owned());
    };
    wait_for_start(pods, name, grace).await
}

/// Runs `run` with `sent` on the pod's input, and reads how it ended.
pub(super) async fn ran(pods: &Api<Pod>, run: &Run<'_>, sent: Sent<'_>) -> Ended {
    let limit = Duration::from_secs(u64::from(run.seconds)).saturating_add(run.grace);
    let Ok(streamed) = tokio::time::timeout(limit, attached(pods, run, sent)).await else {
        return Ended::Ran(CodeOutcome::Failed(CodeFailure::TimedOut));
    };
    match streamed {
        Ok((answer, errors)) => ended(pods, run.pod, answer, errors).await,
        Err(why) => Ended::NotStarted(why),
    }
}

/// Waits until the pod's container has started, for up to `grace`.
pub(super) async fn wait_for_start(
    pods: &Api<Pod>,
    name: &str,
    grace: Duration,
) -> Result<(), String> {
    let waited = tokio::time::timeout(grace, async {
        loop {
            let pod = pods
                .get(name)
                .await
                .map_err(|error| format!("the pod could not be read: {error}"))?;
            if let Some(why) = refusal_to_start(&pod) {
                return Err(why);
            }
            if has_started(&pod) {
                return Ok(());
            }
            tokio::time::sleep(ASK_EVERY).await;
        }
    })
    .await;
    waited.unwrap_or_else(|_| Err(format!("the pod did not start within {}s", grace.as_secs())))
}

/// Attaches to the pod, hands it the header line and `sent`, and reads
/// what it writes until its streams end: its answer and the end of its
/// errors.
async fn attached(
    pods: &Api<Pod>,
    run: &Run<'_>,
    sent: Sent<'_>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let parameters = AttachParams::default()
        .container(CONTAINER)
        .stdin(true)
        .stdout(true)
        .stderr(true);
    let mut process = pods
        .attach(run.pod, &parameters)
        .await
        .map_err(|error| format!("the pod could not be attached to: {error}"))?;
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (process.stdin(), process.stdout(), process.stderr())
    else {
        return Err("the pod's streams were not opened".to_owned());
    };
    let header = input_header(run, &sent);
    let written = write_input(stdin, sent, &header);
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

/// Describes the exact byte counts and limits preceding a pod's streamed run.
fn input_header(run: &Run<'_>, sent: &Sent<'_>) -> Header {
    Header {
        bundle_bytes: sent.bundle.length(),
        files_bytes: u64::try_from(sent.files.len()).unwrap_or(u64::MAX),
        seconds: run.seconds,
        proxy: run.proxy.clone(),
    }
}

/// Streams the header, bounded bundle and run files into the attached pod.
async fn write_input(
    mut stdin: impl AsyncWrite + Unpin,
    sent: Sent<'_>,
    header: &Header,
) -> std::io::Result<()> {
    stdin.write_all(header.line().as_bytes()).await?;
    tokio::io::copy(
        &mut sent.bundle.into_reader().take(header.bundle_bytes),
        &mut stdin,
    )
    .await?;
    stdin.write_all(sent.files).await?;
    stdin.flush().await
}

/// How the run ended, once the pod's status shows its container ended.
pub(super) async fn ended(pods: &Api<Pod>, name: &str, answer: Vec<u8>, errors: Vec<u8>) -> Ended {
    let shown = tokio::time::timeout(END_SHOWN_WITHIN, async {
        loop {
            if let Ok(pod) = pods.get(name).await
                && let Some(end) = end_of(&pod)
            {
                return end;
            }
            tokio::time::sleep(ASK_EVERY).await;
        }
    })
    .await;
    let Ok(end) = shown else {
        return Ended::NotStarted("the pod's end was not shown".to_owned());
    };
    if end.past_its_deadline {
        return Ended::Ran(CodeOutcome::Failed(CodeFailure::TimedOut));
    }
    let exit = Exit {
        status: end.status,
        answer,
        errors,
        memory: end.memory,
    };
    Ended::Ran(code_outcome(&exit))
}

/// How a pod's container ended, as its status shows it.
struct End {
    status: Option<i32>,
    memory: Memory,
    past_its_deadline: bool,
}

/// How `pod`'s container ended, once it has.
fn end_of(pod: &Pod) -> Option<End> {
    let status = pod.status.as_ref()?;
    let past_its_deadline = status.reason.as_deref() == Some("DeadlineExceeded");
    let terminated = state_of(pod).and_then(|state| state.terminated.as_ref());
    match (terminated, past_its_deadline) {
        (Some(terminated), _) => Some(End {
            status: Some(terminated.exit_code),
            memory: match terminated.reason.as_deref() {
                Some("OOMKilled") => Memory::OverItsLimit,
                _ => Memory::WithinItsLimit,
            },
            past_its_deadline,
        }),
        (None, true) => Some(End {
            status: None,
            memory: Memory::WithinItsLimit,
            past_its_deadline,
        }),
        (None, false) => None,
    }
}

/// Whether `pod`'s container started, or ended already.
fn has_started(pod: &Pod) -> bool {
    let failed = pod
        .status
        .as_ref()
        .and_then(|status| status.phase.as_deref())
        == Some("Failed");
    failed
        || state_of(pod).is_some_and(|state| state.running.is_some() || state.terminated.is_some())
}

/// Why `pod`'s container will not start, when its waiting says so.
pub(super) fn refusal_to_start(pod: &Pod) -> Option<String> {
    let waiting = state_of(pod)?.waiting.as_ref()?;
    let reason = waiting.reason.as_deref()?;
    WILL_NOT_START.contains(&reason).then(|| {
        format!(
            "the pod will not start: {reason}: {}",
            waiting.message.as_deref().unwrap_or_default()
        )
    })
}

/// The state of `pod`'s one container.
pub(super) fn state_of(pod: &Pod) -> Option<&ContainerState> {
    pod.status
        .as_ref()?
        .container_statuses
        .as_ref()?
        .first()?
        .state
        .as_ref()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn pod(status: &serde_json::Value) -> Pod {
        serde_json::from_value(json!({"metadata": {"name": "p"}, "status": status})).unwrap()
    }

    /// A container killed for its memory reads as out of memory; a pod
    /// Kubernetes ended at its deadline reads as past it.
    #[test]
    fn the_end_is_read_from_the_pod() {
        let killed = pod(&json!({"containerStatuses": [{
            "name": "code", "image": "i", "imageID": "", "ready": false, "restartCount": 0,
            "state": {"terminated": {"exitCode": 137, "reason": "OOMKilled"}},
        }]}));
        let late = pod(&json!({"phase": "Failed", "reason": "DeadlineExceeded"}));

        let killed = end_of(&killed).unwrap();
        let late = end_of(&late).unwrap();

        assert_eq!(
            (killed.status, killed.memory),
            (Some(137), Memory::OverItsLimit)
        );
        assert!(late.past_its_deadline);
    }

    /// An image-pull failure supplies its refusal reason, while a container
    /// still being created has neither started nor been refused.
    #[test]
    fn an_image_that_cannot_be_pulled_is_a_refusal() {
        let stuck = pod(&json!({"containerStatuses": [{
            "name": "code", "image": "i", "imageID": "", "ready": false, "restartCount": 0,
            "state": {"waiting": {"reason": "ErrImagePull", "message": "not found"}},
        }]}));
        let pulling = pod(&json!({"containerStatuses": [{
            "name": "code", "image": "i", "imageID": "", "ready": false, "restartCount": 0,
            "state": {"waiting": {"reason": "ContainerCreating"}},
        }]}));

        assert!(refusal_to_start(&stuck).is_some_and(|why| why.contains("ErrImagePull")));
        assert!(refusal_to_start(&pulling).is_none());
        assert!(!has_started(&pulling));
    }
}
