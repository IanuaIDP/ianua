//! Code reaching the network: a version names the hosts its code may
//! reach, and its runs reach those through the network filter and nothing
//! else. The runs go through the sandbox gate on the local engine; the
//! filter and a stand-in for the allowed service run beside the stack, the
//! stand-in answering for every host the filter is asked for, so only the
//! filter decides which host is reached.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;

use ianua_infra::sandbox::{ProxyServing, SandboxProxy, TicketKey, Upstreams};
use ianua_scenarios::api::workflows;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::workflows::{Edge, Execution, Graph, Node, Step};
use ianua_scenarios::world::World;
use rcgen::{CertificateParams, KeyPair};
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;

use crate::code::gate::RunningGate;
use crate::code::registry::{Fingerprints, registry};
use crate::code::running::{Recipe, begun, code_step, finished, ready, step_of};
use crate::support::{APPROVAL_STEP, ApprovalStep, Approver, run};

/// The engine's network runs reaching the filter join.
const EGRESS_NETWORK: &str = "ianua-scenario-egress";

/// How a container on the engine's network reaches this machine.
const THIS_MACHINE: &str = "host.docker.internal";

/// The host Ann's version may reach.
const ALLOWED: &str = "api.allowed.test";

/// What the allowed service answers.
const ANSWER: &str = r#"{"reached":true}"#;

/// Python that asks both hosts and says what came of each: the service's
/// answer, or the kind of error the attempt raised.
const ASK_BOTH: &str = "import json\nimport ssl\nimport urllib.request\n\n\
def main(input):\n\
\tcontext = ssl._create_unverified_context()\n\
\treached = {}\n\
\tfor name, host in [('allowed', 'api.allowed.test'), ('other', 'api.other.test')]:\n\
\t\ttry:\n\
\t\t\tbody = urllib.request.urlopen('https://' + host + '/', context=context, timeout=10).read()\n\
\t\t\treached[name] = json.loads(body)['reached']\n\
\t\texcept Exception as error:\n\
\t\t\treached[name] = type(error).__name__\n\
\treturn reached\n";

/// The filter serving in this process until stopped, with the key it
/// shares with the stack's worker.
struct RunningFilter {
    port: u16,
    key: String,
    stop: oneshot::Sender<()>,
    served: JoinHandle<()>,
}

impl RunningFilter {
    /// A filter reaching every allowed host at `stand_in`, on a fresh port
    /// containers reach, with a key made now.
    async fn start(stand_in: SocketAddr) -> Self {
        let key: String = (0..32)
            .map(|_| format!("{:02x}", rand::random::<u8>()))
            .collect();
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("a port for the filter");
        let port = listener.local_addr().expect("an address").port();
        let proxy = Arc::new(SandboxProxy::new(ProxyServing {
            listen: listener.local_addr().expect("an address"),
            key: TicketKey::parse(&key).expect("a key"),
            most_at_once: 16,
            upstreams: Upstreams::StandIn(stand_in),
        }));
        let (stop, stopped) = oneshot::channel::<()>();
        let served = tokio::spawn(proxy.serve_on(listener, async move {
            let _ = stopped.await;
        }));
        Self {
            port,
            key,
            stop,
            served,
        }
    }

    /// Stops the filter.
    async fn stop(self) {
        let _ = self.stop.send(());
        self.served.await.expect("the filter's task ends");
    }
}

/// An HTTPS service answering [`ANSWER`] to every request, under a
/// certificate of its own, until dropped; its address.
async fn stand_in() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a port for the stand-in");
    let address = listener.local_addr().expect("an address");
    let tls = stand_in_tls();
    let serving = tokio::spawn(serve_stand_in(listener, tls));
    (address, serving)
}

/// The stand-in serves its allowed hostname using its own self-signed certificate.
fn stand_in_tls() -> TlsAcceptor {
    let key = KeyPair::generate().expect("a key");
    let certificate = CertificateParams::new(vec![ALLOWED.to_owned()])
        .expect("parameters")
        .self_signed(&key)
        .expect("a certificate");
    let server = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .expect("TLS configuration");
    TlsAcceptor::from(Arc::new(server))
}

/// Accepted TLS requests receive the fixed answer independently on each connection.
async fn serve_stand_in(listener: TcpListener, tls: TlsAcceptor) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let tls = tls.clone();
        tokio::spawn(async move {
            let Ok(mut stream) = tls.accept(stream).await else {
                return;
            };
            let mut asked = [0_u8; 4096];
            let _ = stream.read(&mut asked).await;
            let answer = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ANSWER}",
                ANSWER.len()
            );
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Makes the engine's network runs reaching the filter join, unless it is
/// there already.
async fn egress_network() {
    let made = tokio::process::Command::new("docker")
        .args(["network", "create", EGRESS_NETWORK])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .expect("docker starts");
    let listed = tokio::process::Command::new("docker")
        .args(["network", "inspect", EGRESS_NETWORK])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .expect("docker starts");
    assert!(
        made.success() || listed.success(),
        "the engine's network {EGRESS_NETWORK} could not be made"
    );
}

/// Ann's version that asks both hosts, allowed to reach `allowed`.
fn asking_both(allowed: &'static [&'static str]) -> Recipe<'static> {
    Recipe {
        name: "Ask both hosts",
        language: "python",
        runtime: "python-3.13",
        code: ASK_BOTH,
        packages: &[],
        run_seconds: 30,
        allowed_hosts: allowed,
    }
}

/// A graph running `version` once an approval right before it is given:
/// code that may reach the network is published only so.
fn asking(version: &str) -> Graph {
    Graph {
        nodes: vec![
            Node {
                key: APPROVAL_STEP.to_owned(),
                name: "Approve reaching out".to_owned(),
                step: Step::Approval {
                    summary: "Let the code reach the hosts it names".to_owned(),
                    action_class: "undeclared".to_owned(),
                    window_seconds: 120,
                },
            },
            code_step("ask", version, Vec::new()),
        ],
        edges: vec![Edge {
            from: APPROVAL_STEP.to_owned(),
            to: "ask".to_owned(),
        }],
    }
}

/// Waits until the run `execution_id` is held at its approval step.
async fn held_at_the_approval(world: &World<'_>, execution_id: &str) {
    eventually("the run to wait for its approval", || async {
        let execution = run(world, execution_id).await;
        let held = execution
            .steps
            .iter()
            .any(|step| step.key == APPROVAL_STEP && step.phase == "running");
        held.then_some(())
    })
    .await;
}

/// Ann publishes `graph` and Tess starts it. A high-risk step needs two
/// approvers who neither wrote, published nor started it: Bea and Cal,
/// administrators, each approve what they are shown with a code from
/// their own authenticator. The run once it has ended.
async fn approved_and_ran(world: &World<'_>, graph: Graph) -> Execution {
    let mut bea = Approver::joined(world, "bea", "Bea Approver").await;
    let mut cal = Approver::joined(world, "cal", "Cal Approver").await;
    let execution_id = begun(world, graph).await;
    held_at_the_approval(world, &execution_id).await;
    let shown = workflows::approval(world.tenant(), &execution_id, APPROVAL_STEP)
        .send(bea.client())
        .await
        .ok()
        .shown;

    let target = ApprovalStep {
        execution_id: &execution_id,
        step: APPROVAL_STEP,
    };
    bea.approve(world, target, &shown).await;
    cal.approve(world, target, &shown).await;

    finished(world, &execution_id).await
}

/// Ann's version may reach `api.allowed.test`. Tess runs it through the
/// gate, Bea and Cal approve the run, and its code asks
/// that host and `api.other.test`. The allowed host answers through the
/// filter; the other is refused by the filter, so the code's attempt
/// raises an error, and the run still succeeds with both results.
#[tokio::test]
async fn code_reaches_its_allowed_host_and_no_other() {
    let _clock = Clock::controlled();
    egress_network().await;
    let (stand_in, serving) = stand_in().await;
    let filter = RunningFilter::start(stand_in).await;
    let gate = RunningGate::start(Some(EGRESS_NETWORK)).await;
    let npm = registry(&[], Fingerprints::True).await;
    let socket = gate.socket().display().to_string();
    let address = format!("{THIS_MACHINE}:{}", filter.port);
    let profile = Profile::standard()
        .with("NPM_REGISTRY_URL", &npm.url())
        .with("SANDBOX_GATE_SOCKET", &socket)
        .with("SANDBOX_PROXY_ADDRESS", &address)
        .with("SANDBOX_PROXY_KEY", &filter.key);
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let version = ready(&world, &asking_both(&[ALLOWED])).await;

    let execution = approved_and_ran(&world, asking(&version)).await;

    assert_eq!(execution.status, "succeeded", "{:?}", execution.steps);
    let reached = step_of(&execution, "ask")
        .output
        .clone()
        .expect("an output");
    assert_eq!(reached["allowed"], json!(true), "{reached}");
    assert_eq!(reached["other"], json!("URLError"), "{reached}");

    stack.stop().await.expect("the stack stops cleanly");
    gate.stop().await;
    filter.stop().await;
    serving.abort();
}

/// Without a network filter, Ann's version naming an allowed host cannot
/// run. Even after both approvals, the execution fails with `code_not_run`.
#[tokio::test]
async fn a_version_naming_hosts_does_not_run_without_a_filter() {
    let _clock = Clock::controlled();
    let gate = RunningGate::start(None).await;
    let npm = registry(&[], Fingerprints::True).await;
    let socket = gate.socket().display().to_string();
    let profile = Profile::standard()
        .with("NPM_REGISTRY_URL", &npm.url())
        .with("SANDBOX_GATE_SOCKET", &socket);
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let version = ready(&world, &asking_both(&[ALLOWED])).await;

    let execution = approved_and_ran(&world, asking(&version)).await;

    assert_eq!(execution.status, "failed");
    let refused = step_of(&execution, "ask")
        .failure
        .clone()
        .expect("a failure");
    assert_eq!(refused.code, "code_not_run");

    stack.stop().await.expect("the stack stops cleanly");
    gate.stop().await;
}
