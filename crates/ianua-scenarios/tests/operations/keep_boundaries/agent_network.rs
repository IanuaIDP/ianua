//! What an agent can reach on the network, on the local OrbStack cluster
//! (`kubectl` and `helm` on the path, the `orbstack` context): the network
//! rules the chart renders for two agents, Pat's and Ann's, are applied in
//! a namespace of their own, with stand-ins carrying the labels the real
//! pods carry: each agent and its runner, the gateway, the API, and the
//! database, cache and bus behind them.
//!
//! Pat's agent reaches its own runner and nothing else: not Ann's agent or
//! runner, not the gateway or the API directly, not the database, the
//! cache or the bus, not the internet, and no name lookup that could carry
//! data out. Pat's runner reaches the gateway's runner entry and the API,
//! and nothing else. Every stand-in answers anyone not held back, so each
//! refusal is the network rules' doing, and an outsider no rule holds
//! back first proves each probe can succeed on this cluster.

use std::time::Duration;

use futures_util::future::join_all;
use ianua_scenarios::expect::{Waiting, eventually_paced};

/// The release the chart is rendered as.
const RELEASE: &str = "ianua";

/// The image every stand-in runs.
const IMAGE: &str = "busybox:1.36";

/// The port each runner serves its agent on, as the chart's default.
const RUNNER_PORT: u16 = 8480;

/// The gateway's public and runner ports, as the chart's defaults.
const GATEWAY_PORTS: [u16; 2] = [8080, 8082];

/// The gateway's runner entry.
const GATEWAY_RUNNER_PORT: u16 = 8082;

/// The API's public port.
const API_PORT: u16 = 3000;

/// An address on the internet that answers plain HTTP.
const INTERNET: &str = "http://1.1.1.1/";

/// How long one try to connect may take before it counts as refused.
const TRY_SECONDS: &str = "3";

/// How long the stand-ins may take to start, the image pulled on the
/// first run.
const STARTING: Waiting = Waiting {
    patience: Duration::from_secs(120),
    every: Duration::from_secs(2),
};

/// One stand-in pod: its name, the labels the real pod carries, and the
/// ports it answers on.
struct StandIn {
    name: &'static str,
    labels: Vec<(&'static str, String)>,
    ports: Vec<u16>,
}

/// The labels the chart's rules select one of the platform's own parts
/// by.
fn platform_part(component: &str) -> Vec<(&'static str, String)> {
    vec![
        ("app.kubernetes.io/name", "ianua".to_owned()),
        ("app.kubernetes.io/instance", RELEASE.to_owned()),
        ("app.kubernetes.io/component", component.to_owned()),
    ]
}

/// The labels one agent's sandbox pod of `role` carries.
fn sandbox(role: &str, agent: &str) -> Vec<(&'static str, String)> {
    vec![
        ("ianua.io/sandbox", role.to_owned()),
        ("ianua.io/agent", agent.to_owned()),
    ]
}

/// Everything around the two agents.
fn stand_ins() -> Vec<StandIn> {
    let mut parts = agent_stand_ins();
    parts.extend(platform_stand_ins());
    parts.push(StandIn {
        name: "outsider",
        labels: vec![("ianua.io/stand-in", "outsider".to_owned())],
        ports: vec![9000],
    });
    parts
}

/// Each agent and runner carries the same labels selected by the sandbox rules.
fn agent_stand_ins() -> Vec<StandIn> {
    vec![
        StandIn {
            name: "pat-agent",
            labels: sandbox("agent", "pat"),
            ports: vec![9000],
        },
        StandIn {
            name: "pat-runner",
            labels: sandbox("runner", "pat"),
            ports: vec![RUNNER_PORT],
        },
        StandIn {
            name: "ann-agent",
            labels: sandbox("agent", "ann"),
            ports: vec![9000],
        },
        StandIn {
            name: "ann-runner",
            labels: sandbox("runner", "ann"),
            ports: vec![RUNNER_PORT],
        },
    ]
}

/// Gateway, API and storage stand-ins listen on the platform's configured ports.
fn platform_stand_ins() -> Vec<StandIn> {
    vec![
        StandIn {
            name: "gateway",
            labels: platform_part("zero"),
            ports: GATEWAY_PORTS.to_vec(),
        },
        StandIn {
            name: "api",
            labels: platform_part("server"),
            ports: vec![API_PORT],
        },
        StandIn {
            name: "database",
            labels: platform_part("postgresql"),
            ports: vec![5432],
        },
        StandIn {
            name: "cache",
            labels: platform_part("redis"),
            ports: vec![6379],
        },
        StandIn {
            name: "bus",
            labels: platform_part("nats"),
            ports: vec![4222],
        },
    ]
}

/// The manifest of `stand_in`: a pod answering plain HTTP on each of its
/// ports.
fn pod_manifest(stand_in: &StandIn) -> String {
    let labels: String = stand_in
        .labels
        .iter()
        .map(|(name, value)| format!("    {name}: \"{value}\"\n"))
        .collect();
    let listeners: String = stand_in
        .ports
        .iter()
        .map(|port| format!("httpd -p {port} -h /w; "))
        .collect();
    format!(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {name}\n  labels:\n{labels}spec:\n  terminationGracePeriodSeconds: 0\n  containers:\n    - name: stand-in\n      image: {IMAGE}\n      command: [\"sh\", \"-c\", \"mkdir -p /w && echo ok > /w/index.html && {listeners}sleep 3600\"]\n",
        name = stand_in.name,
    )
}

/// The two agents' sandbox values the chart is rendered with.
const CHART_VALUES: [&str; 22] = [
    "config.appBaseUrl=https://app.example.com",
    "config.baseDomain=apps.example.com",
    "postgresql.enabled=true",
    "postgresql.mode=standalone",
    "imagePullSecret.existingSecret=pull",
    "agentSandboxes.organization=acme",
    "agentSandboxes.tenant=main",
    "agentSandboxes.tokenAudience=https://app.example.com",
    "agentSandboxes.egressGateway.tlsSecret=egress-tls",
    "agentSandboxes.egressGateway.clientCaSecret=egress-ca",
    "agentSandboxes.agents[0].name=pat",
    "agentSandboxes.agents[0].agentId=0190a6f0-0000-7000-8000-000000000001",
    "agentSandboxes.agents[0].upstreamHost=orders.acme.test",
    "agentSandboxes.agents[0].granted={}",
    "agentSandboxes.agents[0].image=busybox:1.36",
    "agentSandboxes.agents[1].name=ann",
    "agentSandboxes.agents[1].agentId=0190a6f0-0000-7000-8000-000000000002",
    "agentSandboxes.agents[1].upstreamHost=orders.acme.test",
    "agentSandboxes.agents[1].granted={}",
    "agentSandboxes.agents[1].image=busybox:1.36",
    "zero.networkPolicy.enabled=true",
    "server.networkPolicy.enabled=true",
];

/// The chart's network rules for the agents, rendered for `namespace`.
async fn rendered_rules(namespace: &str) -> String {
    let chart = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/helm/ianua");
    let mut command = tokio::process::Command::new("helm");
    command.args(["template", RELEASE, chart, "--namespace", namespace]);
    command.args(["--show-only", "templates/agent-sandbox-networkpolicy.yaml"]);
    for value in CHART_VALUES {
        command.args(["--set", value]);
    }
    let output = command.output().await.expect("helm starts");
    assert!(
        output.status.success(),
        "the chart renders: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("the chart renders text")
}

/// One namespace on the local cluster holding the rules and stand-ins.
struct Cluster {
    namespace: String,
}

impl Cluster {
    /// A new namespace with the chart's rules applied first, then every
    /// stand-in, each running under the rules from its first moment.
    async fn set_up() -> Self {
        let namespace = format!(
            "agent-net-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let cluster = Self { namespace };
        let created = kubectl(&["create", "namespace", &cluster.namespace], None).await;
        assert!(created.is_some(), "the namespace is made");
        let rules = rendered_rules(&cluster.namespace).await;
        cluster.applied(&rules).await;
        let pods: String = stand_ins()
            .iter()
            .map(|stand_in| format!("---\n{}", pod_manifest(stand_in)))
            .collect();
        cluster.applied(&pods).await;
        cluster.started().await;
        cluster
    }

    /// Applies `manifest` in the namespace.
    async fn applied(&self, manifest: &str) {
        let applied = kubectl(&["-n", &self.namespace, "apply", "-f", "-"], Some(manifest)).await;
        assert!(applied.is_some(), "the manifest applies");
    }

    /// Waits until every stand-in runs.
    async fn started(&self) {
        let namespace = self.namespace.clone();
        eventually_paced("every stand-in to start", STARTING, || {
            let namespace = namespace.clone();
            async move {
                let phases = kubectl(
                    &[
                        "-n",
                        &namespace,
                        "get",
                        "pods",
                        "-o",
                        "jsonpath={.items[*].status.phase}",
                    ],
                    None,
                )
                .await?;
                let running = phases
                    .split_whitespace()
                    .filter(|phase| *phase == "Running");
                (running.count() == stand_ins().len()).then_some(())
            }
        })
        .await;
    }

    /// The address of the stand-in `name`.
    async fn address_of(&self, name: &str) -> String {
        kubectl(
            &[
                "-n",
                &self.namespace,
                "get",
                "pod",
                name,
                "-o",
                "jsonpath={.status.podIP}",
            ],
            None,
        )
        .await
        .filter(|address| !address.is_empty())
        .expect("the stand-in has an address")
    }

    /// Whether `from` gets an answer from `url`.
    async fn reaches(&self, from: &str, url: &str) -> bool {
        let exec = ["-n", &self.namespace, "exec", from, "--"];
        let fetch = ["wget", "-qO-", "-T", TRY_SECONDS, url];
        kubectl(&[exec.as_slice(), &fetch].concat(), None)
            .await
            .is_some()
    }

    /// Whether `from` gets an answer from `name` on `port`.
    async fn reaches_part(&self, from: &str, name: &str, port: u16) -> bool {
        let address = self.address_of(name).await;
        self.reaches(from, &format!("http://{address}:{port}/"))
            .await
    }

    /// Which of `parts`, each a stand-in's name and port, `from` reaches,
    /// every one tried at once.
    async fn reached(&self, from: &str, parts: &[(&str, u16)]) -> Vec<String> {
        let tries = parts.iter().map(|&(name, port)| async move {
            self.reaches_part(from, name, port)
                .await
                .then(|| format!("{name} on {port}"))
        });
        join_all(tries).await.into_iter().flatten().collect()
    }

    /// Whether `from` can look a name up.
    async fn looks_up(&self, from: &str) -> bool {
        let exec = ["-n", &self.namespace, "exec", from, "--"];
        let lookup = [
            "nslookup",
            "-timeout=3",
            "kubernetes.default.svc.cluster.local",
        ];
        kubectl(&[exec.as_slice(), &lookup].concat(), None)
            .await
            .is_some()
    }

    /// Waits until `from` reaches `name` on `port`, proving the stand-ins
    /// answer and the rules are in force before any refusal counts.
    async fn eventually_reaches(&self, from: &str, name: &str, port: u16) {
        let what = format!("{from} to reach {name} on {port}");
        eventually_paced(&what, STARTING, || async {
            self.reaches_part(from, name, port).await.then_some(())
        })
        .await;
    }

    /// Asserts the outsider, whom no rule holds back, reaches the database,
    /// the internet and a name lookup: each refusal of an agent is then the
    /// rules' doing, never a probe that cannot succeed here.
    async fn ensure_probes_work(&self) {
        self.eventually_reaches("outsider", "database", 5432).await;
        eventually_paced("the outsider to reach the internet", STARTING, || async {
            self.reaches("outsider", INTERNET).await.then_some(())
        })
        .await;
        eventually_paced("the outsider to look a name up", STARTING, || async {
            self.looks_up("outsider").await.then_some(())
        })
        .await;
    }
}

impl Drop for Cluster {
    /// Removes the namespace and everything in it, whether the scenario
    /// passed or stopped on a failed assertion, so no stand-in is left
    /// running on the cluster.
    fn drop(&mut self) {
        let removed = std::process::Command::new("kubectl")
            .args(["--context", "orbstack", "delete", "namespace"])
            .args([self.namespace.as_str(), "--wait=false"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if !removed.is_ok_and(|status| status.success()) {
            eprintln!("the namespace {} could not be removed", self.namespace);
        }
    }
}

/// What `kubectl` printed for `args` on the local cluster, given `input`,
/// or `None` when it failed.
async fn kubectl(args: &[&str], input: Option<&str>) -> Option<String> {
    use tokio::io::AsyncWriteExt as _;

    let mut command = tokio::process::Command::new("kubectl");
    command
        .args(["--context", "orbstack"])
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut running = command.spawn().expect("kubectl starts");
    let mut stdin = running.stdin.take().expect("kubectl's input");
    stdin
        .write_all(input.unwrap_or_default().as_bytes())
        .await
        .expect("kubectl's input is written");
    drop(stdin);
    let output = running.wait_with_output().await.expect("kubectl ends");
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// What Pat's agent may not reach: another sandbox, or any platform part
/// directly.
const AGENT_HELD_BACK: [(&str, u16); 8] = [
    ("ann-agent", 9000),
    ("ann-runner", RUNNER_PORT),
    ("gateway", GATEWAY_PORTS[0]),
    ("gateway", GATEWAY_PORTS[1]),
    ("api", API_PORT),
    ("database", 5432),
    ("cache", 6379),
    ("bus", 4222),
];

/// What Pat's runner may not reach: Ann's agent, and the stores behind the
/// platform.
const RUNNER_HELD_BACK: [(&str, u16); 4] = [
    ("ann-agent", 9000),
    ("database", 5432),
    ("cache", 6379),
    ("bus", 4222),
];

/// Pat's agent reaches its own runner but cannot reach Ann's agent or runner,
/// either gateway entry, the API, database, cache, bus or internet. Name
/// lookups are also blocked, and Ann's agent cannot reach Pat's runner.
/// Every refusal is tried at once, each given its full time to succeed.
#[tokio::test]
async fn pat_s_agent_reaches_its_runner_and_nothing_else() {
    let cluster = Cluster::set_up().await;
    cluster.ensure_probes_work().await;
    cluster
        .eventually_reaches("pat-agent", "pat-runner", RUNNER_PORT)
        .await;

    let (reached, internet, lookup, from_ann) = tokio::join!(
        cluster.reached("pat-agent", &AGENT_HELD_BACK),
        cluster.reaches("pat-agent", INTERNET),
        cluster.looks_up("pat-agent"),
        cluster.reaches_part("ann-agent", "pat-runner", RUNNER_PORT),
    );

    assert!(reached.is_empty(), "Pat's agent reaches {reached:?}");
    assert!(!internet, "Pat's agent reaches the internet");
    assert!(!lookup, "Pat's agent looks a name up");
    assert!(!from_ann, "Ann's agent reaches Pat's runner");
}

/// Pat's runner reaches the gateway's runner entry and the API. Its network
/// rules block the database, cache, bus, Ann's agent, internet access and
/// name lookups, limiting where a compromised runner could connect. Every
/// refusal is tried at once, each given its full time to succeed.
#[tokio::test]
async fn pat_s_runner_reaches_the_platform_entries_alone() {
    let cluster = Cluster::set_up().await;
    cluster.ensure_probes_work().await;
    cluster
        .eventually_reaches("pat-runner", "gateway", GATEWAY_RUNNER_PORT)
        .await;
    cluster
        .eventually_reaches("pat-runner", "api", API_PORT)
        .await;

    let (reached, internet, lookup) = tokio::join!(
        cluster.reached("pat-runner", &RUNNER_HELD_BACK),
        cluster.reaches("pat-runner", INTERNET),
        cluster.looks_up("pat-runner"),
    );

    assert!(reached.is_empty(), "Pat's runner reaches {reached:?}");
    assert!(!internet, "Pat's runner reaches the internet");
    assert!(!lookup, "Pat's runner looks a name up");
}
