//! Code steps in real containers: Ann's workflow tidies an issue's title
//! with JavaScript that uses a package from the registry, then makes a
//! slug of it with Python, each run in a container of its own under the
//! real Node and Python each version picked. Code that reaches for the
//! network finds none, and code that runs past its limit is stopped. Each
//! runs three ways: through the container command (`docker`); through the
//! sandbox gate, which alone holds the local engine's socket; and in pods
//! on the local OrbStack cluster (`kubectl` on the path, its `orbstack`
//! context), each scenario in a namespace of its own, one pod of each kind
//! kept warm. On the cluster, a second run takes the pod left waiting by
//! the first. The slim images are pulled on their first run.

use std::time::Duration;

use ianua_scenarios::api::sandboxes;
use ianua_scenarios::expect::{Waiting, eventually_paced};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::sandboxes::{NewSandbox, NewSandboxVersion, Pin};
use ianua_scenarios::wire::workflows::{
    Edge, Execution, ExecutionStep, Graph, MappedField, Node, Step, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::code::gate::RunningGate;
use crate::code::registry::{Fingerprints, Package, registry};
use crate::support::{drafted, published, read, run, started_with};

/// How long a build or a run with code may take here, the first one
/// pulling its image, asking once a second, as a person's browser would,
/// so the platform's rate limit never answers instead.
pub(crate) const CONTAINER_PATIENCE: Waiting = Waiting {
    patience: Duration::from_secs(300),
    every: Duration::from_secs(1),
};

/// `trim`, as npm would serve a small package: real JavaScript.
const TRIM: Package = Package {
    name: "trim",
    version: "1.0.0",
    files: &[
        (
            "package.json",
            r#"{"name":"trim","version":"1.0.0","main":"index.js"}"#,
        ),
        (
            "index.js",
            "module.exports = (text) => text.replace(/\\s+/g, ' ').trim();",
        ),
    ],
    needs: &[],
};

/// JavaScript that tidies the title it is handed with `trim`.
const TIDY: &str = "const trim = require('trim');\n\
module.exports = async (input) => ({ title: trim(input.title), runtime: process.version });\n";

/// Python that makes a slug of the title it is handed.
const SLUG: &str = "import re\nimport sys\n\n\
def main(input):\n\
\tprint('making a slug')\n\
\tslug = re.sub(r'[^a-z0-9]+', '-', input['title'].lower()).strip('-')\n\
\treturn {'slug': slug, 'python': sys.version_info[:2]}\n";

/// Python that tries to fetch a page from the internet.
const FETCH: &str = "import urllib.request\n\n\
def main(input):\n\
\treturn urllib.request.urlopen('http://example.com', timeout=5).read().decode()\n";

/// JavaScript that never ends.
const SPIN: &str = "module.exports = () => { for (;;) {} };\n";

/// What one sandbox holds.
pub(crate) struct Recipe<'a> {
    pub(crate) name: &'a str,
    pub(crate) language: &'a str,
    pub(crate) runtime: &'a str,
    pub(crate) code: &'a str,
    pub(crate) packages: &'a [&'a Package],
    pub(crate) run_seconds: u32,
    pub(crate) allowed_hosts: &'a [&'a str],
}

/// The Python version used by both the mixed-language and warm-pod scenarios.
const SLUG_RECIPE: Recipe<'static> = Recipe {
    name: "Slugs",
    language: "python",
    runtime: "python-3.13",
    code: SLUG,
    packages: &[],
    run_seconds: 20,
    allowed_hosts: &[],
};

/// The Node version tidying titles with the pinned trim package.
const TIDY_RECIPE: Recipe<'static> = Recipe {
    name: "Tidy titles",
    language: "javascript",
    runtime: "node-24",
    code: TIDY,
    packages: &[&TRIM],
    run_seconds: 20,
    allowed_hosts: &[],
};

/// The Python version that tries a network read without any allowed host.
const FETCH_RECIPE: Recipe<'static> = Recipe {
    name: "Fetch a page",
    language: "python",
    runtime: "python-3.12",
    code: FETCH,
    packages: &[],
    run_seconds: 20,
    allowed_hosts: &[],
};

/// The endless JavaScript version whose two-second run limit must stop it.
const SPIN_RECIPE: Recipe<'static> = Recipe {
    name: "Spin",
    language: "javascript",
    runtime: "node-22",
    code: SPIN,
    packages: &[],
    run_seconds: 2,
    allowed_hosts: &[],
};

/// Where the stack runs code.
#[derive(Clone, Copy)]
enum Sandbox {
    /// In containers through `docker`.
    Containers,
    /// In pods on the local OrbStack cluster, in a namespace of the
    /// scenario's own set up as the chart sets one up.
    Cluster(&'static str),
    /// In containers the sandbox gate starts, the worker holding no
    /// container engine.
    Gate,
}

/// The stack running code, with the gate it asks when it runs through one.
struct CodeStack {
    stack: Stack,
    sandbox: Sandbox,
    gate: Option<RunningGate>,
}

impl CodeStack {
    /// Stops the stack, then removes what its code runs left: the gate,
    /// and the cluster's code pods, warm ones among them.
    async fn stop(self) {
        self.stack.stop().await.expect("the stack stops cleanly");
        if let Some(gate) = self.gate {
            gate.stop().await;
        }
        torn_down(self.sandbox).await;
    }
}

/// The code namespace `namespace` as the chart makes it: the restricted
/// pod security level, and no traffic in or out.
fn namespace_manifest(namespace: &str) -> String {
    format!(
        "apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: no-traffic
  namespace: {namespace}
spec:
  podSelector: {{}}
  policyTypes: [Ingress, Egress]
"
    )
}

/// The stack, running code as `sandbox` says, with the npm stand-in at
/// `npm_url`.
async fn stack_running_code(npm_url: &str, sandbox: Sandbox) -> CodeStack {
    let profile = Profile::standard().with("NPM_REGISTRY_URL", npm_url);
    let (profile, gate) = match sandbox {
        Sandbox::Containers => (profile.with("SANDBOX_CONTAINER_COMMAND", "docker"), None),
        Sandbox::Cluster(namespace) => {
            set_up(namespace).await;
            let profile = profile
                .with("SANDBOX_CLUSTER_NAMESPACE", namespace)
                .with("SANDBOX_CLUSTER_CONTEXT", "orbstack")
                .with("SANDBOX_CLUSTER_WARM", "1");
            (profile, None)
        }
        Sandbox::Gate => {
            let gate = RunningGate::start(None).await;
            let socket = gate.socket().display().to_string();
            (profile.with("SANDBOX_GATE_SOCKET", &socket), Some(gate))
        }
    };
    let stack = Stack::start(profile).await.expect("the stack starts");
    CodeStack {
        stack,
        sandbox,
        gate,
    }
}

/// Sets up `namespace` on the local cluster, through its own context only,
/// emptied of what an earlier run left.
async fn set_up(namespace: &str) {
    let manifest = namespace_manifest(namespace);
    let applied = kubectl(&["apply", "-f", "-"], Some(&manifest)).await;
    assert!(
        applied.is_some(),
        "the code namespace {namespace} could not be set up"
    );
    let selector = "--selector=ianua.io/sandbox=code";
    kubectl(
        &["delete", "pods", "-n", namespace, selector, "--wait=true"],
        None,
    )
    .await;
}

/// Removes every code pod `sandbox` left, warm ones among them, once its
/// stack stopped.
async fn torn_down(sandbox: Sandbox) {
    let Sandbox::Cluster(namespace) = sandbox else {
        return;
    };
    let selector = "--selector=ianua.io/sandbox=code";
    let deleted = kubectl(
        &["delete", "pods", "-n", namespace, selector, "--wait=true"],
        None,
    )
    .await;
    assert!(
        deleted.is_some(),
        "the code pods in {namespace} could not be removed"
    );
}

/// What `kubectl` printed for `args` on the local cluster, given `input`,
/// or `None` when it failed.
async fn kubectl(args: &[&str], input: Option<&str>) -> Option<String> {
    let mut command = tokio::process::Command::new("kubectl");
    command
        .args(["--context", "orbstack"])
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut running = command.spawn().expect("kubectl starts");
    let mut stdin = running.stdin.take().expect("kubectl's input");
    tokio::io::AsyncWriteExt::write_all(&mut stdin, input.unwrap_or_default().as_bytes())
        .await
        .expect("kubectl's input is written");
    drop(stdin);
    let output = running.wait_with_output().await.expect("kubectl ends");
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The names of the pods waiting warm in `namespace` whose container runs.
async fn warm_pods(namespace: &str) -> Vec<String> {
    let listed = kubectl(
        &[
            "get",
            "pods",
            "-n",
            namespace,
            "--selector=ianua.io/sandbox=code,ianua.io/state=warm",
            "--field-selector=status.phase=Running",
            "-o",
            "jsonpath={.items[*].metadata.name}",
        ],
        None,
    )
    .await
    .unwrap_or_default();
    listed.split_whitespace().map(str::to_owned).collect()
}

/// Whether pod `name` is gone from `namespace`, or on its way out.
async fn is_gone(namespace: &str, name: &str) -> bool {
    let read = kubectl(
        &[
            "get",
            "pod",
            name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.metadata.deletionTimestamp}",
        ],
        None,
    )
    .await;
    read.is_none_or(|deleting| !deleting.is_empty())
}

/// Ann makes a sandbox of `recipe` and Tess saves its version 1; the
/// version's id once its bundle is ready.
pub(crate) async fn ready(world: &World<'_>, recipe: &Recipe<'_>) -> String {
    readied(world, recipe).await.version_id
}

/// A sandbox and its version whose bundle is ready.
pub(crate) struct Readied {
    /// The sandbox.
    pub(crate) sandbox_id: String,
    /// Its version 1.
    pub(crate) version_id: String,
}

/// Ann makes a sandbox of `recipe` and Tess saves its version 1; both ids
/// once the version's bundle is ready.
pub(crate) async fn readied(world: &World<'_>, recipe: &Recipe<'_>) -> Readied {
    let made = NewSandbox {
        name: recipe.name.to_owned(),
        language: recipe.language.to_owned(),
    };
    let sandbox = sandboxes::create(world.tenant(), &made)
        .send(world.owner().client())
        .await
        .ok();
    let version = version_from(recipe);
    sandboxes::save_version(world.tenant(), &sandbox.id, &version)
        .send(world.admin().client())
        .await
        .ok();
    let version_id = wait_for_bundle(world, &sandbox.id).await;
    Readied {
        sandbox_id: sandbox.id,
        version_id,
    }
}

/// A saved version preserves its recipe's runtime, pins, resource limit and allowed hosts.
fn version_from(recipe: &Recipe<'_>) -> NewSandboxVersion {
    NewSandboxVersion {
        runtime: recipe.runtime.to_owned(),
        code: recipe.code.to_owned(),
        packages: recipe
            .packages
            .iter()
            .map(|package| Pin {
                name: package.name.to_owned(),
                version: package.version.to_owned(),
            })
            .collect(),
        run_seconds: recipe.run_seconds,
        memory_mib: 128,
        allowed_hosts: recipe
            .allowed_hosts
            .iter()
            .map(|host| (*host).to_owned())
            .collect(),
    }
}

/// Waits for the newest bundle and fails immediately if its build fails.
async fn wait_for_bundle(world: &World<'_>, sandbox_id: &str) -> String {
    eventually_paced(
        "the version's bundle to be ready",
        CONTAINER_PATIENCE,
        || async {
            let detail = sandboxes::get(world.tenant(), sandbox_id)
                .send(world.admin().client())
                .await
                .ok();
            let newest = detail.versions.items.into_iter().next()?;
            assert_ne!(newest.build.status, "failed", "{:?}", newest.build);
            (newest.build.status == "ready").then_some(newest.id)
        },
    )
    .await
}

/// A step `key` running version `version_id` on `inputs`.
pub(crate) fn code_step(key: &str, version_id: &str, inputs: Vec<MappedField>) -> Node {
    Node {
        key: key.to_owned(),
        name: key.to_owned(),
        step: Step::Code {
            sandbox_version_id: version_id.to_owned(),
            inputs,
        },
    }
}

/// The trigger's title, handed on as `title`.
fn title_from(path: &str) -> Vec<MappedField> {
    vec![MappedField {
        field: "title".to_owned(),
        source: read(path),
    }]
}

/// Ann publishes `graph`, Tess starts it with an untidy title, and the run
/// once it has ended.
pub(crate) async fn ran(world: &World<'_>, graph: Graph) -> Execution {
    let execution_id = begun(world, graph).await;
    finished(world, &execution_id).await
}

/// Ann publishes `graph` and Tess starts it with an untidy title; the id
/// of the run.
pub(crate) async fn begun(world: &World<'_>, graph: Graph) -> String {
    let draft = drafted(world, Trigger::Manual, graph).await;
    let workflow = published(world, &draft).await;
    started_with(world, &workflow, json!({"title": "  Fix   Login Page  "}))
        .await
        .execution_id
}

/// The run `execution_id` once it has ended.
pub(crate) async fn finished(world: &World<'_>, execution_id: &str) -> Execution {
    eventually_paced("the run to end", CONTAINER_PATIENCE, || async {
        let execution = run(world, execution_id).await;
        (execution.status != "running").then_some(execution)
    })
    .await
}

/// The step `key` of `execution`.
pub(crate) fn step_of<'e>(execution: &'e Execution, key: &str) -> &'e ExecutionStep {
    execution
        .steps
        .iter()
        .find(|step| step.key == key)
        .expect("the step is in the run")
}

/// Ann's workflow tidies the title with JavaScript using `trim` from the
/// registry, saved under Node 24, then makes a slug of the tidied title
/// with Python, saved under Python 3.13. Tess runs it: the run succeeds,
/// the JavaScript ran under Node 24 and gave back the tidied title, and
/// the Python ran under Python 3.13 and gave back the slug. What the
/// Python printed is not mistaken for its answer.
#[tokio::test]
async fn a_workflow_runs_real_javascript_and_python() {
    runs_real_javascript_and_python(Sandbox::Containers).await;
}

/// The same workflow, each step in a pod of its own on Kubernetes, made
/// through the worker's own kubeconfig context in the code namespace.
#[tokio::test]
async fn a_workflow_runs_real_javascript_and_python_on_kubernetes() {
    runs_real_javascript_and_python(Sandbox::Cluster("ianua-scenario-code-workflow")).await;
}

/// The same workflow on a self-hosted server, each step in a container the
/// sandbox gate starts, the worker holding no container engine.
#[tokio::test]
async fn a_workflow_runs_real_javascript_and_python_through_the_gate() {
    runs_real_javascript_and_python(Sandbox::Gate).await;
}

/// Mallory's Python cannot fetch a page from the internet, and
/// her JavaScript never ends within its two seconds. The fetch finds no
/// network, so its step fails with the error the code raised. The endless
/// code is stopped at its limit, so its step fails as timed out. Neither
/// run succeeds.
#[tokio::test]
async fn code_reaches_no_network_and_stops_at_its_limit() {
    reaches_no_network_and_stops_at_its_limit(Sandbox::Containers).await;
}

/// Kubernetes pods run behind a namespace policy denying all traffic.
/// The Python fetch fails with `URLError`, and endless JavaScript times out.
#[tokio::test]
async fn code_reaches_no_network_and_stops_at_its_limit_on_kubernetes() {
    reaches_no_network_and_stops_at_its_limit(Sandbox::Cluster("ianua-scenario-code-limits")).await;
}

/// The sandbox gate starts containers without a network. The Python fetch
/// fails with `URLError`, and endless JavaScript times out.
#[tokio::test]
async fn code_reaches_no_network_and_stops_at_its_limit_through_the_gate() {
    reaches_no_network_and_stops_at_its_limit(Sandbox::Gate).await;
}

/// Tess runs Ann's slug workflow on Kubernetes. Once its pod has run, a
/// pod of the same kind waits warm. Tess runs it again: the run succeeds
/// with the same slug, and it took the waiting pod, which is gone after.
#[tokio::test]
async fn a_second_run_takes_a_warm_pod_on_kubernetes() {
    let sandbox = Sandbox::Cluster("ianua-scenario-code-warm");
    let npm = registry(&[], Fingerprints::True).await;
    let running = stack_running_code(&npm.url(), sandbox).await;
    let world = World::new(&running.stack).await;
    let slug = ready(&world, &SLUG_RECIPE).await;
    let graph = || Graph {
        nodes: vec![code_step("slug", &slug, title_from("trigger.title"))],
        edges: Vec::new(),
    };
    let first = ran(&world, graph()).await;
    let waiting = eventually_paced("a pod to wait warm", CONTAINER_PATIENCE, || async {
        warm_pods("ianua-scenario-code-warm")
            .await
            .into_iter()
            .next()
    })
    .await;

    let second = ran(&world, graph()).await;

    assert_eq!(first.status, "succeeded", "{:?}", first.steps);
    assert_eq!(second.status, "succeeded", "{:?}", second.steps);
    assert_eq!(
        step_of(&second, "slug").output.clone().expect("an output")["slug"],
        "fix-login-page"
    );
    assert!(
        is_gone("ianua-scenario-code-warm", &waiting).await,
        "the second run did not take the waiting pod {waiting}"
    );

    running.stop().await;
}

/// The selected runtime runs the pinned JavaScript step before the Python step.
async fn runs_real_javascript_and_python(sandbox: Sandbox) {
    let npm = registry(&[TRIM], Fingerprints::True).await;
    let running = stack_running_code(&npm.url(), sandbox).await;
    let world = World::new(&running.stack).await;
    let tidy = ready(&world, &TIDY_RECIPE).await;
    let slug = ready(&world, &SLUG_RECIPE).await;
    let graph = Graph {
        nodes: vec![
            code_step("tidy", &tidy, title_from("trigger.title")),
            code_step("slug", &slug, title_from("tidy.title")),
        ],
        edges: vec![Edge {
            from: "tidy".to_owned(),
            to: "slug".to_owned(),
        }],
    };

    let execution = ran(&world, graph).await;
    check_language_outputs(&execution);
    running.stop().await;
}

/// The outputs carry the transformed title and slug plus the exact selected language versions.
fn check_language_outputs(execution: &Execution) {
    assert_eq!(execution.status, "succeeded", "{:?}", execution.steps);
    let tidied = step_of(execution, "tidy")
        .output
        .clone()
        .expect("an output");
    assert_eq!(tidied["title"], "Fix Login Page");
    assert!(
        tidied["runtime"]
            .as_str()
            .is_some_and(|runtime| runtime.starts_with("v24.")),
        "{tidied}"
    );
    let slugged = step_of(execution, "slug")
        .output
        .clone()
        .expect("an output");
    assert_eq!(
        slugged,
        json!({"slug": "fix-login-page", "python": [3, 13]})
    );
}

/// The selected runtime refuses network access and terminates endless code at its time limit.
async fn reaches_no_network_and_stops_at_its_limit(sandbox: Sandbox) {
    let npm = registry(&[], Fingerprints::True).await;
    let running = stack_running_code(&npm.url(), sandbox).await;
    let world = World::new(&running.stack).await;
    let fetch = ready(&world, &FETCH_RECIPE).await;
    let spin = ready(&world, &SPIN_RECIPE).await;

    let fetched = ran(
        &world,
        Graph {
            nodes: vec![code_step("fetch", &fetch, Vec::new())],
            edges: Vec::new(),
        },
    )
    .await;
    let spun = ran(
        &world,
        Graph {
            nodes: vec![code_step("spin", &spin, Vec::new())],
            edges: Vec::new(),
        },
    )
    .await;

    check_runtime_refusals(&fetched, &spun);
    running.stop().await;
}

/// The network failure comes from the code, while the endless run fails with the timeout code.
fn check_runtime_refusals(fetched: &Execution, spun: &Execution) {
    assert_eq!(fetched.status, "failed");
    let refused = step_of(fetched, "fetch")
        .failure
        .clone()
        .expect("a failure");
    assert_eq!(refused.code, "code_raised");
    assert!(refused.detail.contains("URLError"), "{}", refused.detail);
    assert_eq!(spun.status, "failed");
    let stopped = step_of(spun, "spin").failure.clone().expect("a failure");
    assert_eq!(stopped.code, "code_timed_out");
}
