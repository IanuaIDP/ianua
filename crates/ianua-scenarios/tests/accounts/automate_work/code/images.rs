//! A company's own image as a code step: Pat's team packs a program as a
//! container image, here jq's own image on GitHub's registry, which reads
//! JSON on its standard input and writes it back. An administrator allows
//! the registry, the version keeps the digest the tag points to, and a
//! scanner checks the image before it first runs; the scanner is a
//! stand-in program printing the findings the scenario hands it, as a
//! small script around Trivy would. An image from a registry nobody
//! allowed is refused, a critical finding refuses the version, and a
//! cleared version's run reads the step's input as JSON and answers JSON.
//! The runs pull the image from the registry and run it through `docker`,
//! so they need the network and a container engine.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use ianua_scenarios::api::{sandboxes, workflows};
use ianua_scenarios::expect::eventually_paced;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sandboxes::{
    Findings, NewImageSandbox, NewImageVersion, NewRegistry, SandboxVersion,
};
use ianua_scenarios::wire::workflows::{Graph, MappedField, Publication, Trigger};
use ianua_scenarios::world::World;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::code::running::{CONTAINER_PATIENCE, code_step, ran, step_of};
use crate::support::{drafted, read};

/// The registry Pat's team takes its image from.
const REGISTRY: &str = "ghcr.io";

/// The image by its tag, as Pat names it.
const IMAGE: &str = "ghcr.io/jqlang/jq:1.7.1";

/// What a version of the image keeps instead of the tag: its digest.
const PINNED: &str = "ghcr.io/jqlang/jq@sha256:";

/// A vulnerability the scanner rates high, which refuses nothing.
const HIGH: &str = "CVE-2026-10001";

/// A vulnerability the scanner rates critical, which refuses the image.
const CRITICAL: &str = "CVE-2026-10002";

/// A stand-in for the operator's scanner: a program in a folder of its
/// own that notes each image it was asked to scan and prints the SARIF
/// it was handed.
struct StandInScanner {
    folder: TempDir,
}

impl StandInScanner {
    /// The scanner, reporting `findings`, each a vulnerability and the
    /// severity it is tagged with.
    fn reporting(findings: &[(&str, &str)]) -> Self {
        let folder = TempDir::new().expect("a folder for the scanner");
        let report = folder.path().join("findings.sarif");
        let scanned = folder.path().join("scanned");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\nexec cat '{}'\n",
            scanned.display(),
            report.display()
        );
        let command = folder.path().join("scan");
        std::fs::write(&command, script).expect("the scanner is written");
        let runnable = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&command, runnable).expect("the scanner may run");
        std::fs::write(&report, sarif(findings).to_string()).expect("the findings are written");
        Self { folder }
    }

    /// The program the worker runs as its scanner.
    fn command(&self) -> PathBuf {
        self.folder.path().join("scan")
    }

    /// The images the worker asked it to scan, in order.
    fn scanned(&self) -> Vec<String> {
        std::fs::read_to_string(self.folder.path().join("scanned"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// SARIF 2.1 naming `findings`, each a rule tagged with its severity and
/// one result of it, as Trivy prints them.
fn sarif(findings: &[(&str, &str)]) -> Value {
    let rules: Vec<Value> = findings
        .iter()
        .map(|(id, severity)| json!({"id": id, "properties": {"tags": ["security", severity]}}))
        .collect();
    let results: Vec<Value> = findings
        .iter()
        .map(|(id, _)| json!({"ruleId": id, "level": "error", "message": {"text": id}}))
        .collect();
    json!({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "stand-in", "rules": rules}}, "results": results}],
    })
}

/// The stack running code through `docker`, letting tenants run their own
/// images and scanning them with `scanner`.
async fn stack_scanning_with(scanner: &StandInScanner) -> Stack {
    let profile = Profile::standard()
        .with("SANDBOX_CONTAINER_COMMAND", "docker")
        .with("SANDBOX_OWN_IMAGES", "true")
        .with(
            "IMAGE_SCAN_COMMAND",
            &scanner.command().display().to_string(),
        );
    Stack::start(profile).await.expect("the stack starts")
}

/// Ann makes the image sandbox; its id.
async fn image_sandbox(world: &World<'_>) -> String {
    let made = NewImageSandbox {
        name: "Code generator".to_owned(),
        kind: "image".to_owned(),
    };
    sandboxes::create_image(world.tenant(), &made)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// The image by its tag, with limits a run stays far under.
fn image_version() -> NewImageVersion {
    NewImageVersion {
        image: IMAGE.to_owned(),
        run_seconds: 30,
        memory_mib: 128,
    }
}

/// Ann allows GitHub's registry, which serves its images to anyone.
async fn allow_registry(world: &World<'_>) {
    let registry = NewRegistry {
        host: REGISTRY.to_owned(),
    };
    let allowed = sandboxes::allow_registry(world.tenant(), &registry)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(allowed.login, "anonymous");
}

/// Tess saves the image as the sandbox's next version; it answers as
/// scanning, pinned to its digest.
async fn saved(world: &World<'_>, sandbox_id: &str) -> SandboxVersion {
    let version = sandboxes::save_image_version(world.tenant(), sandbox_id, &image_version())
        .send(world.admin().client())
        .await
        .ok();
    assert!(version.image.starts_with(PINNED), "{}", version.image);
    assert_eq!(version.build.status, "building", "it is scanned first");
    version
}

/// The newest version of `sandbox_id` once its build or scan settled,
/// ready or failed.
pub(crate) async fn settled(world: &World<'_>, sandbox_id: &str) -> SandboxVersion {
    eventually_paced("the version to settle", CONTAINER_PATIENCE, || async {
        let detail = sandboxes::get(world.tenant(), sandbox_id)
            .send(world.admin().client())
            .await
            .ok();
        let newest = detail.versions.items.into_iter().next()?;
        (newest.build.status != "building").then_some(newest)
    })
    .await
}

/// A graph whose one step runs version `version_id` on the trigger's
/// title.
fn image_graph(version_id: &str) -> Graph {
    let title = MappedField {
        field: "title".to_owned(),
        source: read("trigger.title"),
    };
    Graph {
        nodes: vec![code_step("generate", version_id, vec![title])],
        edges: Vec::new(),
    }
}

/// Tess names jq's image before anyone allowed GitHub's registry: refused,
/// an administrator allows it first. Ann allows it, and Tess saves the
/// image again: the version keeps the digest the tag points to now, and
/// the scanner is asked about exactly that digest. It finds one high
/// vulnerability, which refuses nothing, so the version is ready and
/// shows the count. Ann publishes a workflow running it and Tess starts
/// it with an untidy title: the image read the step's input as JSON on
/// its standard input and answered it as JSON, the step's output.
#[tokio::test]
async fn a_companys_image_is_pinned_scanned_and_answers_json() {
    let scanner = StandInScanner::reporting(&[(HIGH, "HIGH")]);
    let stack = stack_scanning_with(&scanner).await;
    let world = World::new(&stack).await;
    let sandbox_id = image_sandbox(&world).await;
    refused_until_allowed(&world, &sandbox_id).await;
    allow_registry(&world).await;
    let pinned = saved(&world, &sandbox_id).await;

    let cleared = settled(&world, &sandbox_id).await;
    let execution = ran(&world, image_graph(&cleared.id)).await;

    assert_eq!(cleared.build.status, "ready", "{:?}", cleared.build);
    assert_eq!(
        cleared.build.findings,
        Some(Findings {
            high: 1,
            medium: 0,
            low: 0
        })
    );
    assert_eq!(scanner.scanned(), [pinned.image], "the digest was scanned");
    assert_eq!(execution.status, "succeeded", "{:?}", execution.steps);
    let answer = step_of(&execution, "generate").output.clone();
    assert_eq!(answer, Some(json!({"title": "  Fix   Login Page  "})));
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess's image from a registry not on the tenant's list is refused, and
/// the sandbox keeps no version.
async fn refused_until_allowed(world: &World<'_>, sandbox_id: &str) {
    let refused = sandboxes::save_image_version(world.tenant(), sandbox_id, &image_version())
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert!(
        refused.message().contains("not on the tenant's list"),
        "{}",
        refused.message()
    );
    let detail = sandboxes::get(world.tenant(), sandbox_id)
        .send(world.admin().client())
        .await
        .ok();
    assert!(detail.versions.items.is_empty(), "no version was kept");
}

/// The scanner finds a critical vulnerability in the image Tess saves: the
/// version fails as `critical_vulnerabilities`, naming it, and Ann's
/// publication of a workflow running it is refused, so it never runs.
#[tokio::test]
async fn a_critical_finding_refuses_the_image() {
    let scanner = StandInScanner::reporting(&[(HIGH, "HIGH"), (CRITICAL, "CRITICAL")]);
    let stack = stack_scanning_with(&scanner).await;
    let world = World::new(&stack).await;
    let sandbox_id = image_sandbox(&world).await;
    allow_registry(&world).await;
    saved(&world, &sandbox_id).await;

    let refused = settled(&world, &sandbox_id).await;
    let draft = drafted(&world, Trigger::Manual, image_graph(&refused.id)).await;
    let publication = Publication {
        revision: draft.revision,
    };
    let publishing = workflows::publish(world.tenant(), &draft.id, &publication)
        .send(world.owner().client())
        .await;

    assert_eq!(refused.build.status, "failed");
    assert_eq!(
        refused.build.failure.as_deref(),
        Some("critical_vulnerabilities")
    );
    let detail = refused.build.detail.clone().unwrap_or_default();
    assert!(detail.contains(CRITICAL), "{detail}");
    assert!(
        !detail.contains(HIGH),
        "only critical findings refuse: {detail}"
    );
    publishing.refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    stack.stop().await.expect("the stack stops cleanly");
}

/// On an installation that runs no company images, Ann's image sandbox is
/// refused before anything is made.
#[tokio::test]
async fn an_installation_without_own_images_makes_no_image_sandbox() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let made = NewImageSandbox {
        name: "Code generator".to_owned(),
        kind: "image".to_owned(),
    };

    sandboxes::create_image(world.tenant(), &made)
        .send(world.owner().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    stack.stop().await.expect("the stack stops cleanly");
}
