//! Sandboxes on the wire: making one, saving a version of its code and
//! packages, written or imported from a repository, reading how far each
//! version's package bundle got, and pushing a version to a repository; a
//! version holding an agent, and the company's own image from a registry
//! its administrator allowed, with what scanning it found.

use serde::{Deserialize, Serialize};

use super::Page;
use super::workflows::StepFailed;

/// `POST …/sandboxes`: a sandbox to make.
#[derive(Debug, Clone, Serialize)]
pub struct NewSandbox {
    /// Its name for people.
    pub name: String,
    /// `python` or `javascript`.
    pub language: String,
}

/// One package a version pins, at one exact version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    /// Its name, as its registry names it.
    pub name: String,
    /// Its exact version.
    pub version: String,
}

/// `POST …/sandboxes/{id}/versions`: the next version to save.
#[derive(Debug, Clone, Serialize)]
pub struct NewSandboxVersion {
    /// The runtime it runs under, such as `python-3.13`.
    pub runtime: String,
    /// Source text saved with this version and executed during trials.
    pub code: String,
    /// The packages it pins.
    pub packages: Vec<Pin>,
    /// The longest one run may take, in seconds.
    pub run_seconds: u32,
    /// The memory one run is given, in MiB.
    pub memory_mib: u32,
    /// The hosts its code may reach; empty for none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,
}

/// `POST …/sandboxes/{id}/versions`: the next version, its code read from
/// a repository's file.
#[derive(Debug, Clone, Serialize)]
pub struct ImportedSandboxVersion {
    /// The runtime it runs under, such as `python-3.13`.
    pub runtime: String,
    /// The file its code is read from.
    pub import: Import,
    /// The packages it pins.
    pub packages: Vec<Pin>,
    /// The longest one run may take, in seconds.
    pub run_seconds: u32,
    /// The memory one run is given, in MiB.
    pub memory_mib: u32,
}

/// A repository's file, read through a connected account.
#[derive(Debug, Clone, Serialize)]
pub struct Import {
    /// The account it is read through.
    pub account_id: String,
    /// The repository, such as `acme/web`.
    pub repository: String,
    /// The file.
    pub path: String,
    /// The branch, tag or commit it is read at.
    #[serde(rename = "ref")]
    pub at: String,
}

/// `POST …/sandboxes/{id}/versions/{version_id}/pushes`: where a version's
/// copy goes.
#[derive(Debug, Clone, Serialize)]
pub struct NewPush {
    /// The account it goes through.
    pub account_id: String,
    /// Remote destination receiving the version's source and package files.
    pub repository: String,
    /// The branch, which must exist.
    pub branch: String,
    /// The folder its files go in.
    pub folder: String,
}

/// The repository file a version's code was imported from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ImportedFrom {
    /// The integration keeping it, such as `github`.
    pub integration: String,
    /// Remote source from which this version's code was read.
    pub repository: String,
    /// The file.
    pub path: String,
    /// The exact commit it was read at.
    pub commit: String,
}

/// Lifecycle and latest saved version reported for an isolated code project.
#[derive(Debug, Clone, Deserialize)]
pub struct Sandbox {
    /// Handle used to save versions and archive this code project.
    pub id: String,
    /// `active` or `archived`.
    pub status: String,
    /// The number of its latest version, or 0 before the first.
    pub latest_version: u32,
}

/// One saved version of a sandbox.
#[derive(Debug, Clone, Deserialize)]
pub struct SandboxVersion {
    /// Handle used to run trials or export this immutable version.
    pub id: String,
    /// Its number, from 1.
    pub number: u32,
    /// The runtime it runs under, such as `node-22`; empty for a
    /// company's image.
    #[serde(default)]
    pub runtime: String,
    /// The exact image it runs in, named by its content.
    pub image: String,
    /// Source text preserved when the version was saved; empty for a
    /// company's image.
    #[serde(default)]
    pub code: String,
    /// The file its code was imported from; none for code written in the
    /// platform.
    #[serde(default)]
    pub imported_from: Option<ImportedFrom>,
    /// The packages it pins.
    pub packages: Vec<Pin>,
    /// The hosts its code may reach; empty for none.
    pub allowed_hosts: Vec<String>,
    /// How far building its package bundle got.
    pub build: Bundle,
}

/// How far building a version's package bundle got.
#[derive(Debug, Clone, Deserialize)]
pub struct Bundle {
    /// `building`, `ready` or `failed`.
    pub status: String,
    /// The bundle's SHA-256, once ready.
    pub digest: Option<String>,
    /// How large the bundle is, once ready.
    pub bytes: Option<u64>,
    /// Packages a pinned one needs that the version does not pin.
    #[serde(default)]
    pub unlisted: Vec<String>,
    /// Why it failed, once failed.
    pub failure: Option<String>,
    /// The package the failure names, or a company image's critical
    /// findings.
    pub detail: Option<String>,
    /// What scanning a company's image found below critical, once ready.
    #[serde(default)]
    pub findings: Option<Findings>,
}

/// How many known vulnerabilities below critical a company's image has.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Findings {
    /// Findings rated high.
    pub high: u32,
    /// Findings rated medium.
    pub medium: u32,
    /// Findings rated low or not rated.
    pub low: u32,
}

/// `POST …/sandboxes` with kind `image`: a sandbox running the company's
/// own container image instead of code.
#[derive(Debug, Clone, Serialize)]
pub struct NewImageSandbox {
    /// Its name for people.
    pub name: String,
    /// Always `image`.
    pub kind: String,
}

/// `POST …/sandboxes/{id}/versions` for an image sandbox: the company's
/// image by its registry, path and tag.
#[derive(Debug, Clone, Serialize)]
pub struct NewImageVersion {
    /// The image, such as `registry.acme.example/tools/codegen:1.4`.
    pub image: String,
    /// The longest one run may take, in seconds.
    pub run_seconds: u32,
    /// The memory one run is given, in MiB.
    pub memory_mib: u32,
}

/// `POST …/sandboxes/{id}/versions` holding an agent: the code is the
/// check each of the agent's answers must pass.
#[derive(Debug, Clone, Serialize)]
pub struct HeldAgentVersion {
    /// The runtime the check runs under, such as `python-3.13`.
    pub runtime: String,
    /// The check.
    pub code: String,
    /// The longest one check may take, in seconds.
    pub run_seconds: u32,
    /// The memory one check is given, in MiB.
    pub memory_mib: u32,
    /// The agent and the rules it works under.
    pub agent: HeldAgent,
}

/// The agent a version holds, and the rules it works under.
#[derive(Debug, Clone, Serialize)]
pub struct HeldAgent {
    /// The agent that does the step's work.
    pub agent_id: String,
    /// The tenant's model provider it reasons with.
    pub provider_id: String,
    /// What it works toward.
    pub goal: String,
    /// The action classes its calls may take, such as `read`.
    pub purpose: Vec<String>,
    /// The most steps it may take across every try.
    pub max_steps: u32,
    /// The most it may spend on its model across every try, in millionths.
    pub spend_cap_micros: u64,
    /// How many answers it may give, from 1 to 3.
    pub tries: u8,
}

/// `POST …/sandboxes/registries`: a registry the tenant's image sandboxes
/// may take images from, here one serving them to anyone.
#[derive(Debug, Clone, Serialize)]
pub struct NewRegistry {
    /// The registry's host, such as `registry.acme.example`.
    pub host: String,
}

/// An image registry the tenant allowed.
#[derive(Debug, Clone, Deserialize)]
pub struct Registry {
    /// Handle used to remove it.
    pub id: String,
    /// The registry's host.
    pub host: String,
    /// `anonymous`, or `password` with a login kept sealed.
    pub login: String,
}

/// One runtime a new version may pick, from `GET …/sandboxes/runtimes`.
#[derive(Debug, Clone, Deserialize)]
pub struct OfferedRuntime {
    /// The runtime, such as `python-3.13`.
    pub runtime: String,
    /// The image a version saved now keeps.
    pub image: String,
}

/// `GET …/sandboxes/{id}`: a sandbox and a page of its versions.
#[derive(Debug, Clone, Deserialize)]
pub struct SandboxDetail {
    /// Project lifecycle and latest-version metadata accompanying the page.
    pub sandbox: Sandbox,
    /// Its versions, newest first.
    pub versions: Page<SandboxVersion>,
}

/// `POST …/sandboxes/{id}/versions/{version_id}/trials`: sample input to
/// try a version on.
#[derive(Debug, Clone, Serialize)]
pub struct NewTrial {
    /// What the code is given.
    pub input: serde_json::Value,
}

/// One trial of a version, from starting it or `GET …/trials/{id}`.
#[derive(Debug, Clone, Deserialize)]
pub struct Trial {
    /// Handle used to poll for the sample execution's outcome.
    pub id: String,
    /// `running`, `succeeded` or `failed`.
    pub status: String,
    /// What the code gave back, once it succeeded.
    pub output: Option<serde_json::Value>,
    /// Why it failed, once it failed.
    pub failure: Option<StepFailed>,
}
