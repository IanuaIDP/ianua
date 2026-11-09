//! Sandbox versions on the wire: the body that saves one, its code written
//! or imported from a repository or the company's image, and a version
//! with its build or scan and where its code came from.

use ianua_app::use_cases::workflows::sandboxes::images::SaveRequest;
use ianua_app::use_cases::workflows::sandboxes::{SaveVersionRequest, VersionCode, WrittenPackage};
use ianua_domain::domains::workflows::sandbox::build::Build;
use ianua_domain::domains::workflows::sandbox::image::{ImageName, LesserFindings};
use ianua_domain::domains::workflows::sandbox::network::{AllowedHost, NetworkAccess};
use ianua_domain::domains::workflows::sandbox::package::PinnedPackage;
use ianua_domain::domains::workflows::sandbox::recipe::{
    CodeProgram, Program, RunBudget, SandboxCode,
};
use ianua_domain::domains::workflows::sandbox::runtime::Runtime;
use ianua_domain::domains::workflows::sandbox::source::{
    CodeSource, GitRef, RepositoryName, RepositoryPath,
};
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{IntegrationAccountId, SandboxId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::workflows::data::person_label;
use crate::dto::workflows::sandboxes::agent::HeldAgentBody;
use crate::error::ApiError;

/// One package a version pins.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct PackageBody {
    /// Its name, as its registry names it, such as `requests-toolbelt` or
    /// `@acme/tools`.
    pub name: String,
    /// Its exact version, such as `1.0.0`. A range is refused.
    pub version: String,
}

impl From<&PinnedPackage> for PackageBody {
    fn from(pinned: &PinnedPackage) -> Self {
        Self {
            name: pinned.name().as_str().to_owned(),
            version: pinned.version().as_str().to_owned(),
        }
    }
}

/// Request body for saving a sandbox's next version: code under a runtime,
/// or, for an `image` sandbox, the company's image.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SaveVersionBody {
    /// The runtime it runs under, of the sandbox's language and offered
    /// now: `python-3.11`, `python-3.12`, `python-3.13`, `node-20`,
    /// `node-22` or `node-24`. The version keeps the exact image it is
    /// offered in now. Left out for an image.
    #[serde(default)]
    pub runtime: Option<String>,
    /// The company's image for an `image` sandbox, by its registry, path
    /// and tag or digest, such as `registry.acme.example/tools/codegen:1.4`.
    /// The registry must be on the tenant's list; the version keeps the
    /// digest the tag points to now. Given alone, without `runtime`,
    /// `code`, `import` or `packages`.
    #[serde(default)]
    pub image: Option<String>,
    /// The code, at most 256 KiB. Left out when it is imported.
    #[serde(default)]
    pub code: Option<String>,
    /// A repository's file the code is read from instead, at the commit its
    /// ref points to now. Left out when `code` is given.
    #[serde(default)]
    pub import: Option<ImportBody>,
    /// The packages it pins, each at one exact version, at most 50.
    #[serde(default)]
    pub packages: Vec<PackageBody>,
    /// The longest one run may take, from 1 to 300 seconds.
    pub run_seconds: u32,
    /// The memory one run is given, from 64 to 2048 MiB.
    pub memory_mib: u32,
    /// The hosts its code may reach over `https`, by exact DNS name, such
    /// as `api.github.com`, at most 20. Empty, or left out, the code
    /// reaches no network at all.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// An agent the version holds, with the rules it works under; the code
    /// is then the check each of its answers must pass. Left out when the
    /// code is the step's work. Not taken with an image.
    #[serde(default)]
    pub agent: Option<HeldAgentBody>,
}

/// A repository's file a version's code is read from.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ImportBody {
    /// The GitHub or GitLab account it is read through, one the caller
    /// owns or may manage.
    pub account_id: Uuid,
    /// The repository, such as `acme/web`.
    pub repository: String,
    /// The file, such as `scripts/tidy.py`.
    pub path: String,
    /// The branch, tag or commit it is read at, such as `main`.
    #[serde(rename = "ref")]
    pub at: String,
}

/// What a saved version's body asks for: code, or the company's image.
pub(crate) enum VersionSaving {
    /// Code under a runtime.
    Code(Box<SaveVersionRequest>),
    /// The company's image.
    Image(SaveRequest),
}

impl SaveVersionBody {
    /// Saving this as the next version of `sandbox_id`.
    ///
    /// # Errors
    ///
    /// - `422` when the runtime, the image, the code, the file, the limits
    ///   or a host are not valid, a host is named twice, the body gives both
    ///   or neither of `code` and `import`, or an image beside code.
    pub(crate) fn saving(self, sandbox_id: SandboxId) -> Result<VersionSaving, ApiError> {
        let budget =
            RunBudget::new(self.run_seconds, self.memory_mib).map_err(ApiError::validation)?;
        let only_an_image = self.names_only_an_image();
        let network = network_of(self.allowed_hosts)?;
        let Some(image) = self.image else {
            let runtime = self.runtime.ok_or_else(runtime_or_image)?;
            return Ok(VersionSaving::Code(Box::new(SaveVersionRequest {
                sandbox_id,
                runtime: Runtime::parse(&runtime).map_err(ApiError::validation)?,
                code: version_code(self.code, self.import)?,
                packages: written_packages(self.packages),
                budget,
                network,
                agent: self.agent.map(HeldAgentBody::rules).transpose()?,
            })));
        };
        if !only_an_image {
            return Err(runtime_or_image());
        }
        Ok(VersionSaving::Image(SaveRequest {
            sandbox_id,
            image: ImageName::parse(&image).map_err(ApiError::validation)?,
            budget,
            network,
        }))
    }
}

impl SaveVersionBody {
    /// Whether the body names nothing beside an image that code would: no
    /// runtime, code, import, package or agent.
    fn names_only_an_image(&self) -> bool {
        self.runtime.is_none()
            && self.code.is_none()
            && self.import.is_none()
            && self.packages.is_empty()
            && self.agent.is_none()
    }
}

/// The packages `bodies` pin, as written.
fn written_packages(bodies: Vec<PackageBody>) -> Vec<WrittenPackage> {
    bodies
        .into_iter()
        .map(|package| WrittenPackage {
            name: package.name,
            version: package.version,
        })
        .collect()
}

/// The hosts `hosts` names, each once.
fn network_of(hosts: Vec<String>) -> Result<NetworkAccess, ApiError> {
    let hosts = hosts
        .into_iter()
        .map(|host| AllowedHost::new(host).map_err(ApiError::validation))
        .collect::<Result<Vec<_>, _>>()?;
    NetworkAccess::new(hosts).map_err(ApiError::validation)
}

/// The refusal of a body naming neither a runtime nor an image, or an
/// image beside code.
fn runtime_or_image() -> ApiError {
    ApiError::validation(DomainError::invalid(message!(
        "workflows-a-version-runs-code-or-an-image",
        "give a runtime with code, or an image alone"
    )))
}

/// The code `code` gives, or the file `import` names: exactly one of them.
fn version_code(code: Option<String>, import: Option<ImportBody>) -> Result<VersionCode, ApiError> {
    match (code, import) {
        (Some(code), None) => Ok(VersionCode::Written(
            SandboxCode::new(code).map_err(ApiError::validation)?,
        )),
        (None, Some(import)) => Ok(VersionCode::Imported {
            account: IntegrationAccountId::from_uuid(import.account_id),
            repository: RepositoryName::new(import.repository).map_err(ApiError::validation)?,
            path: RepositoryPath::new(import.path).map_err(ApiError::validation)?,
            at: GitRef::new(import.at).map_err(ApiError::validation)?,
        }),
        _ => Err(ApiError::validation(DomainError::invalid(message!(
            "workflows-a-version-has-code-or-an-import",
            "give the version's code or a file to import it from, not both"
        )))),
    }
}

/// How many known vulnerabilities below critical a company's image was
/// found to have; none of them refuse it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FindingsResponse {
    /// Findings rated high.
    pub high: u32,
    /// Findings rated medium.
    pub medium: u32,
    /// Findings rated low or not rated.
    pub low: u32,
}

impl From<LesserFindings> for FindingsResponse {
    fn from(findings: LesserFindings) -> Self {
        Self {
            high: findings.high,
            medium: findings.medium,
            low: findings.low,
        }
    }
}

/// How far building a version's package bundle, or scanning its image, got.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct BuildResponse {
    /// `building`, `ready` or `failed`.
    pub status: String,
    /// The bundle's SHA-256, once ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// How large the bundle is in bytes, once ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Packages a pinned one says it needs that the version does not pin,
    /// once ready. They are not in the bundle; pin them in a next version
    /// when the code needs them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unlisted: Vec<String>,
    /// What scanning a company's image found below critical, once it is
    /// ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<FindingsResponse>,
    /// Why it failed, once failed: such as `fingerprint_mismatch`,
    /// `install_script`, `no_wheel`, `bad_archive`, `wrong_runtime`, `not_found`,
    /// `too_large` or `registry_unavailable`; for an image
    /// `critical_vulnerabilities`, `not_scanned` when no scanner is set up,
    /// `scanner_unavailable`, `registry_not_allowed` or `own_images_off`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    /// The package it names, how large the bundle came to, or the critical
    /// findings, comma-separated; absent when there is nothing more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl From<&Build> for BuildResponse {
    fn from(build: &Build) -> Self {
        let none = Self {
            status: build.as_str().to_owned(),
            digest: None,
            bytes: None,
            unlisted: Vec::new(),
            findings: None,
            failure: None,
            detail: None,
        };
        match build {
            Build::Building => none,
            Build::Ready(bundle) => Self {
                digest: Some(bundle.digest().as_str().to_owned()),
                bytes: Some(bundle.bytes()),
                unlisted: bundle.unlisted().iter().map(ToString::to_string).collect(),
                ..none
            },
            Build::Cleared(findings) => Self {
                findings: Some(FindingsResponse::from(*findings)),
                ..none
            },
            Build::Failed(failure) => Self {
                failure: Some(failure.code().to_owned()),
                detail: Some(failure.detail()).filter(|detail| !detail.is_empty()),
                ..none
            },
        }
    }
}

/// The repository file a version's code was imported from.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ImportedFromResponse {
    /// The integration of the service keeping it, such as `github`.
    pub integration: String,
    /// The source repository containing the imported file.
    pub repository: String,
    /// The file.
    pub path: String,
    /// The exact commit it was read at.
    pub commit: String,
}

/// One saved version of a sandbox.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SandboxVersionResponse {
    /// Unique identifier: what a workflow step names.
    pub id: Uuid,
    /// The sandbox it is a version of.
    pub sandbox_id: Uuid,
    /// Its number, from 1.
    pub number: u32,
    /// What it runs: `code`, or `image` for the company's own image.
    pub kind: String,
    /// The runtime it runs under, such as `python-3.13` or `node-22`;
    /// absent for an image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// The exact image it runs in every time, named by its content: the
    /// runtime's, or the company's own pinned to its digest.
    pub image: String,
    /// How large the company's image is, in bytes, as its registry counts
    /// its layers; absent for code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_bytes: Option<u64>,
    /// The saved source executed under the pinned runtime image; absent
    /// for an image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// The file its code was imported from; absent for code written here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported_from: Option<ImportedFromResponse>,
    /// The packages it pins.
    pub packages: Vec<PackageBody>,
    /// The longest one run may take, in seconds.
    pub run_seconds: u32,
    /// The memory one run is given, in MiB.
    pub memory_mib: u32,
    /// The hosts its code may reach over `https`; empty when it reaches no
    /// network.
    pub allowed_hosts: Vec<String>,
    /// How far building its package bundle got.
    pub build: BuildResponse,
    /// The agent it holds and the rules it works under, its code the check
    /// of every answer; absent when its program is the step's work.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<HeldAgentBody>,
    /// The person who saved it, as `<kind>:<uuid>`.
    pub saved_by: String,
    /// When it was saved.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When its build last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// The packages `code` pins, in the order given; none for an image.
fn packages_of(code: Option<&CodeProgram>) -> Vec<PackageBody> {
    code.map(|code| code.packages().as_slice())
        .unwrap_or_default()
        .iter()
        .map(PackageBody::from)
        .collect()
}

impl From<SandboxVersion<ResolvedTenant>> for SandboxVersionResponse {
    fn from(version: SandboxVersion<ResolvedTenant>) -> Self {
        let recipe = version.recipe();
        let code = recipe.program().code();
        Self {
            id: *version.id().as_uuid(),
            sandbox_id: *version.sandbox_id().as_uuid(),
            number: version.number(),
            kind: program_kind(recipe.program()).to_owned(),
            runtime: code.map(|code| code.runtime().as_str().to_owned()),
            image: recipe.program().image().to_owned(),
            image_bytes: image_bytes_of(recipe.program()),
            code: code.map(|code| code.code().as_str().to_owned()),
            imported_from: imported_from(version.source()),
            packages: packages_of(code),
            run_seconds: recipe.budget().seconds(),
            memory_mib: recipe.budget().memory_mib(),
            allowed_hosts: recipe
                .network()
                .hosts()
                .iter()
                .map(ToString::to_string)
                .collect(),
            build: BuildResponse::from(version.build()),
            agent: version.held_agent().map(HeldAgentBody::from),
            saved_by: person_label(version.saved_by()),
            created_at: version.created_at(),
            updated_at: version.updated_at(),
        }
    }
}

/// How large `program`'s company image is; `None` for code.
fn image_bytes_of(program: &Program) -> Option<u64> {
    match program {
        Program::Image(own) => Some(own.bytes()),
        Program::Code(_) => None,
    }
}

/// What `program` runs, as the wire names it.
fn program_kind(program: &Program) -> &'static str {
    match program {
        Program::Code(_) => "code",
        Program::Image(_) => "image",
    }
}

/// The file `source` names, when the code was imported.
fn imported_from(source: &CodeSource) -> Option<ImportedFromResponse> {
    let CodeSource::Imported(file) = source else {
        return None;
    };
    Some(ImportedFromResponse {
        integration: file.integration.as_str().to_owned(),
        repository: file.repository.as_str().to_owned(),
        path: file.path.as_str().to_owned(),
        commit: file.commit.as_str().to_owned(),
    })
}
