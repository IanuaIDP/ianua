//! A sandbox version as its row holds it: read back into the aggregate, and
//! written out from it.
//!
//! What it runs is kept as a word: code, with its runtime, code and
//! packages, or the company's image, with its size. Its build is kept as a
//! word, with the bundle's digest, size and the packages a pinned one needs
//! once ready, or for an image what its scan found below critical, or the
//! failure's word and its detail once failed: the package it names, how
//! large the bundle came to, or the critical findings. Where its code came
//! from is in its source columns.

use ianua_domain::domains::workflows::sandbox::build::{Build, BuildFailure, Bundle, BundleDigest};
use ianua_domain::domains::workflows::sandbox::image::{
    LesserFindings, OwnImage, PinnedImage, VulnerabilityId,
};
use ianua_domain::domains::workflows::sandbox::network::{AllowedHost, NetworkAccess};
use ianua_domain::domains::workflows::sandbox::package::{
    PackageName, PackageVersion, Packages, PinnedPackage,
};
use ianua_domain::domains::workflows::sandbox::recipe::{
    CodeParams, CodeProgram, Program, Recipe, RunBudget, SandboxCode,
};
use ianua_domain::domains::workflows::sandbox::runtime::{Language, Runtime, RuntimeImage};
use ianua_domain::domains::workflows::sandbox::version::{SandboxVersion, SandboxVersionRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{SandboxId, SandboxVersionId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _, stored_words};
use crate::postgres::workflows::sandboxes::versions::held::{held_agent_of, holds_from};
use crate::postgres::workflows::sandboxes::versions::source::SourceColumns;

const VERSION: Stored = Stored("sandbox version");

const PACKAGES: Kept = Kept {
    entity: VERSION.0,
    column: "packages",
    shape: 1,
};

const SAVED_BY: Kept = Kept {
    entity: VERSION.0,
    column: "saved_by",
    shape: 1,
};

stored_words! {
    Runtime as "sandbox runtime" {
        Python311 => "python-3.11",
        Python312 => "python-3.12",
        Python313 => "python-3.13",
        Node20 => "node-20",
        Node22 => "node-22",
        Node24 => "node-24",
    }
}

/// Which case of [`Program`] a version runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgramKind {
    Code,
    Image,
}

stored_words! {
    ProgramKind as "sandbox program" {
        Code => "code",
        Image => "image",
    }
}

/// Which case of [`Build`] a version stands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildKind {
    Building,
    Ready,
    Failed,
}

stored_words! {
    BuildKind as "sandbox build" {
        Building => "building",
        Ready => "ready",
        Failed => "failed",
    }
}

/// Which case of [`BuildFailure`] a failed build is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    NotFound,
    FingerprintMismatch,
    InstallScript,
    NoWheel,
    BadArchive,
    WrongRuntime,
    TooLarge,
    RegistryUnavailable,
    CriticalVulnerabilities,
    NotScanned,
    ScannerUnavailable,
    RegistryNotAllowed,
    OwnImagesOff,
}

stored_words! {
    FailureKind as "sandbox build failure" {
        NotFound => "not_found",
        FingerprintMismatch => "fingerprint_mismatch",
        InstallScript => "install_script",
        NoWheel => "no_wheel",
        BadArchive => "bad_archive",
        WrongRuntime => "wrong_runtime",
        TooLarge => "too_large",
        RegistryUnavailable => "registry_unavailable",
        CriticalVulnerabilities => "critical_vulnerabilities",
        NotScanned => "not_scanned",
        ScannerUnavailable => "scanner_unavailable",
        RegistryNotAllowed => "registry_not_allowed",
        OwnImagesOff => "own_images_off",
    }
}

impl FailureKind {
    fn of(failure: &BuildFailure) -> Self {
        match failure {
            BuildFailure::NotFound(_) => Self::NotFound,
            BuildFailure::FingerprintMismatch(_) => Self::FingerprintMismatch,
            BuildFailure::InstallScript(_) => Self::InstallScript,
            BuildFailure::NoWheel(_) => Self::NoWheel,
            BuildFailure::BadArchive(_) => Self::BadArchive,
            BuildFailure::WrongRuntime(_) => Self::WrongRuntime,
            BuildFailure::TooLarge { .. } => Self::TooLarge,
            BuildFailure::RegistryUnavailable => Self::RegistryUnavailable,
            BuildFailure::CriticalVulnerabilities(_) => Self::CriticalVulnerabilities,
            BuildFailure::NotScanned => Self::NotScanned,
            BuildFailure::ScannerUnavailable => Self::ScannerUnavailable,
            BuildFailure::RegistryNotAllowed => Self::RegistryNotAllowed,
            BuildFailure::OwnImagesOff => Self::OwnImagesOff,
        }
    }
}

impl ProgramKind {
    fn of(program: &Program) -> Self {
        match program {
            Program::Code(_) => Self::Code,
            Program::Image(_) => Self::Image,
        }
    }
}

/// The `image_bytes` column of `program`: the company's image's size, or
/// empty for code.
fn image_bytes_of(program: &Program) -> Result<Option<i64>, DomainError> {
    match program {
        Program::Image(own) => i64::try_from(own.bytes())
            .map(Some)
            .map_err(DomainError::infra),
        Program::Code(_) => Ok(None),
    }
}

/// The `packages` column `code` pins are written to, as name and version
/// pairs in their order.
fn packages_of(code: &CodeProgram) -> Result<Value, DomainError> {
    let packages: Vec<[&str; 2]> = code
        .packages()
        .as_slice()
        .iter()
        .map(|pinned| [pinned.name().as_str(), pinned.version().as_str()])
        .collect();
    PACKAGES.seal(&packages)
}

/// A version as it is read. The store's checked queries fill it.
pub(super) struct VersionRecord {
    pub(super) id: Uuid,
    pub(super) sandbox_id: Uuid,
    pub(super) number: i32,
    pub(super) program: String,
    pub(super) runtime: Option<String>,
    pub(super) image: String,
    pub(super) code: Option<String>,
    pub(super) packages: Option<Value>,
    pub(super) image_bytes: Option<i64>,
    pub(super) run_seconds: i32,
    pub(super) memory_mib: i32,
    pub(super) build: String,
    pub(super) bundle_digest: Option<String>,
    pub(super) bundle_bytes: Option<i64>,
    pub(super) unlisted: Option<Vec<String>>,
    pub(super) failure: Option<String>,
    pub(super) failure_detail: Option<String>,
    pub(super) scan_high: Option<i32>,
    pub(super) scan_medium: Option<i32>,
    pub(super) scan_low: Option<i32>,
    pub(super) saved_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
    pub(super) allowed_hosts: Vec<String>,
    pub(super) source_integration: Option<String>,
    pub(super) source_repository: Option<String>,
    pub(super) source_path: Option<String>,
    pub(super) source_commit: Option<String>,
    pub(super) held_agent: Option<Value>,
}

/// What the program columns of a row hold.
struct ProgramColumnsRead {
    kind: ProgramKind,
    runtime: Option<String>,
    image: String,
    code: Option<String>,
    packages: Option<Value>,
    image_bytes: Option<i64>,
}

/// What the build columns of a row hold.
struct BuildColumnsRead {
    kind: BuildKind,
    digest: Option<String>,
    bytes: Option<i64>,
    unlisted: Option<Vec<String>>,
    failure: Option<String>,
    detail: Option<String>,
    scan: ScanColumns,
}

/// What a cleared image's scan found below critical, as its columns hold
/// it: all three counts, or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct ScanColumns {
    pub(super) scan_high: Option<i32>,
    pub(super) scan_medium: Option<i32>,
    pub(super) scan_low: Option<i32>,
}

impl ScanColumns {
    /// The columns `findings` is written to.
    fn of(findings: LesserFindings) -> Result<Self, DomainError> {
        let count = |count: u32| i32::try_from(count).map(Some).map_err(DomainError::infra);
        Ok(Self {
            scan_high: count(findings.high)?,
            scan_medium: count(findings.medium)?,
            scan_low: count(findings.low)?,
        })
    }

    /// The findings the columns hold; `None` when they hold none.
    fn findings(self) -> Result<Option<LesserFindings>, DomainError> {
        let count = |count: i32| {
            u32::try_from(count)
                .map_err(|_| DomainError::corrupt_row(VERSION.0, "a negative finding count"))
        };
        match (self.scan_high, self.scan_medium, self.scan_low) {
            (None, None, None) => Ok(None),
            (Some(high), Some(medium), Some(low)) => Ok(Some(LesserFindings {
                high: count(high)?,
                medium: count(medium)?,
                low: count(low)?,
            })),
            _ => Err(DomainError::corrupt_row(
                VERSION.0,
                "a scan missing a count",
            )),
        }
    }
}

impl VersionRecord {
    /// The version the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the version
    /// keeps.
    // Keep the direct recipe, build and aggregate conversion together in its validation order.
    #[expect(
        clippy::too_many_lines,
        reason = "one checked row maps directly to its recipe, build and aggregate without cloning columns"
    )]
    pub(super) fn into_version(self) -> Result<SandboxVersion<ResolvedTenant>, DomainError> {
        let program = program_from(ProgramColumnsRead {
            kind: VERSION.choice(&self.program)?,
            runtime: self.runtime,
            image: self.image,
            code: self.code,
            packages: self.packages,
            image_bytes: self.image_bytes,
        })?;
        let language = program.code().map(|code| code.runtime().language());
        let recipe = Recipe::new(
            program,
            budget_from(self.run_seconds, self.memory_mib)?,
            network_from(self.allowed_hosts)?,
        );
        let build = build_from(
            language,
            BuildColumnsRead {
                kind: VERSION.choice(&self.build)?,
                digest: self.bundle_digest,
                bytes: self.bundle_bytes,
                unlisted: self.unlisted,
                failure: self.failure,
                detail: self.failure_detail,
                scan: ScanColumns {
                    scan_high: self.scan_high,
                    scan_medium: self.scan_medium,
                    scan_low: self.scan_low,
                },
            },
        )?;
        SandboxVersion::reconstitute(SandboxVersionRow {
            id: SandboxVersionId::from_uuid(self.id),
            sandbox_id: SandboxId::from_uuid(self.sandbox_id),
            number: u32::try_from(self.number)
                .map_err(|_| DomainError::corrupt_row(VERSION.0, "a negative number"))?,
            recipe,
            build,
            source: SourceColumns {
                integration: self.source_integration,
                repository: self.source_repository,
                path: self.source_path,
                commit: self.source_commit,
            }
            .into_source()?,
            holds: holds_from(self.held_agent)?,
            saved_by: SAVED_BY.open(self.saved_by)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// What a row's program columns say the version runs.
fn program_from(read: ProgramColumnsRead) -> Result<Program, DomainError> {
    match (
        read.kind,
        read.runtime,
        read.code,
        read.packages,
        read.image_bytes,
    ) {
        (ProgramKind::Code, Some(runtime), Some(code), Some(packages), None) => {
            code_from(&runtime, read.image, code, packages).map(Program::Code)
        }
        (ProgramKind::Image, None, None, None, Some(bytes)) => {
            own_image_from(&read.image, bytes).map(Program::Image)
        }
        (ProgramKind::Code | ProgramKind::Image, ..) => Err(DomainError::corrupt_row(
            VERSION.0,
            "a program its columns contradict",
        )),
    }
}

/// Code under `runtime` in `image`, pinning `packages`.
fn code_from(
    runtime: &str,
    image: String,
    code: String,
    packages: Value,
) -> Result<CodeProgram, DomainError> {
    let runtime: Runtime = VERSION.choice(runtime)?;
    CodeProgram::new(CodeParams {
        runtime,
        image: VERSION.value("image", RuntimeImage::new(image))?,
        code: VERSION.value("code", SandboxCode::new(code))?,
        packages: packages_from(runtime.language(), PACKAGES.open(packages)?)?,
    })
    .map_err(|_| DomainError::corrupt_row(VERSION.0, "a package of another language"))
}

/// The company's image `image`, of `bytes`.
fn own_image_from(image: &str, bytes: i64) -> Result<OwnImage, DomainError> {
    let image = PinnedImage::parse(image)
        .map_err(|_| DomainError::corrupt_row(VERSION.0, "an image not pinned to its digest"))?;
    let bytes = u64::try_from(bytes).map_err(DomainError::infra)?;
    OwnImage::new(image, bytes)
        .map_err(|_| DomainError::corrupt_row(VERSION.0, "an image larger than any may be"))
}

/// The packages a row pins, read as `language`'s registry names them.
fn packages_from(language: Language, stored: Vec<[String; 2]>) -> Result<Packages, DomainError> {
    let pinned = stored
        .into_iter()
        .map(|[name, version]| {
            Ok(PinnedPackage::new(
                VERSION.value("package name", PackageName::new(language, name))?,
                VERSION.value("package version", PackageVersion::new(language, version))?,
            ))
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    Packages::new(pinned)
        .map_err(|_| DomainError::corrupt_row(VERSION.0, "packages its rules refuse"))
}

/// The hosts a row lets the version's code reach.
fn network_from(stored: Vec<String>) -> Result<NetworkAccess, DomainError> {
    let hosts = stored
        .into_iter()
        .map(|host| VERSION.value("allowed host", AllowedHost::new(host)))
        .collect::<Result<Vec<_>, DomainError>>()?;
    NetworkAccess::new(hosts)
        .map_err(|_| DomainError::corrupt_row(VERSION.0, "allowed hosts their rules refuse"))
}

fn budget_from(seconds: i32, memory: i32) -> Result<RunBudget, DomainError> {
    let seconds = u32::try_from(seconds).map_err(DomainError::infra)?;
    let memory = u32::try_from(memory).map_err(DomainError::infra)?;
    RunBudget::new(seconds, memory)
        .map_err(|_| DomainError::corrupt_row(VERSION.0, "a run budget out of range"))
}

/// The build a row's columns hold, for a version of code in `language`, or
/// of an image when there is none.
fn build_from(language: Option<Language>, read: BuildColumnsRead) -> Result<Build, DomainError> {
    let scan = read.scan.findings()?;
    match (
        read.kind,
        read.digest,
        read.bytes,
        read.unlisted,
        read.failure,
        read.detail,
        scan,
    ) {
        (BuildKind::Building, None, None, None, None, None, None) => Ok(Build::Building),
        (BuildKind::Ready, Some(digest), Some(bytes), Some(unlisted), None, None, None) => {
            bundle_from(language, &digest, bytes, unlisted).map(Build::Ready)
        }
        (BuildKind::Ready, None, None, None, None, None, Some(findings)) => {
            Ok(Build::Cleared(findings))
        }
        (BuildKind::Failed, None, None, None, Some(failure), Some(detail), None) => {
            failure_from(language, VERSION.choice(&failure)?, detail).map(Build::Failed)
        }
        (BuildKind::Building | BuildKind::Ready | BuildKind::Failed, ..) => Err(
            DomainError::corrupt_row(VERSION.0, "a build its columns contradict"),
        ),
    }
}

/// The language a version's packages are read in; an image has none.
fn language_of(language: Option<Language>) -> Result<Language, DomainError> {
    language.ok_or_else(|| DomainError::corrupt_row(VERSION.0, "a package of an image version"))
}

fn bundle_from(
    language: Option<Language>,
    digest: &str,
    bytes: i64,
    unlisted: Vec<String>,
) -> Result<Bundle, DomainError> {
    let language = language_of(language)?;
    let unlisted = unlisted
        .into_iter()
        .map(|name| VERSION.value("unlisted package", PackageName::new(language, name)))
        .collect::<Result<Vec<_>, DomainError>>()?;
    Bundle::new(
        VERSION.value("bundle digest", BundleDigest::new(digest))?,
        u64::try_from(bytes).map_err(DomainError::infra)?,
        unlisted,
    )
    .map_err(|_| DomainError::corrupt_row(VERSION.0, "a bundle larger than any may be"))
}

fn failure_from(
    language: Option<Language>,
    kind: FailureKind,
    detail: String,
) -> Result<BuildFailure, DomainError> {
    let package = |detail: String| {
        VERSION.value(
            "failed package",
            PackageName::new(language_of(language)?, detail),
        )
    };
    Ok(match kind {
        FailureKind::NotFound => BuildFailure::NotFound(package(detail)?),
        FailureKind::FingerprintMismatch => BuildFailure::FingerprintMismatch(package(detail)?),
        FailureKind::InstallScript => BuildFailure::InstallScript(package(detail)?),
        FailureKind::NoWheel => BuildFailure::NoWheel(package(detail)?),
        FailureKind::BadArchive => BuildFailure::BadArchive(package(detail)?),
        FailureKind::WrongRuntime => BuildFailure::WrongRuntime(package(detail)?),
        FailureKind::TooLarge => BuildFailure::TooLarge {
            bytes: detail.parse().map_err(DomainError::infra)?,
        },
        FailureKind::RegistryUnavailable => BuildFailure::RegistryUnavailable,
        FailureKind::CriticalVulnerabilities => {
            BuildFailure::CriticalVulnerabilities(findings_from(&detail)?)
        }
        FailureKind::NotScanned => BuildFailure::NotScanned,
        FailureKind::ScannerUnavailable => BuildFailure::ScannerUnavailable,
        FailureKind::RegistryNotAllowed => BuildFailure::RegistryNotAllowed,
        FailureKind::OwnImagesOff => BuildFailure::OwnImagesOff,
    })
}

/// The critical findings a refused image's detail names, comma-separated.
fn findings_from(detail: &str) -> Result<Vec<VulnerabilityId>, DomainError> {
    detail
        .split(", ")
        .map(|finding| VERSION.value("critical finding", VulnerabilityId::new(finding)))
        .collect()
}

/// A version's build, as its columns write it.
pub(super) struct BuildColumns {
    pub(super) build: &'static str,
    pub(super) bundle_digest: Option<String>,
    pub(super) bundle_bytes: Option<i64>,
    pub(super) unlisted: Option<Vec<String>>,
    pub(super) failure: Option<&'static str>,
    pub(super) failure_detail: Option<String>,
    pub(super) scan: ScanColumns,
}

impl BuildColumns {
    /// The columns `build` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the bundle's size or a
    /// finding count does not fit its column.
    pub(super) fn of(build: &Build) -> Result<Self, DomainError> {
        Ok(match build {
            Build::Building => Self::building(),
            Build::Ready(bundle) => Self::ready(bundle)?,
            Build::Cleared(findings) => Self {
                build: BuildKind::Ready.word(),
                scan: ScanColumns::of(*findings)?,
                ..Self::building()
            },
            Build::Failed(failure) => Self {
                build: BuildKind::Failed.word(),
                failure: Some(FailureKind::of(failure).word()),
                failure_detail: Some(failure.detail()),
                ..Self::building()
            },
        })
    }

    /// The columns of a version still being built: every other one empty.
    fn building() -> Self {
        Self {
            build: BuildKind::Building.word(),
            bundle_digest: None,
            bundle_bytes: None,
            unlisted: None,
            failure: None,
            failure_detail: None,
            scan: ScanColumns::default(),
        }
    }

    /// The columns of a version whose `bundle` is ready.
    fn ready(bundle: &Bundle) -> Result<Self, DomainError> {
        Ok(Self {
            build: BuildKind::Ready.word(),
            bundle_digest: Some(bundle.digest().as_str().to_owned()),
            bundle_bytes: Some(i64::try_from(bundle.bytes()).map_err(DomainError::infra)?),
            unlisted: Some(
                bundle
                    .unlisted()
                    .iter()
                    .map(|name| name.as_str().to_owned())
                    .collect(),
            ),
            ..Self::building()
        })
    }
}

/// A version's columns, as they are written.
pub(super) struct VersionColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) sandbox_id: &'a Uuid,
    pub(super) number: i32,
    pub(super) program: &'static str,
    pub(super) runtime: Option<&'static str>,
    pub(super) image: &'a str,
    pub(super) code: Option<&'a str>,
    pub(super) packages: Option<Value>,
    pub(super) image_bytes: Option<i64>,
    pub(super) run_seconds: i32,
    pub(super) memory_mib: i32,
    pub(super) build: BuildColumns,
    pub(super) saved_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
    pub(super) allowed_hosts: Vec<String>,
    pub(super) source: SourceColumns,
    pub(super) held_agent: Option<Value>,
}

impl<'a> VersionColumns<'a> {
    /// The columns `version` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out, or a number does not fit its column.
    pub(super) fn of(version: &'a SandboxVersion<ResolvedTenant>) -> Result<Self, DomainError> {
        let recipe = version.recipe();
        let code = recipe.program().code();
        Ok(Self {
            id: version.id().as_uuid(),
            sandbox_id: version.sandbox_id().as_uuid(),
            number: i32::try_from(version.number()).map_err(DomainError::infra)?,
            program: ProgramKind::of(recipe.program()).word(),
            runtime: code.map(|code| code.runtime().word()),
            image: recipe.program().image(),
            code: code.map(|code| code.code().as_str()),
            packages: code.map(packages_of).transpose()?,
            image_bytes: image_bytes_of(recipe.program())?,
            run_seconds: i32::try_from(recipe.budget().seconds()).map_err(DomainError::infra)?,
            memory_mib: i32::try_from(recipe.budget().memory_mib()).map_err(DomainError::infra)?,
            build: BuildColumns::of(version.build())?,
            saved_by: SAVED_BY.seal(version.saved_by())?,
            created_at: version.created_at(),
            updated_at: version.updated_at(),
            allowed_hosts: recipe
                .network()
                .hosts()
                .iter()
                .map(|host| host.as_str().to_owned())
                .collect(),
            source: SourceColumns::of(version.source()),
            held_agent: held_agent_of(version.holds())?,
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::types::{Human, HumanAccount, PersonKey, UserId};
    use serde_json::json;

    use super::*;

    /// The person who saved a version is written as their account and
    /// address, and read back.
    #[test]
    fn the_saver_is_stored_in_their_pinned_shape() {
        let ann = Human::new(
            HumanAccount::User(UserId::from_uuid(Uuid::nil())),
            PersonKey::new("ann@acme.example").unwrap(),
        );
        let stored = json!({"v": 1, "value": {
            "account": {"User": "00000000-0000-0000-0000-000000000000"},
            "person": "ann@acme.example"
        }});

        assert_eq!(SAVED_BY.seal(&ann).unwrap(), stored);
        assert_eq!(SAVED_BY.open::<Human>(stored).unwrap(), ann);
    }

    /// The packages a version pins are written as name and version pairs,
    /// in the order given, and read back.
    #[test]
    fn the_packages_are_stored_in_their_pinned_shape() {
        let stored = json!({"v": 1, "value": [["requests", "2.31.0"], ["idna", "3.7"]]});

        let read = packages_from(Language::Python, PACKAGES.open(stored.clone()).unwrap()).unwrap();
        let written: Vec<[&str; 2]> = read
            .as_slice()
            .iter()
            .map(|pinned| [pinned.name().as_str(), pinned.version().as_str()])
            .collect();

        assert_eq!(PACKAGES.seal(&written).unwrap(), stored);
    }

    /// A failed build naming a package, and one too large, are written as
    /// their word and detail and read back as they were.
    #[test]
    fn a_failed_build_reads_back_from_its_columns() {
        let requests = PackageName::new(Language::Python, "requests").unwrap();
        for failure in [
            BuildFailure::FingerprintMismatch(requests.clone()),
            BuildFailure::TooLarge { bytes: 300 },
            BuildFailure::RegistryUnavailable,
        ] {
            let columns = BuildColumns::of(&Build::Failed(failure.clone())).unwrap();

            let read = build_from(
                Some(Language::Python),
                BuildColumnsRead {
                    kind: BuildKind::Failed,
                    digest: None,
                    bytes: None,
                    unlisted: None,
                    failure: columns.failure.map(str::to_owned),
                    detail: columns.failure_detail,
                    scan: ScanColumns::default(),
                },
            )
            .unwrap();

            assert_eq!(read, Build::Failed(failure));
        }
    }

    /// Reading a ready build without its bundle digest returns an
    /// infrastructure error.
    #[test]
    fn a_ready_build_without_its_bundle_is_corrupt() {
        let read = build_from(
            Some(Language::Python),
            BuildColumnsRead {
                kind: BuildKind::Ready,
                digest: None,
                bytes: Some(10),
                unlisted: Some(Vec::new()),
                failure: None,
                detail: None,
                scan: ScanColumns::default(),
            },
        );

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// An image refused for two critical findings, and one no scanner
    /// cleared, are written as their word and detail and read back.
    #[test]
    fn an_image_failure_reads_back_from_its_columns() {
        let found = vec![
            VulnerabilityId::new("CVE-2024-3094").unwrap(),
            VulnerabilityId::new("GHSA-xvch-5gv4-984h").unwrap(),
        ];
        for failure in [
            BuildFailure::CriticalVulnerabilities(found.clone()),
            BuildFailure::NotScanned,
            BuildFailure::RegistryNotAllowed,
        ] {
            let columns = BuildColumns::of(&Build::Failed(failure.clone())).unwrap();

            let read = build_from(
                None,
                BuildColumnsRead {
                    kind: BuildKind::Failed,
                    digest: None,
                    bytes: None,
                    unlisted: None,
                    failure: columns.failure.map(str::to_owned),
                    detail: columns.failure_detail,
                    scan: ScanColumns::default(),
                },
            )
            .unwrap();

            assert_eq!(read, Build::Failed(failure));
        }
    }

    /// A cleared image is written as ready with its three counts, and read
    /// back so; a ready image missing a count is corrupt.
    #[test]
    fn a_cleared_image_reads_back_with_its_findings() {
        let findings = LesserFindings {
            high: 2,
            medium: 5,
            low: 9,
        };
        let scan = BuildColumns::of(&Build::Cleared(findings)).unwrap().scan;
        let read = |scan: ScanColumns| {
            build_from(
                None,
                BuildColumnsRead {
                    kind: BuildKind::Ready,
                    digest: None,
                    bytes: None,
                    unlisted: None,
                    failure: None,
                    detail: None,
                    scan,
                },
            )
        };

        let partial = read(ScanColumns {
            scan_low: None,
            ..scan
        });

        assert_eq!(read(scan).unwrap(), Build::Cleared(findings));
        assert!(matches!(partial, Err(DomainError::Infrastructure(_))));
    }

    /// Code columns on an image row, or an image row with no size, are
    /// corrupt.
    #[test]
    fn a_program_its_columns_contradict_is_corrupt() {
        let image = format!("registry.acme.example/codegen@sha256:{}", "ab".repeat(32));
        let read = |runtime: Option<&str>, image_bytes: Option<i64>| {
            program_from(ProgramColumnsRead {
                kind: ProgramKind::Image,
                runtime: runtime.map(str::to_owned),
                image: image.clone(),
                code: None,
                packages: None,
                image_bytes,
            })
        };

        assert!(matches!(read(None, Some(1024)), Ok(Program::Image(_))));
        assert!(read(Some("python-3.13"), Some(1024)).is_err());
        assert!(read(None, None).is_err());
    }
}
