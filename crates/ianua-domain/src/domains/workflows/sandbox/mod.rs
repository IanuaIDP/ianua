//! Sandboxes: a tenant's named recipes of code, pinned packages and limits,
//! each saved as numbered versions that never change.
//!
//! A sandbox is a recipe, never a running container. Saving a version has
//! its packages fetched, checked against the fingerprints their registry
//! published and stored as one bundle; a run later starts a fresh container
//! from the exact image of its runtime the version was saved with, with
//! that bundle mounted. Its language never changes, so its packages always
//! come from the same registry; each version picks a runtime of it. Who may
//! make, change and archive one is who may do so for workflows, which pick
//! a sandbox's version as a step.
//!
//! A sandbox of a company's own image holds no code: each version keeps
//! the image pinned to its digest, from a registry the tenant allowed, and
//! is scanned for known vulnerabilities before it first runs.
//!
//! A version may also hold an agent with the rules it works under; its
//! program is then the check every answer of that agent must pass (see
//! [`agent`]).

pub mod agent;
pub mod build;
pub mod image;
pub mod network;
pub mod package;
pub mod recipe;
pub mod registry;
pub mod runtime;
pub mod source;
pub mod trial;
pub mod version;

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::events::{SandboxArchived, SandboxCreated, SandboxRef};
use crate::domains::workflows::sandbox::agent::{HeldAgent, VersionHolds};
use crate::domains::workflows::sandbox::network::NetworkAccess;
use crate::domains::workflows::sandbox::recipe::{Program, Recipe, RunBudget};
use crate::domains::workflows::sandbox::runtime::{Language, Runtime};
use crate::domains::workflows::sandbox::source::CodeSource;
use crate::domains::workflows::sandbox::trial::{SandboxTrial, Starting};
use crate::domains::workflows::sandbox::version::{SandboxVersion, Saving};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::{EventLabel, Human, Label, SandboxId};

/// The most versions one sandbox keeps. Each keeps a package bundle in
/// storage, so a sandbox saved over and over cannot fill it.
pub(crate) const MAX_VERSIONS: u32 = 50;

/// Whether a sandbox still takes new versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// New versions are saved, and its versions are picked.
    Active,
    /// Nothing new is saved or picked. Versions already picked keep
    /// running, since what was published is what runs.
    Archived,
}

impl SandboxStatus {
    /// Moves to `to` if a sandbox in this status may: an active one is
    /// archived, an archived one stays as it is.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!((from, to), (Self::Active, Self::Archived))
        })
    }

    /// The stored and shown name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
        }
    }
}

/// What a sandbox's versions run, which never changes for a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxKind {
    /// Code in this language, under a runtime each version picks.
    Code(Language),
    /// The company's own image, which each version pins.
    OwnImage,
}

impl SandboxKind {
    /// The stored and shown name: `code` or `image`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Code(_) => "code",
            Self::OwnImage => "image",
        }
    }

    /// The language its code is written in; `None` for a company's image,
    /// which holds no code.
    #[must_use]
    pub fn language(self) -> Option<Language> {
        match self {
            Self::Code(language) => Some(language),
            Self::OwnImage => None,
        }
    }
}

/// The values a sandbox is made with.
pub struct CreateSandboxParams {
    /// Its name for people.
    pub name: Label,
    /// What its versions run.
    pub kind: SandboxKind,
}

/// What a person saves as a sandbox's next version.
pub struct VersionDraft {
    /// What it runs: code under a runtime of the sandbox's language, or the
    /// company's image pinned to its digest.
    pub program: Program,
    /// What one run may use.
    pub budget: RunBudget,
    /// The hosts its code may reach.
    pub network: NetworkAccess,
    /// Where its code came from; written for a company's image.
    pub source: CodeSource,
}

/// A sandbox as stored.
pub struct SandboxRow {
    /// The persisted identity shared by this code project's revisions.
    pub id: SandboxId,
    /// The display label people use when choosing this code project.
    pub name: Label,
    /// What its versions run: code of a language, or the company's image.
    pub kind: SandboxKind,
    /// Whether it still takes new versions.
    pub status: SandboxStatus,
    /// The number of its latest version; zero before the first.
    pub latest_version: u32,
    /// The person who made it.
    pub created_by: Human,
    /// When it was made.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// A tenant's named recipe of code, packages and limits.
#[derive(Debug, Clone)]
pub struct Sandbox<T: TenantScope> {
    id: SandboxId,
    name: Label,
    kind: SandboxKind,
    status: SandboxStatus,
    latest_version: u32,
    created_by: Human,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> Sandbox<T> {
    /// `by` makes a sandbox, with no version yet. Raises
    /// `workflows.sandbox_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not create workflows.
    pub fn create(
        params: CreateSandboxParams,
        by: &WorkflowControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(WorkflowAction::Create)?;
        let now = crate::shared::clock::now();
        let mut sandbox = Self {
            id: SandboxId::new(),
            name: params.name,
            kind: params.kind,
            status: SandboxStatus::Active,
            latest_version: 0,
            created_by: by.by().clone(),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        sandbox.raised.raise(SandboxCreated {
            sandbox: sandbox.sandbox_ref(),
            kind: sandbox.kind,
            occurred_at: now,
        });
        Ok(sandbox)
    }

    /// Rebuilds a sandbox from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it changed before it was made.
    /// - [`DomainError::Infrastructure`] when it claims more versions than a
    ///   sandbox keeps.
    pub fn reconstitute(row: SandboxRow) -> Result<Self, DomainError> {
        RowCheck::of("sandbox")
            .in_order(row.created_at, row.updated_at, "changed before it was made")
            .holds(
                row.latest_version <= MAX_VERSIONS,
                "more versions than a sandbox keeps",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            name: row.name,
            kind: row.kind,
            status: row.status,
            latest_version: row.latest_version,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// `by` saves `draft` as the sandbox's next version, whose bundle is
    /// then built, or its image scanned.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] or [`DomainError::Conflict`] when `by`
    ///   may not change workflows, or the sandbox is archived or full.
    /// - [`DomainError::Validation`] when the program is not of the
    ///   sandbox's kind.
    pub fn save_version(
        &mut self,
        by: &WorkflowControl<'_>,
        draft: VersionDraft,
    ) -> Result<SandboxVersion<T>, DomainError> {
        self.save(by, draft, VersionHolds::Code)
    }

    /// `by` saves `draft` as the sandbox's next version, holding `agent`:
    /// the agent does a step's work under its rules, and the draft's
    /// program checks each answer it gives. The rules are pinned with the
    /// version, so a step naming it runs exactly what was reviewed.
    ///
    /// # Errors
    ///
    /// As [`save_version`](Self::save_version).
    pub fn save_agent_version(
        &mut self,
        by: &WorkflowControl<'_>,
        draft: VersionDraft,
        agent: HeldAgent,
    ) -> Result<SandboxVersion<T>, DomainError> {
        self.save(by, draft, VersionHolds::Agent(Box::new(agent)))
    }

    /// `by` saves `draft`, holding `holds`, as the sandbox's next version.
    fn save(
        &mut self,
        by: &WorkflowControl<'_>,
        draft: VersionDraft,
        holds: VersionHolds,
    ) -> Result<SandboxVersion<T>, DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_active()?;
        self.ensure_room_for_a_version()?;
        self.ensure_takes(&draft)?;
        let number = self.latest_version.saturating_add(1);
        let recipe = Recipe::new(draft.program, draft.budget, draft.network);
        self.latest_version = number;
        self.updated_at = crate::shared::clock::now();
        Ok(SandboxVersion::saved(Saving {
            sandbox_id: self.id,
            number,
            recipe,
            source: draft.source,
            holds,
            by: by.by().clone(),
        }))
    }

    /// `by` tries `version` of this sandbox on `input`: a worker runs it as
    /// a code step would. Raises `workflows.sandbox_trial_started`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change workflows.
    /// - [`DomainError::Conflict`] when the sandbox is archived.
    /// - [`DomainError::NotFound`] when `version` is another sandbox's.
    /// - [`DomainError::Conflict`] when its bundle is not built.
    pub fn try_version(
        &self,
        by: &WorkflowControl<'_>,
        version: &SandboxVersion<T>,
        input: FlowData,
    ) -> Result<SandboxTrial<T>, DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_active()?;
        if version.sandbox_id() != &self.id {
            return Err(DomainError::NotFound);
        }
        if !version.build().is_ready() {
            return Err(DomainError::conflict(message!(
                "workflows-only-a-built-version-is-tried",
                "only a version whose bundle is built is tried"
            )));
        }
        Ok(SandboxTrial::started(Starting {
            version: version.version_ref(),
            network: version.recipe().network().clone(),
            input,
            by: by.by().clone(),
        }))
    }

    /// `by` archives the sandbox: nothing new is saved or picked. Raises
    /// `workflows.sandbox_archived`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete workflows.
    /// - [`DomainError::Conflict`] when it is archived already.
    pub fn archive(&mut self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Delete)?;
        self.ensure_active()?;
        self.status = self.status.try_transition(SandboxStatus::Archived)?;
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(SandboxArchived {
            sandbox: self.sandbox_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Refuses a sandbox that keeps `MAX_VERSIONS` already.
    fn ensure_room_for_a_version(&self) -> Result<(), DomainError> {
        if self.latest_version < MAX_VERSIONS {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "workflows-a-sandbox-keeps-at-most-versions",
            format!("a sandbox keeps at most {MAX_VERSIONS} versions; make a new sandbox for more")
        )))
    }

    /// Refuses a draft whose program is not of the sandbox's kind.
    fn ensure_takes(&self, draft: &VersionDraft) -> Result<(), DomainError> {
        match (self.kind, &draft.program) {
            (SandboxKind::Code(language), Program::Code(code)) => {
                ensure_runs(language, code.runtime())
            }
            (SandboxKind::OwnImage, Program::Image(_)) => ensure_written(&draft.source),
            (SandboxKind::Code(_), Program::Image(_)) => Err(DomainError::invalid(message!(
                "workflows-a-code-sandbox-runs-no-image",
                "a code sandbox runs code under a runtime; make an image sandbox for the company's own image"
            ))),
            (SandboxKind::OwnImage, Program::Code(_)) => Err(DomainError::invalid(message!(
                "workflows-an-image-sandbox-runs-no-code",
                "an image sandbox runs the company's own image, not code"
            ))),
        }
    }

    fn ensure_active(&self) -> Result<(), DomainError> {
        if self.status == SandboxStatus::Archived {
            return Err(DomainError::conflict(message!(
                "workflows-the-sandbox-is-archived",
                "the sandbox is archived"
            )));
        }
        Ok(())
    }

    fn sandbox_ref(&self) -> SandboxRef {
        SandboxRef {
            sandbox_id: self.id,
            label: EventLabel::of(self.name.as_str()),
        }
    }

    /// The stable identity shared by this code project's revisions.
    #[must_use]
    pub fn id(&self) -> &SandboxId {
        &self.id
    }

    /// Its name for people.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// What its versions run: code of a language, or the company's image.
    #[must_use]
    pub fn kind(&self) -> SandboxKind {
        self.kind
    }

    /// Whether it still takes new versions.
    #[must_use]
    pub fn status(&self) -> SandboxStatus {
        self.status
    }

    /// The number of its latest version; zero before the first.
    #[must_use]
    pub fn latest_version(&self) -> u32 {
        self.latest_version
    }

    /// The person who made it.
    #[must_use]
    pub fn created_by(&self) -> &Human {
        &self.created_by
    }
}

/// Refuses `runtime` when it runs another language than `language`.
fn ensure_runs(language: Language, runtime: Runtime) -> Result<(), DomainError> {
    if runtime.language() == language {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "workflows-the-runtime-is-not-of-the-sandbox-s-language",
        format!(
            "{} does not run {} code",
            runtime.as_str(),
            language.as_str()
        )
    )))
}

/// Refuses an image version said to come from a repository's file: an
/// image holds no code the platform reads.
fn ensure_written(source: &CodeSource) -> Result<(), DomainError> {
    match source {
        CodeSource::Written => Ok(()),
        CodeSource::Imported(_) => Err(DomainError::invalid(message!(
            "workflows-an-image-is-not-imported-code",
            "a company's image is pinned from its registry, never imported from a file"
        ))),
    }
}

impl<T: TenantScope> Raises for Sandbox<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for Sandbox<T> {
    type Id = SandboxId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
    use crate::domains::workflows::execution::tests::fixtures::{
        ann, bob, holding_only, managing, viewing,
    };
    use crate::domains::workflows::integration::IntegrationKey;
    use crate::domains::workflows::sandbox::build::{Build, BuildFailure, Bundle, BundleDigest};
    use crate::domains::workflows::sandbox::image::{
        ImageFindings, LesserFindings, OwnImage, PinnedImage, VulnerabilityId,
    };
    use crate::domains::workflows::sandbox::network::AllowedHost;
    use crate::domains::workflows::sandbox::package::{
        PackageName, PackageVersion, Packages, PinnedPackage,
    };
    use crate::domains::workflows::sandbox::recipe::{CodeParams, CodeProgram, SandboxCode};
    use crate::domains::workflows::sandbox::runtime::RuntimeImage;
    use crate::domains::workflows::sandbox::source::{
        CommitSha, GitRef, PushTarget, RepositoryFile, RepositoryName, RepositoryPath,
    };
    use crate::domains::workflows::sandbox::trial::TrialState;
    use crate::domains::workflows::sandbox::version::SandboxVersionRow;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};

    type Kept = Sandbox<ResolvedTenant>;

    fn requests() -> PackageName {
        PackageName::new(Language::Python, "requests").unwrap()
    }

    fn draft() -> VersionDraft {
        draft_under(Runtime::Python313)
    }

    fn draft_under(runtime: Runtime) -> VersionDraft {
        let code = CodeProgram::new(CodeParams {
            runtime,
            image: RuntimeImage::new(format!("python:3.13-slim@sha256:{}", "cd".repeat(32)))
                .unwrap(),
            code: SandboxCode::new("def main(item):\n\treturn item\n").unwrap(),
            packages: Packages::new(vec![PinnedPackage::new(
                requests(),
                PackageVersion::new(Language::Python, "2.31.0").unwrap(),
            )])
            .unwrap(),
        })
        .unwrap();
        VersionDraft {
            program: Program::Code(code),
            budget: RunBudget::new(30, 256).unwrap(),
            network: NetworkAccess::closed(),
            source: CodeSource::Written,
        }
    }

    fn made() -> Kept {
        Sandbox::create(
            CreateSandboxParams {
                name: Label::new("name", "Clean issue text").unwrap(),
                kind: SandboxKind::Code(Language::Python),
            },
            &managing(&ann()),
        )
        .unwrap()
    }

    fn bundle(unlisted: Vec<PackageName>) -> Bundle {
        Bundle::new(BundleDigest::new("b".repeat(64)).unwrap(), 4096, unlisted).unwrap()
    }

    /// Ann makes a Python sandbox. It has no version yet, and the trail
    /// records that it was made.
    #[test]
    fn a_sandbox_is_made_with_no_version() {
        let mut sandbox = made();

        assert_eq!(sandbox.latest_version(), 0);
        assert_eq!(sandbox.status(), SandboxStatus::Active);
        assert_eq!(raised_names(&mut sandbox), ["workflows.sandbox_created"]);
    }

    /// Ann saves twice under Python 3.13. The versions are numbered 1 and
    /// 2, keep the runtime and the exact image she saved them with, and
    /// each waits for its bundle, its save recorded.
    #[test]
    fn each_save_makes_the_next_version_under_its_runtime() {
        let mut sandbox = made();

        let mut first = sandbox.save_version(&managing(&ann()), draft()).unwrap();
        let second = sandbox.save_version(&managing(&ann()), draft()).unwrap();

        assert_eq!((first.number(), second.number()), (1, 2));
        assert_eq!(
            second.recipe().program().code().map(CodeProgram::runtime),
            Some(Runtime::Python313)
        );
        assert_eq!(second.recipe().program(), &draft().program);
        assert_eq!(second.build(), &Build::Building);
        assert_eq!(sandbox.latest_version(), 2);
        assert_eq!(
            raised_names(&mut first),
            ["workflows.sandbox_version_saved"]
        );
    }

    /// Ann saves a version that may reach `api.github.com`. The version
    /// keeps the host, and the record of the save names it; a version
    /// reaching no network names none.
    #[test]
    fn the_hosts_a_version_reaches_are_recorded() {
        let mut sandbox = made();
        let github = AllowedHost::new("api.github.com").unwrap();
        let reaching = VersionDraft {
            network: NetworkAccess::new(vec![github]).unwrap(),
            ..draft()
        };

        let mut networked = sandbox.save_version(&managing(&ann()), reaching).unwrap();
        let mut closed = sandbox.save_version(&managing(&ann()), draft()).unwrap();

        assert!(networked.recipe().network().allows("api.github.com"));
        let networked = raised(&mut networked);
        let closed = raised(&mut closed);
        assert_eq!(networked[0].payload().get("hosts"), Some("api.github.com"));
        assert_eq!(closed[0].payload().get("hosts"), None);
    }

    /// Ann tries her built version on sample input. The trial runs with
    /// that input, and its start is recorded with the hosts the version
    /// may reach. Once it ran it ends, and ends only once.
    #[test]
    fn a_built_version_is_tried_on_sample_input() {
        let mut sandbox = made();
        let reaching = VersionDraft {
            network: NetworkAccess::new(vec![AllowedHost::new("api.github.com").unwrap()]).unwrap(),
            ..draft()
        };
        let mut version = sandbox.save_version(&managing(&ann()), reaching).unwrap();
        version.finish_build(bundle(Vec::new())).unwrap();
        let input = FlowData::text("Fix login page").unwrap();

        let mut trial = sandbox
            .try_version(&managing(&ann()), &version, input.clone())
            .unwrap();

        assert_eq!(trial.state(), &TrialState::Running);
        assert_eq!(trial.input(), &input);
        let started = raised(&mut trial);
        assert_eq!(
            started[0].event_type().as_str(),
            "workflows.sandbox_trial_started"
        );
        assert_eq!(started[0].payload().get("hosts"), Some("api.github.com"));
        trial
            .settle(CodeOutcome::Failed(CodeFailure::TimedOut))
            .unwrap();
        assert!(matches!(
            trial.settle(CodeOutcome::Failed(CodeFailure::TimedOut)),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// Trials reject an unfinished build, another sandbox's version, a viewer
    /// and a version whose sandbox has been archived.
    #[test]
    fn only_a_built_version_of_an_active_sandbox_is_tried() {
        let mut sandbox = made();
        let mut other = made();
        let building = sandbox.save_version(&managing(&ann()), draft()).unwrap();
        let mut theirs = other.save_version(&managing(&ann()), draft()).unwrap();
        theirs.finish_build(bundle(Vec::new())).unwrap();
        let mut built = sandbox.save_version(&managing(&ann()), draft()).unwrap();
        built.finish_build(bundle(Vec::new())).unwrap();
        let bob = bob();

        let unbuilt = sandbox.try_version(&managing(&ann()), &building, FlowData::null());
        let foreign = sandbox.try_version(&managing(&ann()), &theirs, FlowData::null());
        let viewer = sandbox.try_version(&viewing(&bob), &built, FlowData::null());
        sandbox.archive(&managing(&ann())).unwrap();
        let archived = sandbox.try_version(&managing(&ann()), &built, FlowData::null());

        assert!(matches!(unbuilt, Err(DomainError::Conflict(_))));
        assert!(matches!(foreign, Err(DomainError::NotFound)));
        assert!(matches!(viewer, Err(DomainError::Forbidden(_))));
        assert!(matches!(archived, Err(DomainError::Conflict(_))));
    }

    /// Saving a Node 22 version in a Python sandbox fails without advancing
    /// its version count.
    #[test]
    fn a_runtime_of_another_language_is_refused() {
        let mut sandbox = made();
        let node = CodeProgram::new(CodeParams {
            runtime: Runtime::Node22,
            image: RuntimeImage::new(format!("node:22-slim@sha256:{}", "cd".repeat(32))).unwrap(),
            code: SandboxCode::new("export function main(item) { return item; }\n").unwrap(),
            packages: Packages::new(vec![]).unwrap(),
        })
        .unwrap();
        let in_node = VersionDraft {
            program: Program::Code(node),
            ..draft()
        };

        let refused = sandbox.save_version(&managing(&ann()), in_node);

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert_eq!(sandbox.latest_version(), 0);
    }

    /// Viewing rights cannot create a sandbox or save a version, and update
    /// rights alone cannot archive one.
    #[test]
    fn viewing_alone_changes_no_sandbox() {
        let mut sandbox = made();
        let bob = bob();
        let params = CreateSandboxParams {
            name: Label::new("name", "Mine").unwrap(),
            kind: SandboxKind::Code(Language::JavaScript),
        };

        assert!(matches!(
            Kept::create(params, &viewing(&bob)),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            sandbox.save_version(&viewing(&bob), draft()),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            sandbox.archive(&holding_only(&bob, WorkflowAction::Update)),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// After 50 saved versions, another save is refused and the sandbox's
    /// version count remains at the limit.
    #[test]
    fn a_sandbox_keeps_at_most_its_number_of_versions() {
        let mut sandbox = made();
        for _ in 0..MAX_VERSIONS {
            sandbox.save_version(&managing(&ann()), draft()).unwrap();
        }

        let one_more = sandbox.save_version(&managing(&ann()), draft());

        assert!(matches!(one_more, Err(DomainError::Conflict(_))));
        assert_eq!(sandbox.latest_version(), MAX_VERSIONS);
    }

    /// Ann archives her sandbox. Saving another version is refused, and so
    /// is archiving it again.
    #[test]
    fn an_archived_sandbox_takes_no_new_version() {
        let mut sandbox = made();
        sandbox.archive(&managing(&ann())).unwrap();

        assert!(matches!(
            sandbox.save_version(&managing(&ann()), draft()),
            Err(DomainError::Conflict(_))
        ));
        assert!(matches!(
            sandbox.archive(&managing(&ann())),
            Err(DomainError::Conflict(_))
        ));
    }

    /// A version's bundle comes ready once, and a ready one cannot then
    /// fail. Another version's bundle fails, naming the package whose
    /// fingerprint did not match.
    #[test]
    fn a_bundle_is_built_or_fails_once() {
        let mut sandbox = made();
        let mut ready = sandbox.save_version(&managing(&ann()), draft()).unwrap();
        let mut broken = sandbox.save_version(&managing(&ann()), draft()).unwrap();

        ready.finish_build(bundle(Vec::new())).unwrap();
        let again = ready.fail_build(BuildFailure::RegistryUnavailable);
        broken
            .fail_build(BuildFailure::FingerprintMismatch(requests()))
            .unwrap();

        assert!(matches!(ready.build(), Build::Ready(_)));
        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
        assert_eq!(
            broken.build(),
            &Build::Failed(BuildFailure::FingerprintMismatch(requests()))
        );
    }

    /// A bundle reporting a pinned package as unlisted cannot finish the
    /// build, and the same contradiction in a stored version is corrupt.
    #[test]
    fn a_bundle_leaving_out_a_pinned_package_is_refused() {
        let mut sandbox = made();
        let mut version = sandbox.save_version(&managing(&ann()), draft()).unwrap();

        let refused = version.finish_build(bundle(vec![requests()]));
        let stored = SandboxVersion::<ResolvedTenant>::reconstitute(SandboxVersionRow {
            id: *version.id(),
            sandbox_id: *sandbox.id(),
            number: 1,
            recipe: version.recipe().clone(),
            source: CodeSource::Written,
            build: Build::Ready(bundle(vec![requests()])),
            holds: VersionHolds::Code,
            saved_by: ann(),
            created_at: Aggregate::created_at(&version),
            updated_at: Aggregate::updated_at(&version),
        });

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert!(refused_as_corrupt(&stored));
    }

    fn web_file() -> RepositoryFile {
        RepositoryFile {
            integration: IntegrationKey::new("github").unwrap(),
            repository: RepositoryName::new("acme/web").unwrap(),
            path: RepositoryPath::new("scripts/tidy.py").unwrap(),
            commit: CommitSha::new("a".repeat(40)).unwrap(),
        }
    }

    /// Ann imports her code from acme/web. The version keeps the file and
    /// the exact commit it was read at, and its record names them.
    #[test]
    fn an_imported_version_keeps_the_commit_it_was_read_at() {
        let mut sandbox = made();
        let imported = VersionDraft {
            source: CodeSource::Imported(web_file()),
            ..draft()
        };

        let mut version = sandbox.save_version(&managing(&ann()), imported).unwrap();

        assert_eq!(version.source(), &CodeSource::Imported(web_file()));
        let saved = raised(&mut version);
        assert_eq!(
            saved[0].payload().get("imported_from"),
            Some(format!("github acme/web/scripts/tidy.py at {}", "a".repeat(40)).as_str())
        );
    }

    /// A viewer cannot record a version push. An authorized push raises the
    /// pushed event with its target branch.
    #[test]
    fn a_pushed_version_records_where_it_went() {
        let mut sandbox = made();
        let mut version = sandbox.save_version(&managing(&ann()), draft()).unwrap();
        let _ = raised(&mut version);
        let target = PushTarget {
            integration: IntegrationKey::new("github").unwrap(),
            repository: RepositoryName::new("acme/web").unwrap(),
            branch: GitRef::new("main").unwrap(),
            folder: RepositoryPath::new("sandboxes/tidy").unwrap(),
        };
        let commit = CommitSha::new("b".repeat(40)).unwrap();

        let by_viewer = version.record_push(&viewing(&bob()), target.clone(), commit.clone());
        version
            .record_push(&managing(&ann()), target, commit)
            .unwrap();

        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        let pushed = raised(&mut version);
        assert_eq!(
            pushed[0].event_type().to_string(),
            "workflows.sandbox_version_pushed"
        );
        assert_eq!(pushed[0].payload().get("branch"), Some("main"));
    }

    fn image_draft() -> VersionDraft {
        let pinned = PinnedImage::parse(&format!(
            "registry.acme.example/tools/codegen@sha256:{}",
            "ef".repeat(32)
        ))
        .unwrap();
        VersionDraft {
            program: Program::Image(OwnImage::new(pinned, 80 * 1024 * 1024).unwrap()),
            budget: RunBudget::new(60, 512).unwrap(),
            network: NetworkAccess::closed(),
            source: CodeSource::Written,
        }
    }

    fn image_sandbox() -> Kept {
        Sandbox::create(
            CreateSandboxParams {
                name: Label::new("name", "Code generator").unwrap(),
                kind: SandboxKind::OwnImage,
            },
            &managing(&ann()),
        )
        .unwrap()
    }

    /// Ann makes a sandbox for her company's code generator image and saves
    /// a version of it. The version keeps the image by its digest, and the
    /// record of the save names that image.
    #[test]
    fn an_image_sandbox_keeps_the_pinned_image() {
        let mut sandbox = image_sandbox();

        let mut version = sandbox
            .save_version(&managing(&ann()), image_draft())
            .unwrap();

        assert_eq!(version.recipe().program(), &image_draft().program);
        assert_eq!(version.build(), &Build::Building);
        let saved = raised(&mut version);
        assert_eq!(
            saved[0].payload().get("image"),
            Some(image_draft().program.image())
        );
    }

    /// An image cannot be saved in a code sandbox, nor code in an image
    /// sandbox, nor an image said to be imported from a repository's file.
    #[test]
    fn a_program_of_another_kind_is_refused() {
        let mut code = made();
        let mut image = image_sandbox();
        let imported = VersionDraft {
            source: CodeSource::Imported(web_file()),
            ..image_draft()
        };

        let image_in_code = code.save_version(&managing(&ann()), image_draft());
        let code_in_image = image.save_version(&managing(&ann()), draft());
        let imported_image = image.save_version(&managing(&ann()), imported);

        assert!(matches!(image_in_code, Err(DomainError::Validation(_))));
        assert!(matches!(code_in_image, Err(DomainError::Validation(_))));
        assert!(matches!(imported_image, Err(DomainError::Validation(_))));
        assert_eq!(image.latest_version(), 0);
    }

    /// Ann's image is scanned and found two high findings and nothing
    /// critical. It is cleared to run, the high findings kept beside it.
    /// Bob's image has one critical finding and is refused, the record
    /// naming it.
    #[test]
    fn a_critical_finding_refuses_an_image() {
        let mut sandbox = image_sandbox();
        let mut cleared = sandbox
            .save_version(&managing(&ann()), image_draft())
            .unwrap();
        let mut refused = sandbox
            .save_version(&managing(&ann()), image_draft())
            .unwrap();
        let _ = raised(&mut refused);
        let high = LesserFindings {
            high: 2,
            ..LesserFindings::default()
        };
        let xz = VulnerabilityId::new("CVE-2024-3094").unwrap();

        cleared
            .finish_scan(&ImageFindings::new(Vec::new(), high))
            .unwrap();
        refused
            .finish_scan(&ImageFindings::new(vec![xz.clone()], high))
            .unwrap();

        assert_eq!(cleared.build(), &Build::Cleared(high));
        assert!(cleared.build().is_ready());
        assert_eq!(
            refused.build(),
            &Build::Failed(BuildFailure::CriticalVulnerabilities(vec![xz]))
        );
        let failed = raised(&mut refused);
        assert_eq!(failed[0].payload().get("detail"), Some("CVE-2024-3094"));
    }

    /// A code version is bundled, never scanned, and an image version
    /// scanned, never bundled.
    #[test]
    fn code_is_bundled_and_an_image_scanned() {
        let mut code = made().save_version(&managing(&ann()), draft()).unwrap();
        let mut image = image_sandbox()
            .save_version(&managing(&ann()), image_draft())
            .unwrap();

        let scanned_code =
            code.finish_scan(&ImageFindings::new(Vec::new(), LesserFindings::default()));
        let bundled_image = image.finish_build(bundle(Vec::new()));

        assert!(matches!(scanned_code, Err(DomainError::Validation(_))));
        assert!(matches!(bundled_image, Err(DomainError::Validation(_))));
        assert_eq!(image.build(), &Build::Building);
    }
}
