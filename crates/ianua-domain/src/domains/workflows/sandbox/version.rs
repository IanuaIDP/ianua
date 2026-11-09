//! One saved version of a sandbox: its recipe, which never changes, and how
//! far building its package bundle got.
//!
//! A workflow step names a version, never the sandbox, so what runs is what
//! was reviewed. Changing anything makes the next version.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::events::{
    SandboxVersionBuilt, SandboxVersionFailed, SandboxVersionPushed, SandboxVersionRef,
    SandboxVersionSaved, SavedProgram,
};
use crate::domains::workflows::sandbox::agent::{HeldAgent, VersionHolds};
use crate::domains::workflows::sandbox::build::{Build, BuildFailure, Bundle};
use crate::domains::workflows::sandbox::image::ImageFindings;
use crate::domains::workflows::sandbox::recipe::{Program, Recipe};
use crate::domains::workflows::sandbox::source::{CodeSource, CommitSha, PushTarget};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::{Human, SandboxId, SandboxVersionId};

/// A version as stored.
pub struct SandboxVersionRow {
    /// The persisted artifact identity referenced by workflow code steps.
    pub id: SandboxVersionId,
    /// The sandbox it is a version of.
    pub sandbox_id: SandboxId,
    /// The positive sequence ordering immutable artifacts within the code project.
    pub number: u32,
    /// What it is made of.
    pub recipe: Recipe,
    /// Where its code came from.
    pub source: CodeSource,
    /// How far building its bundle got.
    pub build: Build,
    /// Whether its program is the step's work, or checks an agent's.
    pub holds: VersionHolds,
    /// The person who saved it.
    pub saved_by: Human,
    /// When it was saved.
    pub created_at: OffsetDateTime,
    /// When its build last changed.
    pub updated_at: OffsetDateTime,
}

/// One saved version of a sandbox.
#[derive(Debug, Clone)]
pub struct SandboxVersion<T: TenantScope> {
    id: SandboxVersionId,
    sandbox_id: SandboxId,
    number: u32,
    recipe: Recipe,
    source: CodeSource,
    build: Build,
    holds: VersionHolds,
    saved_by: Human,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// What a sandbox hands a version it saves.
pub(super) struct Saving {
    pub(super) sandbox_id: SandboxId,
    pub(super) number: u32,
    pub(super) recipe: Recipe,
    pub(super) source: CodeSource,
    pub(super) holds: VersionHolds,
    pub(super) by: Human,
}

impl<T: TenantScope> SandboxVersion<T> {
    /// A version just saved, its bundle still to build. Raises
    /// `workflows.sandbox_version_saved`.
    pub(super) fn saved(saving: Saving) -> Self {
        let now = crate::shared::clock::now();
        let mut version = Self {
            id: SandboxVersionId::new(),
            sandbox_id: saving.sandbox_id,
            number: saving.number,
            recipe: saving.recipe,
            source: saving.source,
            build: Build::Building,
            holds: saving.holds,
            saved_by: saving.by,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        version.raised.raise(SandboxVersionSaved {
            version: version.version_ref(),
            program: SavedProgram::of(version.recipe.program()),
            network: version.recipe.network().clone(),
            source: version.source.clone(),
            agent: version.held_agent().map(|held| *held.run().agent_id()),
            occurred_at: now,
        });
        version
    }

    /// Rebuilds a version from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when its number is below one.
    /// - [`DomainError::Infrastructure`] when it changed before it was
    ///   saved.
    /// - [`DomainError::Infrastructure`] when its bundle names as unlisted
    ///   a package the version pins.
    /// - [`DomainError::Infrastructure`] when a code version claims a
    ///   cleared image, an image version a bundle, or an image version an
    ///   imported source.
    pub fn reconstitute(row: SandboxVersionRow) -> Result<Self, DomainError> {
        RowCheck::of("sandbox version")
            .holds(row.number >= 1, "a number below one")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was saved",
            )
            .holds(
                build_fits(&row),
                "a build that does not fit what the version runs",
            )
            .holds(
                image_kept_whole(&row),
                "an image version with a bundle or an imported source",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            sandbox_id: row.sandbox_id,
            number: row.number,
            recipe: row.recipe,
            source: row.source,
            build: row.build,
            holds: row.holds,
            saved_by: row.saved_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Its bundle was built and stored. Raises
    /// `workflows.sandbox_version_built`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not being built.
    /// - [`DomainError::Validation`] when the version runs a company's
    ///   image, which has no bundle, or the bundle names as unlisted a
    ///   package the version pins.
    pub fn finish_build(&mut self, bundle: Bundle) -> Result<(), DomainError> {
        self.ensure_building()?;
        let Some(packages) = self.recipe.program().packages() else {
            return Err(DomainError::invalid(message!(
                "workflows-an-image-version-has-no-bundle",
                "a version of a company's image has no bundle to build"
            )));
        };
        if !bundle.fits(packages) {
            return Err(DomainError::invalid(message!(
                "workflows-the-bundle-leaves-out-a-pinned-package",
                "the bundle leaves out a package the version pins"
            )));
        }
        let bytes = bundle.bytes();
        self.build = Build::Ready(bundle);
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(SandboxVersionBuilt {
            version: self.version_ref(),
            bytes,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Its company's image was scanned and found `findings`. With nothing
    /// critical it is cleared to run, raising
    /// `workflows.sandbox_version_built` with the image's size; one
    /// critical finding refuses it, raising `workflows.sandbox_version_failed`
    /// naming what was found.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not being built.
    /// - [`DomainError::Validation`] when the version runs code, which is
    ///   bundled, not scanned.
    pub fn finish_scan(&mut self, findings: &ImageFindings) -> Result<(), DomainError> {
        self.ensure_building()?;
        let Program::Image(own) = self.recipe.program() else {
            return Err(DomainError::invalid(message!(
                "workflows-only-an-image-version-is-scanned",
                "only a version of a company's image is scanned"
            )));
        };
        if !findings.critical().is_empty() {
            return self.fail_build(BuildFailure::CriticalVulnerabilities(
                findings.critical().to_vec(),
            ));
        }
        let bytes = own.bytes();
        self.build = Build::Cleared(findings.lesser());
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(SandboxVersionBuilt {
            version: self.version_ref(),
            bytes,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Its bundle could not be built, for `failure`. Raises
    /// `workflows.sandbox_version_failed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not being built.
    pub fn fail_build(&mut self, failure: BuildFailure) -> Result<(), DomainError> {
        self.ensure_building()?;
        self.build = Build::Failed(failure.clone());
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(SandboxVersionFailed {
            version: self.version_ref(),
            failure,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// `by` pushed a copy of this version to `target`, where it became
    /// `commit`. The version saved here stays the one that runs. Raises
    /// `workflows.sandbox_version_pushed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change workflows.
    pub fn record_push(
        &mut self,
        by: &WorkflowControl<'_>,
        target: PushTarget,
        commit: CommitSha,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.raised.raise(SandboxVersionPushed {
            version: self.version_ref(),
            target,
            commit,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    fn ensure_building(&self) -> Result<(), DomainError> {
        if self.build != Build::Building {
            return Err(DomainError::invalid_transition(message!(
                "workflows-the-version-was-built-already",
                "the version's bundle was built or failed already"
            )));
        }
        Ok(())
    }

    pub(super) fn version_ref(&self) -> SandboxVersionRef {
        SandboxVersionRef {
            sandbox_id: self.sandbox_id,
            version_id: self.id,
            number: self.number,
        }
    }

    /// The stable artifact identity referenced by workflow code steps.
    #[must_use]
    pub fn id(&self) -> &SandboxVersionId {
        &self.id
    }

    /// The sandbox it is a version of.
    #[must_use]
    pub fn sandbox_id(&self) -> &SandboxId {
        &self.sandbox_id
    }

    /// The positive sequence ordering immutable artifacts within the code project.
    #[must_use]
    pub fn number(&self) -> u32 {
        self.number
    }

    /// What it is made of.
    #[must_use]
    pub fn recipe(&self) -> &Recipe {
        &self.recipe
    }

    /// Where its code came from.
    #[must_use]
    pub fn source(&self) -> &CodeSource {
        &self.source
    }

    /// How far building its bundle got.
    #[must_use]
    pub fn build(&self) -> &Build {
        &self.build
    }

    /// The person who saved it.
    #[must_use]
    pub fn saved_by(&self) -> &Human {
        &self.saved_by
    }

    /// Whether its program is the step's work, or checks an agent's.
    #[must_use]
    pub fn holds(&self) -> &VersionHolds {
        &self.holds
    }

    /// The agent it holds and the rules it works under; `None` when its
    /// program is the step's work.
    #[must_use]
    pub fn held_agent(&self) -> Option<&HeldAgent> {
        match &self.holds {
            VersionHolds::Code => None,
            VersionHolds::Agent(held) => Some(held.as_ref()),
        }
    }
}

/// Whether `row`'s build fits what it runs: a bundle leaving out no pinned
/// package for code, a cleared scan only for an image.
fn build_fits(row: &SandboxVersionRow) -> bool {
    match (&row.build, row.recipe.program().packages()) {
        (Build::Ready(bundle), Some(packages)) => bundle.fits(packages),
        (Build::Cleared(_), Some(_)) => false,
        (Build::Ready(_) | Build::Cleared(_), None) | (Build::Building | Build::Failed(_), _) => {
            true
        }
    }
}

/// Whether an image version in `row` holds no bundle and no imported
/// source; a code version always does.
fn image_kept_whole(row: &SandboxVersionRow) -> bool {
    match row.recipe.program() {
        Program::Image(_) => {
            !matches!(row.build, Build::Ready(_)) && row.source == CodeSource::Written
        }
        Program::Code(_) => true,
    }
}

impl<T: TenantScope> Raises for SandboxVersion<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for SandboxVersion<T> {
    type Id = SandboxVersionId;

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
