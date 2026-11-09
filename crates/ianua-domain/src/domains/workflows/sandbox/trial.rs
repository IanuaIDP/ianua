//! A trial of a sandbox version: a person hands a built version sample
//! input, a worker runs it as a code step would, and they read back what
//! it gave or why it failed.
//!
//! A trial changes nothing in any workflow, and nothing else reads it. It
//! is kept only for a while after it ended, for the person to read.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::events::{SandboxTrialStarted, SandboxVersionRef};
use crate::domains::workflows::execution::step::CodeOutcome;
use crate::domains::workflows::sandbox::network::NetworkAccess;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::{Human, SandboxId, SandboxTrialId, SandboxVersionId};

/// How long an ended trial is kept for its person to read, in hours.
pub const TRIAL_KEPT_HOURS: i64 = 24;

/// How far a trial got.
#[derive(Debug, Clone, PartialEq)]
pub enum TrialState {
    /// A worker runs it, or will.
    Running,
    /// It ran, and this is how it went.
    Ended(CodeOutcome),
}

/// A trial as stored.
pub struct SandboxTrialRow {
    /// The persisted identity correlating sample-input work with its outcome.
    pub id: SandboxTrialId,
    /// The sandbox whose version it tries.
    pub sandbox_id: SandboxId,
    /// The version it tries.
    pub version_id: SandboxVersionId,
    /// What the code is given.
    pub input: FlowData,
    /// How far it got.
    pub state: TrialState,
    /// The person who started it.
    pub started_by: Human,
    /// When it was started.
    pub created_at: OffsetDateTime,
    /// When it last changed: when it ended, once it has.
    pub updated_at: OffsetDateTime,
}

/// One trial of a sandbox version on sample input.
#[derive(Debug, Clone)]
pub struct SandboxTrial<T: TenantScope> {
    id: SandboxTrialId,
    sandbox_id: SandboxId,
    version_id: SandboxVersionId,
    input: FlowData,
    state: TrialState,
    started_by: Human,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// What a sandbox hands a trial it starts.
pub(super) struct Starting {
    pub(super) version: SandboxVersionRef,
    pub(super) network: NetworkAccess,
    pub(super) input: FlowData,
    pub(super) by: Human,
}

impl<T: TenantScope> SandboxTrial<T> {
    /// A trial just started, waiting for a worker. Raises
    /// `workflows.sandbox_trial_started`.
    pub(super) fn started(starting: Starting) -> Self {
        let now = crate::shared::clock::now();
        let mut trial = Self {
            id: SandboxTrialId::new(),
            sandbox_id: starting.version.sandbox_id,
            version_id: starting.version.version_id,
            input: starting.input,
            state: TrialState::Running,
            started_by: starting.by,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        trial.raised.raise(SandboxTrialStarted {
            version: starting.version,
            trial_id: trial.id,
            network: starting.network,
            occurred_at: now,
        });
        trial
    }

    /// Rebuilds a trial from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it changed before it was
    ///   started.
    pub fn reconstitute(row: SandboxTrialRow) -> Result<Self, DomainError> {
        RowCheck::of("sandbox trial")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was started",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            sandbox_id: row.sandbox_id,
            version_id: row.version_id,
            input: row.input,
            state: row.state,
            started_by: row.started_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// It ran, and went as `outcome` says.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it ended already.
    pub fn settle(&mut self, outcome: CodeOutcome) -> Result<(), DomainError> {
        if self.state != TrialState::Running {
            return Err(DomainError::invalid_transition(message!(
                "workflows-the-trial-ended-already",
                "the trial ended already"
            )));
        }
        self.state = TrialState::Ended(outcome);
        self.updated_at = crate::shared::clock::now();
        Ok(())
    }

    /// The stable identity correlating sample-input work with its outcome.
    #[must_use]
    pub fn id(&self) -> &SandboxTrialId {
        &self.id
    }

    /// The sandbox whose version it tries.
    #[must_use]
    pub fn sandbox_id(&self) -> &SandboxId {
        &self.sandbox_id
    }

    /// The version it tries.
    #[must_use]
    pub fn version_id(&self) -> &SandboxVersionId {
        &self.version_id
    }

    /// What the code is given.
    #[must_use]
    pub fn input(&self) -> &FlowData {
        &self.input
    }

    /// How far it got.
    #[must_use]
    pub fn state(&self) -> &TrialState {
        &self.state
    }

    /// The person who started it.
    #[must_use]
    pub fn started_by(&self) -> &Human {
        &self.started_by
    }
}

impl<T: TenantScope> Raises for SandboxTrial<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for SandboxTrial<T> {
    type Id = SandboxTrialId;

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
