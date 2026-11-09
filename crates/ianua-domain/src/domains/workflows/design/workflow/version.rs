//! Where a version of a workflow stands, who published it, and how long its
//! executions may run.

use time::{Duration, OffsetDateTime};

use crate::domains::workflows::design::workflow::Workflow;
use crate::domains::workflows::integration::events::ServiceEventSpec;
use crate::domains::workflows::integration::risk_override::TenantOperation;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::{EventVisibility, Human, Lifetime, SandboxVersionId, WorkflowId};

/// Where one version of a workflow stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowStatus {
    /// Being designed. Nothing starts it yet.
    Draft,
    /// What its trigger starts.
    Published,
    /// Out of service for good. Kept for the executions that ran it.
    Archived,
}

impl WorkflowStatus {
    /// Moves to `to` if a version in this status may.
    ///
    /// A draft is published or archived. A published version is archived.
    /// An archived one stays as it is.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!(
                (from, to),
                (Self::Draft, Self::Published | Self::Archived) | (Self::Published, Self::Archived)
            )
        })
    }

    /// The stored name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Archived => "archived",
        }
    }

    /// Reads a stored name.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] on a name no status has.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "draft" => Ok(Self::Draft),
            "published" => Ok(Self::Published),
            "archived" => Ok(Self::Archived),
            _ => Err(DomainError::corrupt_row("workflow", "an unknown status")),
        }
    }
}

/// Whether a version was ever published, and by whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publication {
    /// It was never published.
    Unpublished,
    /// This person published it.
    PublishedBy(Human),
}

/// The longest any execution may run.
pub(crate) const MAX_RUN_TIME: Duration = Duration::days(31);

/// One revision of a draft, as a person saw it. Any edit makes a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revision(OffsetDateTime);

impl Revision {
    /// The revision a version reached when it last changed, at `at`.
    ///
    /// A publisher's client hands back the time it was shown, as
    /// [`changed_at`](Self::changed_at) gave it. Nothing is gained by making
    /// one up: a revision that is not the draft's own is refused at publish.
    /// It is held to the microsecond, the most the store keeps, so a save and
    /// the read after it name the same revision.
    #[must_use]
    pub fn reviewed(at: OffsetDateTime) -> Self {
        let below_a_microsecond = i64::from(at.nanosecond() % 1_000);
        Self(
            at.checked_sub(Duration::nanoseconds(below_a_microsecond))
                .unwrap_or(at),
        )
    }

    /// When the version reached this revision, for a client to show and
    /// hand back.
    #[must_use]
    pub fn changed_at(self) -> OffsetDateTime {
        self.0
    }
}

/// How long one execution of a workflow may run before it is stopped.
///
/// So no execution runs, waits or holds resources without end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimit(Lifetime);

impl RunLimit {
    /// A limit of `lifetime`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is longer than
    ///   `MAX_RUN_TIME`.
    pub fn new(lifetime: Lifetime) -> Result<Self, DomainError> {
        if lifetime.duration() > MAX_RUN_TIME {
            return Err(DomainError::invalid(message!(
                "workflows-an-execution-may-run-at-most",
                format!(
                    "an execution may run at most {} days",
                    MAX_RUN_TIME.whole_days()
                )
            )));
        }
        Ok(Self(lifetime))
    }

    /// The limit.
    #[must_use]
    pub fn lifetime(self) -> Lifetime {
        self.0
    }
}

/// The version a newly published one takes over from.
#[derive(Debug)]
pub enum Replaces<'a, T: TenantScope> {
    /// No version of the workflow is published now.
    Nothing,
    /// This version is published now, and is archived when the new one is.
    Version(&'a mut Workflow<T>),
}

impl<T: TenantScope> Replaces<'_, T> {
    /// Refuses a version that is not an earlier published version of the
    /// workflow `id`, below `version`.
    pub(super) fn ensure_earlier_than(
        &self,
        id: WorkflowId,
        version: u32,
    ) -> Result<(), DomainError> {
        let Self::Version(current) = self else {
            return Ok(());
        };
        let earlier_and_live = *current.id() == id
            && current.version() < version
            && current.status() == WorkflowStatus::Published;
        if earlier_and_live {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "workflows-a-version-takes-over-only-from",
            "a version takes over only from an earlier published version of its workflow"
        )))
    }

    /// Takes the replaced version out of service.
    pub(super) fn retire(self) -> Result<(), DomainError> {
        let Self::Version(current) = self else {
            return Ok(());
        };
        current.retire_for_successor()
    }
}

/// What a publisher's checks read: the operations and service events the
/// tenant is offered now, and what the publisher may see.
pub struct PublishFacts<'a, V: EventVisibility> {
    /// The operations the graph uses, as the tenant treats them now.
    pub offered: &'a [TenantOperation],
    /// The service events the trigger may start on, as the integrations
    /// offer them now.
    pub events: &'a [ServiceEventSpec],
    /// What the publisher may see now.
    pub sees: &'a V,
    /// The sandbox versions the graph's code steps name that may run now:
    /// kept for the tenant, of a sandbox not archived, with a bundle ready;
    /// each with whether its code reaches the network.
    pub runnable: &'a [RunnableCode],
}

/// A sandbox version that may run now, and whether its code reaches the
/// network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnableCode {
    /// The built code artifact eligible for selection by a published step.
    pub version: SandboxVersionId,
    /// Whether its code reaches the network.
    pub reach: CodeReach,
}

/// Whether a version's code reaches the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeReach {
    /// No network at all: running it changes nothing outside.
    Closed,
    /// The hosts its version names: running it may change something
    /// outside, so a step running it needs an approval before it.
    Networked,
}

impl<V: EventVisibility> Clone for PublishFacts<'_, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V: EventVisibility> Copy for PublishFacts<'_, V> {}

impl<V: EventVisibility> std::fmt::Debug for PublishFacts<'_, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublishFacts")
            .field("offered", &self.offered)
            .finish_non_exhaustive()
    }
}
