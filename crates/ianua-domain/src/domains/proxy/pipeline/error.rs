//! Why a change to a pipeline was refused.

use crate::domains::proxy::pipeline_status::InvalidPipelineTransition;
use crate::shared::errors::Refusal;

/// Why a change to a pipeline was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PipelineError {
    /// Someone without the pipeline right tried to make or change one.
    #[error("this needs the right to change pipelines")]
    NotAllowed,
    /// Attempted to remove a mandatory stage.
    #[error("cannot remove a mandatory stage")]
    CannotRemoveMandatory,
    /// Attempted to add an Identity or Policy stage. Every pipeline runs
    /// exactly one of each.
    #[error("a pipeline holds one Identity and one Policy stage, so neither is added")]
    CannotAddMandatory,
    /// Attempted to change the settings of the Identity or Policy stage,
    /// which have none.
    #[error("the Identity and Policy stages have no settings to change")]
    CannotReconfigureMandatory,
    /// New settings were for another kind of stage. A stage keeps its kind.
    #[error("a stage keeps its kind; add a new stage for another kind")]
    OtherKind,
    /// New settings were refused, since the stage could not do its job with
    /// them.
    #[error("the stage's new settings were refused: {0}")]
    SettingsRefused(Refusal),
    /// Stage not found in the pipeline.
    #[error("stage not found in the pipeline")]
    StageNotFound,
    /// A reorder did not list every stage exactly once.
    #[error("a reorder must list every stage exactly once")]
    IncompleteOrder,
    /// The pipeline is active and must be disabled before it is changed.
    #[error("an active pipeline must be disabled before it is changed")]
    ActivePipelineImmutable,
    /// The pipeline would share cached responses between the callers of a
    /// route that needs sign-in.
    #[error("a cache shared between callers cannot run on a route that needs sign-in")]
    SharedCacheOnSignedInRoute,
    /// A route given as one of this pipeline's runs on another pipeline.
    #[error("a route given for this pipeline runs on another one")]
    ForeignRoute,
    /// Routes still run the pipeline, so it cannot be deleted.
    #[error("routes still run this pipeline, so it cannot be deleted")]
    InUse,
    /// Invalid status transition.
    #[error(transparent)]
    InvalidTransition(#[from] InvalidPipelineTransition),
}
