//! Drafting, editing, publishing and archiving workflow versions, reading
//! them, and reading what each of their steps may read.

pub(crate) mod archive;
pub(crate) mod create;
pub(crate) mod drafting;
pub(crate) mod edit_draft;
pub(crate) mod get;
pub(crate) mod list;
pub(crate) mod next_draft;
pub(crate) mod publish;
pub(crate) mod step_data;

pub use archive::{ArchiveWorkflowPorts, ArchiveWorkflowRequest, ArchiveWorkflowUseCase};
pub use create::{CreateWorkflowPorts, CreateWorkflowRequest, CreateWorkflowUseCase};
pub use drafting::{
    DraftPlace, DraftPorts, DraftRequest, DraftUseCase, Proposal, ProposedEdge, ProposedKind,
    ProposedStep, ProposedTrigger, ProposedValue,
};
pub use edit_draft::{DraftEdit, EditDraftPorts, EditDraftRequest, EditDraftUseCase};
pub use get::{GetWorkflowPorts, GetWorkflowRequest, GetWorkflowUseCase, WhichVersion};
pub use list::{ListWorkflowsPorts, ListWorkflowsRequest, ListWorkflowsUseCase};
pub use next_draft::{NextDraftPorts, NextDraftUseCase};
pub use publish::{PublishWorkflowPorts, PublishWorkflowRequest, PublishWorkflowUseCase};
pub use step_data::{
    DataSource, EarlierData, ReadableValue, StepData, StepDataPorts, StepDataRequest,
    StepDataUseCase, ValueShape,
};
