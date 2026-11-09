//! The integration catalog: what a workflow's builder may use, the
//! integrations as they present themselves and how an account is connected
//! to each, each operation with its guide, each service event a workflow
//! may start on, the options a step form's pickers offer, the apps a
//! Protected apps step may call, the systems a Protected data step may
//! reach, each integration's own picture, and the tenant raising how risky
//! an operation counts as.

pub(crate) mod choices;
pub(crate) mod list_apps;
pub(crate) mod list_data;
pub(crate) mod list_events;
pub(crate) mod list_integrations;
pub(crate) mod list_operations;
pub(crate) mod picture;
pub mod risk_overrides;

pub use choices::{
    Choice, Choices, ListChoicesPorts, ListChoicesRequest, ListChoicesUseCase, MAX_CHOICES,
};
pub use list_apps::{ListAppsPorts, ListAppsUseCase};
pub use list_data::{ListDataPorts, ListDataUseCase};
pub use list_events::{ListEventsPorts, ListEventsUseCase, OfferedEvent};
pub use list_integrations::{
    Connecting, ListIntegrationsPorts, ListIntegrationsUseCase, ListedIntegration,
};
pub use list_operations::{ListOperationsPorts, ListOperationsUseCase, OfferedOperation};
pub use picture::{IntegrationPicturePorts, IntegrationPictureUseCase};
