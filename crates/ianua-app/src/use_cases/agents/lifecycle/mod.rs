//! Creating, changing, suspending and retiring agents, and handing them to
//! other people.

pub(crate) mod bootstrap;
/// Stopping an agent from acting, and letting it act again.
pub(crate) mod containment;
pub(crate) mod create;
pub(crate) mod delete;
pub(crate) mod get;
pub(crate) mod list;
/// An agent offered to, and taken over by, a new owner.
pub(crate) mod ownership;
pub(crate) mod update;

pub use bootstrap::{BootstrapAgentPorts, BootstrapAgentRequest, BootstrapAgentUseCase};
pub use containment::{
    ContainAgentPorts, ContainAgentUseCase, ResumeAgentPorts, ResumeAgentUseCase, RevokeAgentPorts,
    RevokeAgentUseCase, SuspendAgentPorts, SuspendAgentUseCase, SuspendAllAgentsPorts,
    SuspendAllAgentsUseCase,
};
pub use create::{CreateAgentPorts, CreateAgentRequest, CreateAgentUseCase, CreatedAgent};
pub use delete::{DeleteAgentPorts, DeleteAgentUseCase};
pub use get::{GetAgentPorts, GetAgentUseCase};
pub use list::{ListAgentsPorts, ListAgentsRequest, ListAgentsUseCase};
pub use ownership::{
    AcceptAgentPorts, AcceptAgentUseCase, ListAgentOffersPorts, ListAgentOffersUseCase,
    OfferAgentPorts, OfferAgentRequest, OfferAgentUseCase, TakeOverAgentPorts,
    TakeOverAgentUseCase, WithdrawAgentOfferPorts, WithdrawAgentOfferUseCase,
};
pub use update::{UpdateAgentPorts, UpdateAgentRequest, UpdateAgentUseCase};
