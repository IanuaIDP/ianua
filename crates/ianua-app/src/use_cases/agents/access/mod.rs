//! Deciding whether an agent may make a call: dry runs a person asks for
//! about an agent they may watch.

pub(crate) mod authorize;
pub(crate) mod authorize_resource;
mod token;
mod verdict;

pub use authorize::{
    AgentAuthorizeOutcome, AuthorizeAgentPorts, AuthorizeAgentRequest, AuthorizeAgentUseCase,
    AuthorizeCheckTarget,
};
pub use authorize_resource::{
    AuthorizeResourcePorts, AuthorizeResourceRequest, AuthorizeResourceUseCase,
};
