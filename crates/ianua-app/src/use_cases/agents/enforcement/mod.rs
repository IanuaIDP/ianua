//! What the gateway lets an agent do, and what it refuses: the controls it
//! applies only to agents, and the record of each decision.
//!
//! These run in the gateway. What they record goes through the gateway's
//! `EventDispatcher`, its inbox, which takes only the events the data plane
//! raises: `agents.action_authorized`, `agents.action_denied`,
//! `agents.egress_denied` and `agents.token_attack_refused` here, and the
//! proxy's threat records. Nothing here raises any other.

pub(crate) mod admit_action;
pub(crate) mod authority;
pub(crate) mod record_action;
pub(crate) mod record_egress_denial;
pub(crate) mod record_stolen_binding;

pub use admit_action::{
    Admission, AdmitActionPorts, AdmitActionRequest, AdmitActionUseCase, AgentRefusal, AgentRoute,
    CarriedValues, TaskLimits,
};
pub use authority::{
    AgentAuthority, AgentAuthorityPorts, AgentAuthorityRequest, AuthorityLoss,
    CheckAgentAuthorityUseCase,
};
pub use record_action::{ActionOutcome, RecordActionRequest, RecordActionUseCase};
pub(crate) use record_egress_denial::{RecordEgressDenialRequest, RecordEgressDenialUseCase};
pub use record_stolen_binding::{
    RecordStolenBindingPorts, RecordStolenBindingRequest, RecordStolenBindingUseCase,
};
