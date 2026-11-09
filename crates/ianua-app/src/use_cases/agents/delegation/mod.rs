//! Authority people hand to agents, and the resources it covers.

/// A person giving an agent part of what they hold, and taking it back.
pub(crate) mod granting;
/// Delegations as people read them, and what they reach.
pub(crate) mod reading;
/// An agent asking a person for a delegation.
pub(crate) mod requests;
/// Delegations scoped to one resource or relation.
pub(crate) mod resources;

pub use granting::{
    AttenuatePorts, AttenuateRequest, AttenuateUseCase, Attenuating, AttenuationRecordPorts,
    FollowUpPorts, GrantDelegationRequest, GrantPorts, GrantRecordPorts, GrantUseCase,
    GrantedDelegation, IntentGrant, LineagePorts, RenewPorts, RenewRequest, RenewUseCase,
    RevokePorts, RevokeRequest, RevokeUseCase, TaskTokenPorts,
};
pub use reading::{
    AgentEffectiveCapabilities, DescribeDelegations, DescribeDelegationsPorts, DescribedDelegation,
    GetBlastRadiusPorts, GetBlastRadiusUseCase, GetEffectiveCapabilitiesPorts,
    GetEffectiveCapabilitiesUseCase, ListDelegationsPorts, ListDelegationsUseCase,
    ListGrantedDelegationsPorts, ListGrantedDelegationsUseCase,
};
pub use requests::{
    ApproveRequestPorts, ApproveRequestRequest, ApproveRequestUseCase, AskingAgent,
    DenyRequestPorts, DenyRequestRequest, DenyRequestUseCase, ListRequestsPorts,
    ListRequestsUseCase, RequestPorts, RequestRequest, RequestUseCase, RequestsOf,
};
pub use resources::{
    GrantResourcePorts, GrantResourceRelationUseCase, GrantResourceRequest, GrantResourceUseCase,
    ResourceGrantPorts, ResourceGrantRequest, RevokeResourcePorts, RevokeResourceRelationUseCase,
    RevokeResourceRequest, RevokeResourceUseCase,
};
