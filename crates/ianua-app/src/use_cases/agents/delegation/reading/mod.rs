//! Delegations as people read them, and what they reach.

pub(crate) mod describe_delegations;
pub(crate) mod get_blast_radius;
pub(crate) mod get_effective_capabilities;
pub(crate) mod list_delegations;
pub(crate) mod list_granted_delegations;
pub(in crate::use_cases::agents) mod viewing;

pub use describe_delegations::{
    DescribeDelegations, DescribeDelegationsPorts, DescribedDelegation,
};
pub use get_blast_radius::{GetBlastRadiusPorts, GetBlastRadiusUseCase};
pub use get_effective_capabilities::{
    AgentEffectiveCapabilities, GetEffectiveCapabilitiesPorts, GetEffectiveCapabilitiesUseCase,
};
pub use list_delegations::{ListDelegationsPorts, ListDelegationsUseCase};
pub use list_granted_delegations::{ListGrantedDelegationsPorts, ListGrantedDelegationsUseCase};
