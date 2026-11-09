//! Mapping a provider's groups to the tenant's roles and groups.

pub(crate) mod map_provider;
pub(crate) mod stop_mapping;

pub use map_provider::{
    GroupRuleRequest, MapProviderGroupsPorts, MapProviderGroupsRequest, MapProviderGroupsUseCase,
};
pub use stop_mapping::{StopMappingGroupsPorts, StopMappingGroupsUseCase};
