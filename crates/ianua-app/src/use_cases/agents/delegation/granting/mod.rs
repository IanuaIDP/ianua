//! A person giving an agent part of what they hold, and taking it back.

pub(crate) mod attenuate;
pub(in crate::use_cases::agents) mod authority;
pub(crate) mod grant;
pub(super) mod grant_shape;
pub(crate) mod lineage;
pub(crate) mod renew;
pub(crate) mod revoke;

pub use attenuate::{
    AttenuatePorts, AttenuateRequest, AttenuateUseCase, Attenuating, AttenuationRecordPorts,
};
pub use grant::{
    FollowUpPorts, GrantDelegationRequest, GrantPorts, GrantRecordPorts, GrantUseCase,
    GrantedDelegation, IntentGrant, TaskTokenPorts,
};
pub use lineage::LineagePorts;
pub use renew::{RenewPorts, RenewRequest, RenewUseCase};
pub use revoke::{RevokePorts, RevokeRequest, RevokeUseCase};
