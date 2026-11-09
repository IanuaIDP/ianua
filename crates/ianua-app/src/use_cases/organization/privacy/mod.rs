//! Members' consent records and their requests to be erased, by the same
//! rules a tenant's people have.

pub(crate) mod cancel_org_erasure;
pub(crate) mod cancel_org_erasure_by_link;
pub(crate) mod grant_org_consent;
pub(crate) mod hold_org_erasure;
mod legal_hold;
pub(crate) mod list_org_consents;
mod lookup;
pub(crate) mod process_org_erasures;
pub(crate) mod release_org_erasure;
pub(crate) mod request_org_erasure;
pub(crate) mod revoke_org_consent;
pub mod whose;

pub use cancel_org_erasure::{CancelOrgErasurePorts, CancelOrgErasureUseCase};
pub use cancel_org_erasure_by_link::{CancelOrgErasureByLinkPorts, CancelOrgErasureByLinkUseCase};
pub use grant_org_consent::{GrantOrgConsentPorts, GrantOrgConsentUseCase};
pub use hold_org_erasure::{HoldOrgErasurePorts, HoldOrgErasureUseCase};
pub use list_org_consents::{ListOrgConsentsPorts, ListOrgConsentsUseCase};
pub use process_org_erasures::{
    OrgErasureReport, ProcessOrgErasuresPorts, ProcessOrgErasuresUseCase,
};
pub use release_org_erasure::{ReleaseOrgErasurePorts, ReleaseOrgErasureUseCase};
pub use request_org_erasure::{
    OrgErasurePolicy, RequestOrgErasurePorts, RequestOrgErasureRequest, RequestOrgErasureUseCase,
};
pub use revoke_org_consent::{
    RevokeOrgConsentPorts, RevokeOrgConsentRequest, RevokeOrgConsentUseCase,
};
