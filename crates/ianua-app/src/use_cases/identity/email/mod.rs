//! Confirming addresses and moving users onto new ones.

/// A tenant user moving their account to a new address.
pub(crate) mod changes;
/// An organization member moving their account to a new address.
pub(crate) mod org_changes;
/// Proving an account's address.
pub(crate) mod verification;

pub use changes::{
    CancelChangePorts, CancelChangeUseCase, ChangePorts, ChangeRequest, ChangeStatusPorts,
    ChangeStatusUseCase, ChangeUseCase, ConfirmChangePorts, ConfirmChangeUseCase,
    EmailChangePolicy, RequestChangePorts, RequestChangeRequest, RequestChangeUseCase,
    ResendChangePorts, ResendChangeRequest, ResendChangeUseCase,
};
pub use org_changes::{
    CancelOrgChangePorts, CancelOrgChangeUseCase, ConfirmOrgChangePorts, ConfirmOrgChangeUseCase,
    OrgChangePorts, OrgChangeStatusUseCase, RequestOrgChangePorts, RequestOrgChangeUseCase,
    ResendOrgChangePorts, ResendOrgChangeUseCase,
};
pub(crate) use verification::LinkMailed;
pub use verification::{
    ResendVerificationPorts, ResendVerificationRequest, ResendVerificationUseCase,
    SendVerificationPorts, SendVerificationRequest, SendVerificationUseCase,
    VerificationLinkStores, VerificationLinks, VerificationPolicy, VerificationStatusPorts,
    VerificationStatusUseCase, VerifyPorts, VerifyUseCase,
};
