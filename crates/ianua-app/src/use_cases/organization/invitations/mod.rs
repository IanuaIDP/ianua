//! Bringing people into the organization: invitations, welcome mail and address verification.

/// Inviting a member and the invitation's life: accepted, declined, renewed, revoked.
pub(crate) mod offers;
/// Proving a new owner's address before the organization opens.
pub(crate) mod verification;
/// The welcome a new member is sent.
pub(crate) mod welcome;

pub use offers::{
    AcceptOrgPorts, AcceptOrgRequest, AcceptOrgUseCase, DeclineOrgPorts, DeclineOrgUseCase,
    FollowedInvitation, InviteOrgUserPorts, InviteOrgUserRequest, InviteOrgUserUseCase,
    LapseOrgPorts, LapseOrgUseCase, OrgInvited, OrgStatusPorts, OrgStatusUseCase, RenewOrgPorts,
    RenewOrgRequest, RenewOrgUseCase, ResendOrgPorts, ResendOrgRequest, ResendOrgUseCase,
    RevokeOrgPorts, RevokeOrgRequest, RevokeOrgUseCase,
};
pub use verification::{
    ConfirmInstallerPorts, ConfirmInstallerUseCase, ConfirmOrgVerificationPorts,
    ConfirmOrgVerificationUseCase, OrgVerificationMail, OrgVerificationStatusPorts,
    OrgVerificationStatusUseCase, ResendOrgVerificationByEmailUseCase,
    ResendOrgVerificationFromLinkUseCase, ResendOrgVerificationRequest,
    ResendOrgVerificationUseCase,
};
pub use welcome::{
    OrgWelcomePorts, SendOrgActivationWelcomeUseCase, SendOrgWelcomePorts, SendOrgWelcomeRequest,
    SendOrgWelcomeUseCase,
};
