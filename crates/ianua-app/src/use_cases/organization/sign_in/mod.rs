//! How members sign in and stay signed in: passwords, sessions, devices and tenants.

/// The devices a member trusts.
pub(crate) mod devices;
/// Signing in by a link sent to the member's mailbox.
pub(crate) mod mailed;
/// Signing in a member with their password and second factor.
pub(crate) mod password;
/// A member's open sessions: listed, switched, ended.
pub(crate) mod sessions;
/// Signing in through the organization's identity provider.
pub(crate) mod sso;
/// The steps every way in shares: choosing the organization, landing, opening and finishing the session.
pub(crate) mod steps;

pub use devices::{
    ListOrgDevicesPorts, ListOrgDevicesUseCase, RevokeOrgDevicePorts, RevokeOrgDeviceUseCase,
    TrustOrgDevicePorts, TrustOrgDeviceRequest, TrustOrgDeviceUseCase,
};
pub use mailed::{
    OrgConfirmPorts, OrgConfirmRequest, OrgConfirmUseCase, OrgConfirmationMailPorts, OrgConfirmed,
    OrgMagicLinkPolicy, OrgMagicLinkPorts, OrgMagicLinkRequest, OrgMagicLinkUseCase,
    RequestOrgMagicLinkPorts, RequestOrgMagicLinkUseCase,
};
pub use password::{
    MarkCredentialUsedPorts, MarkCredentialUsedUseCase, OrgCredentialBearer, OrgLoginFactorPorts,
    OrgLoginSettings, OrgLoginSuccess, OrgPasswordCheckPorts, OrgPasswordLoginPorts,
    OrgPasswordLoginRequest, OrgPasswordLoginUseCase, OrgSessionOpeningPorts,
};
pub use sessions::{
    ActiveSessionInfo, LinkedSwitchSuccess, LinkedTenantSwitchPorts, LinkedTenantSwitchUseCase,
    ListActiveSessionsPorts, ListActiveSessionsRequest, ListActiveSessionsUseCase, MovedOrgSession,
    OrgLogoutPorts, OrgLogoutUseCase, RevokeMemberSessionPorts, RevokeMemberSessionRequest,
    RevokeMemberSessionUseCase, SwitchOrgTenantPorts, SwitchOrgTenantUseCase,
};
pub use sso::{
    OrgSsoAnswer, OrgSsoCallbackPorts, OrgSsoCallbackRequest, OrgSsoCallbackUseCase,
    OrgSsoStartPorts, OrgSsoStartRequest, OrgSsoStartUseCase,
};
pub use steps::{
    FinishingPorts, LandedTenant, OfferedOrganization, OrgLoginOutcome, OrganizationChoice,
};
