//! The flows that hand out codes and take people through them: screening
//! and pushing authorization requests, the consent step, the device flow,
//! `userinfo`, reading a token back, and signing out through an app.

/// The browser flow: a pushed or carried request, screened and answered.
pub(crate) mod browser;
/// The device flow: a code shown on one device, approved on another.
pub(crate) mod device;
/// Signing out of the apps a session reached.
pub(crate) mod logout;
pub(crate) mod resolve_access_token;
pub(crate) mod userinfo;

pub use browser::{
    AuthorizationAsk, AuthorizeOutcome, AuthorizePorts, AuthorizeRequest, AuthorizeUseCase,
    BrowserParameters, Consent, ConsentAnswer, HintSent, PushAuthorizationRequestPorts,
    PushAuthorizationRequestUseCase, PushRequest, PushedRequestResult, Reply,
    ScreenAuthorizationPorts, ScreenAuthorizationUseCase, ScreenedRequest,
};
pub use device::{
    ApproveDevicePorts, ApproveDeviceUseCase, DenyDevicePorts, DenyDeviceUseCase, DeviceCodeResult,
    DeviceCodeTiming, ExpireDeviceAuthorizationsPorts, ExpireDeviceAuthorizationsUseCase,
    RequestDeviceCodePorts, RequestDeviceCodeRequest, RequestDeviceCodeUseCase,
};
pub use logout::{
    AddressAsked, BACK_CHANNEL_LOGOUT_JOB, BackChannelLogoutHandler, ClientNamed,
    EndSessionOutcome, EndSessionPorts, EndSessionRequest, EndSessionUseCase, LogoutConfirmation,
    LogoutDeliveries, LogoutJobs, NotifyBackChannelLogoutPorts, NotifyBackChannelLogoutUseCase,
    PlanBackChannelPorts, PlanBackChannelUseCase, SignOutNotice,
};
pub use resolve_access_token::{
    PresentedAccessToken, ResolveAccessTokenPorts, ResolveAccessTokenUseCase, ResolvedGrant,
};
pub use userinfo::{UserInfoPorts, UserInfoUseCase};
