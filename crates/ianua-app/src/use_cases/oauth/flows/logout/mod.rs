//! Signing out of the apps a session reached: ending the session, planning
//! the back-channel logouts a sign-out means, and telling each app.

pub(crate) mod back_channel_job;
pub(crate) mod end_session;
pub(crate) mod notify_back_channel;
pub(crate) mod plan_back_channel;
mod receivers;

pub use back_channel_job::{BACK_CHANNEL_LOGOUT_JOB, BackChannelLogoutHandler, LogoutJobs};
pub use end_session::{
    AddressAsked, ClientNamed, EndSessionOutcome, EndSessionPorts, EndSessionRequest,
    EndSessionUseCase, LogoutConfirmation,
};
pub use notify_back_channel::{
    LogoutDeliveries, NotifyBackChannelLogoutPorts, NotifyBackChannelLogoutUseCase, SignOutNotice,
};
pub use plan_back_channel::{PlanBackChannelPorts, PlanBackChannelUseCase};
