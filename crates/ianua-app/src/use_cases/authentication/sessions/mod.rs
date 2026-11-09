//! Sessions: ending, refreshing and suspending them, holding each use
//! against where they were last used, purging those long over, trusted
//! devices, break-glass access and sign-in options.

pub mod break_glass;
pub mod device_trust;
mod holder;
pub(crate) mod logout;
mod lookup;
pub(crate) mod purge_ended;
pub(crate) mod sign_in_options;
pub(crate) mod token_refresh;
pub(crate) mod watch_use;

pub use logout::{LogoutPorts, LogoutUseCase, SigningOut};
pub use purge_ended::{PurgeEndedPorts, PurgeEndedUseCase};
pub use sign_in_options::{
    SignInConnection, SignInOptions, SignInOptionsPorts, SignInOptionsUseCase,
};
pub use token_refresh::{RefreshPorts, RefreshSuccess, TokenRefreshRequest, TokenRefreshUseCase};
pub use watch_use::{SessionStanding, WatchUsePorts, WatchUseRequest, WatchUseUseCase};
