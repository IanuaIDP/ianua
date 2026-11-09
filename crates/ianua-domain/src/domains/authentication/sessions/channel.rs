//! Where a session was opened, and so where it may be used.

use crate::types::ServiceId;

/// Where a session was opened.
///
/// A session opened by signing in on an app's own host belongs to that app.
/// It is presented only as that host's session cookie. It is never
/// refreshed into a bearer token for anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionChannel {
    /// Signed in through the dashboard or the API.
    Dashboard,
    /// Signed in on the host of an app behind the gateway, through the app
    /// sign-in of this service.
    App(ServiceId),
}

impl SessionChannel {
    /// The service whose app sign-in opened the session, if any.
    #[must_use]
    pub fn app_service(&self) -> Option<&ServiceId> {
        match self {
            Self::Dashboard => None,
            Self::App(service_id) => Some(service_id),
        }
    }
}
