//! Connecting an account by signing in at a service, through the app the
//! deployment registered with it: where the browser is sent, and the code
//! the service sends it back with swapped for the credential an account of
//! the integration holds.
//!
//! The platform makes the `state` and the PKCE verifier, keeps them, and
//! hands an integration only what one step needs. An integration never
//! sees a session or an account.

use async_trait::async_trait;
use ianua_domain::shared::security::secret::Secret;

/// What the browser carries to the service.
#[derive(Clone, Copy)]
pub struct SignInLink<'a> {
    /// The random `state`, sent to the service and brought back.
    pub state: &'a Secret,
    /// The `S256` challenge of the PKCE verifier.
    pub challenge: &'a str,
    /// The platform's one callback address, which every app registers.
    pub redirect: &'a str,
}

/// What a service answered the code with.
pub enum Exchange {
    /// The credential, written the way the integration's accounts hold it.
    Issued(Secret),
    /// The service refused the code: spent, expired or not for this app.
    Refused,
    /// The service could not be reached, or did not answer in time.
    Unreachable,
}

/// What a service's code is swapped with.
#[derive(Clone, Copy)]
pub struct Swap<'a> {
    /// The service's code.
    pub code: &'a Secret,
    /// The PKCE verifier the code was asked for with.
    pub verifier: &'a Secret,
    /// The platform's one callback address the browser came back to.
    pub redirect: &'a str,
    /// The space at the service the person named, when the sign-in asks
    /// for one, such as an Azure DevOps organization.
    pub place: Option<&'a str>,
}

/// Signing in at one integration's service to connect an account.
///
/// An integration offers one only when the deployment registered an app
/// with its service, so its client id and secret are set.
#[async_trait]
pub trait SignIn: Send + Sync {
    /// The service's word for the space a person names besides the
    /// account's name, such as `organization`, for a service whose sign-in
    /// reaches several; none by default.
    fn asks_for_place(&self) -> Option<&'static str> {
        None
    }

    /// Where to send the browser to sign in and allow the app.
    fn authorize_address(&self, link: SignInLink<'_>) -> String;

    /// The credential the service issues for `swap`, written the way the
    /// integration's accounts hold it. The call follows no redirect and is
    /// held to a time limit.
    async fn exchange(&self, swap: Swap<'_>) -> Exchange;
}
