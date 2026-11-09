//! The browser that comes to a sign-out address: an app's logout through
//! OpenID Connect, or a peer's single logout through SAML. It may hold a
//! session of the tenant, which the request may end, or none.

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::tenancy::ScopedTenant;

/// The browser a sign-out request came through.
pub enum LogoutBrowser {
    /// It holds a session here, which the request may end.
    SignedIn(Box<CallerContext>),
    /// It holds none in this tenant, so there is nothing to end; the
    /// tenant is the one the address names.
    SignedOut(ScopedTenant),
}

impl LogoutBrowser {
    /// The tenant the request came to.
    #[must_use]
    pub fn tenant(&self) -> ScopedTenant {
        match self {
            Self::SignedIn(caller) => caller.tenant(),
            Self::SignedOut(tenant) => *tenant,
        }
    }

    /// The person signed in to the browser's session, or none when it holds
    /// no session that still counts.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when who is signed in cannot be read.
    pub(crate) async fn person(
        &self,
        authorities: &dyn TenantAuthorities,
    ) -> Result<Option<SignedInAccount>, AppError> {
        let Self::SignedIn(caller) = self else {
            return Ok(None);
        };
        match authorities.signed_in(caller).await {
            Ok(person) => Ok(Some(person)),
            Err(AppError::Unauthenticated) => Ok(None),
            Err(failed) => Err(failed),
        }
    }
}
