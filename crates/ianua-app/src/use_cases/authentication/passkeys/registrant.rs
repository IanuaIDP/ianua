//! Who adds a passkey: someone signed in, or someone whose sign-in waits
//! for them to set up the second factor the workspace requires.
//!
//! The second has no finished session to act through. The sign-in they
//! hold lets them set up that factor and nothing else, and they show it by
//! its refresh token, which their browser holds.

use std::sync::Arc;

use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;

/// Who adds a passkey.
pub enum Registrant {
    /// Someone signed in to a session of the tenant.
    SignedIn(Box<CallerContext>),
    /// Someone whose sign-in waits for them to set up a second factor.
    SettingUpFactor(PendingSignIn),
}

/// A sign-in that waits for its person to set up a second factor, shown by
/// its refresh token. The token is a credential, so this has no `Debug`.
pub struct PendingSignIn {
    /// The tenant signed in to.
    pub tenant: ScopedTenant,
    /// The sign-in's refresh token, as the browser holds it.
    pub refresh_token: Secret,
}

impl Registrant {
    /// The tenant the passkey is added in.
    #[must_use]
    pub fn tenant(&self) -> ScopedTenant {
        match self {
            Self::SignedIn(caller) => caller.tenant(),
            Self::SettingUpFactor(pending) => pending.tenant,
        }
    }
}

/// The ports that find out who a [`Registrant`] is.
#[derive(ianua_macros::Fakes)]
pub struct RegistrantPorts {
    /// Who is signed in to a caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The tenant's sessions, for a sign-in still waiting.
    pub sessions: Arc<dyn SessionStore>,
    /// The tenant's users, for the account a waiting sign-in is for.
    pub users: Arc<dyn UserStore>,
    /// Hashes a refresh token the way sessions keep it.
    pub token_hasher: Arc<dyn RefreshTokenGenerator>,
}

/// The account adding a passkey, and the session they act through.
pub struct Registering {
    /// The account, as it is now.
    pub account: User<ResolvedTenant>,
    /// The finished session, or the sign-in still waiting for its factor.
    pub session: Session<ResolvedTenant>,
    /// Where the request came from, which a password typed again counts
    /// against: the caller's request, or for a waiting sign-in, where it
    /// was made moments ago.
    pub origin: AttemptOrigin,
}

impl RegistrantPorts {
    /// The account `registrant` adds a passkey to, and their session.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session no longer counts, or
    ///   the sign-in is not one waiting, moments ago, for a factor to be
    ///   set up.
    /// - `AppError::Internal` on storage failure.
    pub async fn registering(&self, registrant: &Registrant) -> Result<Registering, AppError> {
        match registrant {
            Registrant::SignedIn(caller) => {
                let person = self.tenant_authorities.signed_in(caller).await?;
                Ok(Registering {
                    account: person.account,
                    session: person.session,
                    origin: caller.origin(),
                })
            }
            Registrant::SettingUpFactor(pending) => self.waiting(pending).await,
        }
    }

    /// The sign-in `pending` shows, while it waits for a factor to be set
    /// up, and its account.
    async fn waiting(&self, pending: &PendingSignIn) -> Result<Registering, AppError> {
        let hash = self.token_hasher.hash_raw(pending.refresh_token.expose());
        let session = self
            .sessions
            .find_by_refresh_token_hash(&pending.tenant, &hash)
            .await
            .or_internal()?
            .filter(|session| session.enrolment_proof(clock::now()).is_some())
            .ok_or(AppError::Unauthenticated)?;
        let account = self
            .users
            .find_by_id(&pending.tenant, session.user_id())
            .await
            .or_internal()?
            .ok_or(AppError::Unauthenticated)?;
        Ok(Registering {
            account,
            origin: AttemptOrigin::of(session.ip_address()),
            session,
        })
    }
}
