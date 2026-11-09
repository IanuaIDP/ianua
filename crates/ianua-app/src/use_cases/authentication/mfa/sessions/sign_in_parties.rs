//! The session a second factor is given for, with its account and the
//! tenant's step-up policy, loaded fresh, as every step that answers a
//! session's factor needs them.

use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{SessionId, UserId};

use crate::error::AppError;
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::{existing_tenant, existing_user, owned_session};
use crate::tenancy::ScopedTenant;

/// A sign-in still in progress: the session and its owner, as the sign-in
/// token the person holds names them. The token is read before the use
/// case, since an unfinished session signs no request in.
pub struct PendingSignIn {
    /// The tenant the sign-in is in.
    pub tenant: ScopedTenant,
    /// The session waiting on a second factor.
    pub session_id: SessionId,
    /// Whose session it is.
    pub user_id: UserId,
}

/// Where a sign-in's session, account and tenant are read.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication::mfa) struct SignInSources<'a> {
    /// The tenant's sessions.
    pub(in crate::use_cases::authentication::mfa) sessions: &'a dyn SessionStore,
    /// The tenant's users.
    pub(in crate::use_cases::authentication::mfa) users: &'a dyn UserStore,
    /// Tenants, for their step-up policy.
    pub(in crate::use_cases::authentication::mfa) tenants: &'a dyn TenantStore,
}

/// A session, its account and the tenant's step-up policy.
pub(in crate::use_cases::authentication::mfa) struct SignInParties {
    /// The session, as stored.
    pub(in crate::use_cases::authentication::mfa) session: Session<ResolvedTenant>,
    /// Its account, as it is now.
    pub(in crate::use_cases::authentication::mfa) account: User<ResolvedTenant>,
    /// What the tenant asks a sign-in to reach.
    pub(in crate::use_cases::authentication::mfa) policy: StepUpPolicy,
}

impl SignInSources<'_> {
    /// The session `session_id` of `user_id`, with its account and the
    /// tenant's step-up policy.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the session is unknown or another
    ///   user's, or the user or tenant is gone.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::authentication::mfa) async fn parties(
        &self,
        tenant: &ScopedTenant,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Result<SignInParties, AppError> {
        let session = owned_session(self.sessions, tenant, session_id, user_id).await?;
        let account = existing_user(self.users, tenant, user_id).await?;
        let policy = existing_tenant(self.tenants, tenant)
            .await?
            .auth_config()
            .step_up_policy()
            .clone();
        Ok(SignInParties {
            session,
            account,
            policy,
        })
    }
}
