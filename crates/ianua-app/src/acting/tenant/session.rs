//! A tenant user's own session, checked as it stands now.

use ianua_domain::domains::authentication::sessions::account_check::SessionCheck;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{SessionId, UserId};
use time::OffsetDateTime;

use crate::acting::tenant::{Resolving, SignedInAccount, TenantActing};
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::Holder;
use crate::tenancy::ScopedTenant;

impl TenantActing {
    /// A tenant user's own session, while the session check admits it.
    pub(in crate::acting::tenant) async fn of_session(
        &self,
        at: &Resolving<'_>,
        user_id: &UserId,
        session_id: &SessionId,
    ) -> Result<TenantAuthority, AppError> {
        let signed_in = self
            .checked_session(at.caller, user_id, session_id, at.now)
            .await?;
        let records = self.held_by(at.caller, Holder::user(*user_id)).await?;
        records
            .access(at.caller.tenant_id())
            .authority_of(&signed_in.account, &signed_in.signed_in, at.now)
            .map_err(AppError::from_domain)
    }

    /// The account and its sign-in, while the session check admits the
    /// session.
    pub(in crate::acting::tenant) async fn checked_session(
        &self,
        caller: &CallerContext,
        user_id: &UserId,
        session_id: &SessionId,
        now: OffsetDateTime,
    ) -> Result<SignedInAccount, AppError> {
        let tenant = caller.tenant();
        let account = self.user(&tenant, user_id).await?;
        let session = self.session(&tenant, session_id).await?;
        self.admitted(&tenant, account, session, now).await
    }

    /// The account holding the session `session_id` of `tenant` and its
    /// sign-in, while the session check admits the session.
    pub(in crate::acting::tenant) async fn session_holder(
        &self,
        tenant: &ScopedTenant,
        session_id: &SessionId,
        now: OffsetDateTime,
    ) -> Result<SignedInAccount, AppError> {
        let session = self.session(tenant, session_id).await?;
        let account = self.user(tenant, session.user_id()).await?;
        self.admitted(tenant, account, session, now).await
    }

    async fn session(
        &self,
        tenant: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        self.ports
            .tenant
            .sessions
            .find_by_id(tenant, session_id)
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)
    }

    /// `account` signed in on `session`, when the session check under
    /// `tenant`'s timeouts admits it at `now`.
    async fn admitted(
        &self,
        tenant: &ScopedTenant,
        account: User<ResolvedTenant>,
        session: Session<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<SignedInAccount, AppError> {
        let timeout = self
            .tenant_record(tenant)
            .await?
            .auth_config()
            .session_timeout()
            .map_err(AppError::from_domain)?;
        let check = SessionCheck {
            account: &account,
            timeout: &timeout,
            now,
        };
        let signed_in = session.signed_in(&check).ok_or(AppError::Unauthenticated)?;
        Ok(SignedInAccount {
            account,
            signed_in,
            session,
            timeout,
        })
    }
}
