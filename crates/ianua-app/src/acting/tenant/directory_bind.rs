//! A tenant user's directory bind, checked again on every request a bound
//! connection makes.
//!
//! A bind proves the person once, for the whole connection. Without
//! checking the certificate again, Ann's admin revokes the certificate on
//! her stolen laptop, or resets her password, and the connection open on it
//! keeps writing.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::UserId;
use time::OffsetDateTime;

use crate::acting::tenant::{Resolving, TenantActing};
use crate::context::{CallerContext, DirectoryBound};
use crate::error::AppError;
use crate::ports::authorization::Holder;

impl TenantActing {
    /// A tenant user's directory bind, for what they hold now, while the
    /// certificate it was made over still admits them.
    pub(in crate::acting::tenant) async fn of_directory_bind(
        &self,
        at: &Resolving<'_>,
        user_id: &UserId,
        bound: &DirectoryBound,
    ) -> Result<TenantAuthority, AppError> {
        let account = self
            .bound_account(at.caller, user_id, bound, at.now)
            .await?;
        let records = self.held_by(at.caller, Holder::user(*user_id)).await?;
        records
            .access(at.caller.tenant_id())
            .authority_of(&account, bound.bind(), at.now)
            .map_err(AppError::from_domain)
    }

    /// The account bound as, loaded fresh, while the certificate the bind
    /// was made over is in force for it, it may still sign in, and its
    /// credentials have not changed since the bind.
    pub(in crate::acting::tenant) async fn bound_account(
        &self,
        caller: &CallerContext,
        user_id: &UserId,
        bound: &DirectoryBound,
        now: OffsetDateTime,
    ) -> Result<User<ResolvedTenant>, AppError> {
        let tenant = caller.tenant();
        let account = self.user(&tenant, user_id).await?;
        let certificate = self
            .ports
            .tenant
            .certificates
            .find_by_id(&tenant, bound.certificate())
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)?;
        if !bound.bind().still_admits(&account, &certificate, now) {
            return Err(AppError::Unauthenticated);
        }
        Ok(account)
    }
}
