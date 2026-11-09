//! The account a session belongs to and the tenant's timeouts, which the
//! domain holds a stored session to each time it is used, and how audit
//! records name that account.

use ianua_domain::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{EventLabel, UserId};

use crate::error::AppError;
use crate::ports::identity::UserStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::{existing_tenant, existing_user};
use crate::tenancy::ScopedTenant;

/// Where a session's account and the tenant's timeouts are read.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication::sessions) struct HolderSources<'a> {
    /// The tenant's users.
    pub(in crate::use_cases::authentication::sessions) users: &'a dyn UserStore,
    /// Tenants, for their session timeouts.
    pub(in crate::use_cases::authentication::sessions) tenants: &'a dyn TenantStore,
}

impl HolderSources<'_> {
    /// `user_id`'s account as it is now, and the timeouts of `tenant`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant or the account no longer
    ///   exists.
    /// - `AppError::Domain` when the tenant's timeouts make no policy.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::authentication::sessions) async fn holder(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(User<ResolvedTenant>, SessionTimeoutPolicy), AppError> {
        let timeout = existing_tenant(self.tenants, tenant)
            .await?
            .auth_config()
            .session_timeout()
            .map_err(AppError::from_domain)?;
        let account = existing_user(self.users, tenant, user_id).await?;
        Ok((account, timeout))
    }
}

/// How an audit record names `user_id`: by the account's display name, or
/// by its id once the account is gone.
pub(in crate::use_cases::authentication::sessions) fn account_label(
    account: Option<&User<ResolvedTenant>>,
    user_id: &UserId,
) -> EventLabel {
    account.map_or_else(
        || EventLabel::of(&user_id.to_string()),
        |account| EventLabel::of(account.display_name().as_str()),
    )
}
