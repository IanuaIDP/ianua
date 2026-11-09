//! The password reset a followed link names, and the account it was mailed
//! for, which every use of a reset link checks it against.

use ianua_domain::domains::authentication::recovery::reset::PasswordResetRequest;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::TokenState;
use time::OffsetDateTime;

use crate::error::{AppError, OrInternal};
use crate::input::validate_token;
use crate::ports::authentication::ResetRequestStore;
use crate::ports::identity::UserStore;
use crate::tenancy::ScopedTenant;

/// Where reset requests and their accounts are kept, and how a link's token
/// is hashed to find its request.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication::password) struct ResetLinks<'a> {
    /// The tenant's reset requests.
    pub(in crate::use_cases::authentication::password) resets: &'a dyn ResetRequestStore,
    /// The tenant's users.
    pub(in crate::use_cases::authentication::password) users: &'a dyn UserStore,
    /// Hashes a raw token the way it was stored.
    pub(in crate::use_cases::authentication::password) hasher: &'a dyn RefreshTokenGenerator,
}

/// A reset request and the account it was mailed for.
pub(in crate::use_cases::authentication::password) struct FollowedReset {
    /// The request the link names.
    pub(in crate::use_cases::authentication::password) reset: PasswordResetRequest,
    /// The account it was mailed for, as it is now.
    pub(in crate::use_cases::authentication::password) holder: User<ResolvedTenant>,
}

impl ResetLinks<'_> {
    /// The reset request the link `raw_token` belongs to and its account,
    /// when both still exist, whatever state the request is in.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the token is empty or too long.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::authentication::password) async fn followed(
        &self,
        tenant: &ScopedTenant,
        raw_token: &str,
    ) -> Result<Option<FollowedReset>, AppError> {
        validate_token("token", raw_token)?;
        let hash = self.hasher.hash_raw(raw_token);
        let Some(reset) = self
            .resets
            .find_by_token_hash(tenant, &hash)
            .await
            .or_internal()?
        else {
            return Ok(None);
        };
        let holder = self
            .users
            .find_by_id(tenant, reset.user_id())
            .await
            .or_internal()?;
        Ok(holder.map(|holder| FollowedReset { reset, holder }))
    }

    /// The reset request the link `raw_token` belongs to and its account,
    /// while the link can still set a password for that account at `now`.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the token is empty or too long.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::authentication::password) async fn usable(
        &self,
        tenant: &ScopedTenant,
        raw_token: &str,
        now: OffsetDateTime,
    ) -> Result<Option<FollowedReset>, AppError> {
        let followed = self.followed(tenant, raw_token).await?;
        Ok(followed.filter(|held| held.reset.state_for(&held.holder, now) == TokenState::Usable))
    }
}
