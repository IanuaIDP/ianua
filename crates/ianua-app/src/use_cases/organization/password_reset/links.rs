//! The reset link a member followed, and the member it was mailed for,
//! which every use of a reset link checks it against.

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::password_reset::PasswordReset;
use ianua_domain::domains::organization::access::token::OrgPasswordResetToken;
use ianua_domain::domains::organization::members::org_user::OrgUser;

use crate::error::{AppError, OrInternal};
use crate::input::validate_token;
use crate::ports::organization::{OrgTokenStore, OrgUserStore};

/// Where members' reset links and the members are kept, and how a link's
/// token is hashed to find it.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::password_reset) struct MemberResetLinks<'a> {
    /// Members' reset links.
    pub(in crate::use_cases::organization::password_reset) tokens:
        &'a dyn OrgTokenStore<PasswordReset>,
    /// Loads the account named by a password-reset link.
    pub(in crate::use_cases::organization::password_reset) members: &'a dyn OrgUserStore,
    /// Hashes a raw token the way it was stored.
    pub(in crate::use_cases::organization::password_reset) hasher: &'a dyn RefreshTokenGenerator,
}

/// A reset link and the member it was mailed for.
pub(in crate::use_cases::organization::password_reset) struct FollowedMemberReset {
    /// The link the token names.
    pub(in crate::use_cases::organization::password_reset) link: OrgPasswordResetToken,
    /// The member it was mailed for, as they are now.
    pub(in crate::use_cases::organization::password_reset) holder: OrgUser,
}

impl MemberResetLinks<'_> {
    /// The reset link `raw_token` names and its member, when both still
    /// exist, whatever state the link is in.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the token is empty or too long.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::organization::password_reset) async fn followed(
        &self,
        raw_token: &str,
    ) -> Result<Option<FollowedMemberReset>, AppError> {
        validate_token("token", raw_token)?;
        let Some(link) = self
            .tokens
            .find_by_hash(&self.hasher.hash_raw(raw_token))
            .await
            .or_internal()?
        else {
            return Ok(None);
        };
        let holder = self
            .members
            .find_by_id(link.org_user_id())
            .await
            .or_internal()?;
        Ok(holder.map(|holder| FollowedMemberReset { link, holder }))
    }
}
