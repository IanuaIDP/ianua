//! Confirming a member's address with a single-use link that proves it:
//! one mailed to the address, or the setup token an installation shows its
//! first owner.

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::installation_setup::InstallationSetup;
use ianua_domain::domains::identity::tokens::purpose::TokenPurpose;
use ianua_domain::domains::organization::access::token::OrgToken;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::shared::clock;

use crate::email::refused_link;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::{OrgTokenStore, OrgUserStore};
use crate::use_cases::organization::lookup::existing_token;

/// Where a link that proves an address is kept, and the member it names.
pub(in crate::use_cases::organization::invitations) struct AddressLinks<'a, Purpose>
where
    Purpose: TokenPurpose + Send + Sync + 'static,
{
    /// Loads and saves the accounts whose mailed links are being spent.
    pub(in crate::use_cases::organization::invitations) members: &'a dyn OrgUserStore,
    /// The links of this purpose.
    pub(in crate::use_cases::organization::invitations) tokens: &'a dyn OrgTokenStore<Purpose>,
    /// Hashes the token that was presented.
    pub(in crate::use_cases::organization::invitations) token_generator:
        &'a dyn RefreshTokenGenerator,
}

impl<Purpose> AddressLinks<'_, Purpose>
where
    Purpose: TokenPurpose + Send + Sync + 'static,
{
    /// Spends the link `raw_token` for the member it names, marks their
    /// address confirmed, saves both and hands back the member, holding
    /// the confirmation it raised.
    ///
    /// It works only while the member still has the address it went to.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the link is unknown or already used, by
    ///   another request a moment before too, or its member is gone.
    /// - `AppError::LinkExpired` if the link ran out of time, or the member
    ///   moved to another address since.
    /// - `AppError::Internal` on persistence failure.
    pub(in crate::use_cases::organization::invitations) async fn confirm(
        &self,
        raw_token: &str,
    ) -> Result<OrgUser, AppError> {
        let (mut token, mut member) = self.presented(raw_token).await?;
        let proof = token.redeem(&member, clock::now()).map_err(refused_link)?;
        member.verify_email(&proof).or_internal()?;
        self.keep(&token, &member).await?;
        Ok(member)
    }

    /// The link `raw_token` names, and the member it was issued to.
    async fn presented(&self, raw_token: &str) -> Result<(OrgToken<Purpose>, OrgUser), AppError> {
        crate::input::validate_token("token", raw_token)?;
        let token_hash = self.token_generator.hash_raw(raw_token);
        let token = existing_token(self.tokens, &token_hash).await?;
        let member = self
            .members
            .find_by_id(token.org_user_id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "organization-org-user-not-found",
                "org user not found"
            ))?;
        Ok((token, member))
    }

    /// Marks `token` spent, unless another request spent it a moment
    /// before, and saves `member`.
    async fn keep(&self, token: &OrgToken<Purpose>, member: &OrgUser) -> Result<(), AppError> {
        if !self.tokens.spend(token).await.or_internal()? {
            return Err(AppError::NotFound(message!(
                "app-this-link-was-already-used",
                "this link was already used"
            )));
        }
        self.members.save(member).await.or_internal()
    }
}

impl AddressLinks<'_, InstallationSetup> {
    /// Spends the setup token `raw_token` for the first owner it was issued
    /// to, confirms them as the installer, saves both and hands back the
    /// owner, holding the confirmation it raised. Their address is marked
    /// confirmed, and the token vouches for their first sign-in.
    ///
    /// # Errors
    ///
    /// As [`Self::confirm`] lists, and `AppError::Conflict` when the member
    /// it names never joined.
    pub(in crate::use_cases::organization::invitations) async fn confirm_installer(
        &self,
        raw_token: &str,
    ) -> Result<OrgUser, AppError> {
        let (mut token, mut owner) = self.presented(raw_token).await?;
        let proof = token
            .confirm_installer(&owner, clock::now())
            .map_err(refused_link)?;
        owner
            .confirm_as_installer(&proof)
            .map_err(AppError::from_domain)?;
        self.keep(&token, &owner).await?;
        Ok(owner)
    }
}
