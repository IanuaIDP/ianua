//! Proving a tenant user again by a sign-in link mailed to them and
//! followed just now, for an account whose mailbox is how it signs in.

use ianua_domain::domains::authentication::sessions::fresh_sign_in::{
    BesideTheMailbox, FreshSignIn,
};
use ianua_domain::domains::authentication::sessions::way_in::WayIn;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;

use crate::error::{AppError, OrInternal};
use crate::services::authentication::account_factor::FactorAnswer;
use crate::services::authentication::fresh_proof::FreshProofStep;
use crate::tenancy::ScopedTenant;

impl FreshProofStep {
    /// A sign-in link followed just now, for an account that signs in with
    /// its mailbox.
    pub(super) async fn by_mailbox(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        link: &Secret,
        code: Option<&str>,
    ) -> Result<FreshSignIn, AppError> {
        let signs_in_otherwise = self.holds_password_or_passkey(tenant, account).await?;
        let way_in = self.followed(tenant, account, link).await?;
        if signs_in_otherwise {
            return FreshSignIn::by_mailbox(way_in, BesideTheMailbox::PasswordOrPasskey)
                .map_err(AppError::from_domain);
        }
        let factor = self.factor_answer(tenant, account, code).await?;
        FreshSignIn::by_mailbox(way_in, beside_the_mailbox(&factor)).map_err(AppError::from_domain)
    }

    /// Whether the account signs in with a password or a passkey, which it
    /// then proves itself with instead of its mailbox.
    async fn holds_password_or_passkey(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
    ) -> Result<bool, AppError> {
        let password = self
            .ports
            .password
            .credentials
            .find_password_hash(tenant, account.id())
            .await
            .or_internal()?;
        if password.is_some() {
            return Ok(true);
        }
        let passkeys = self
            .ports
            .passkeys
            .passkeys
            .list_by_user(tenant, account.id())
            .await
            .or_internal()?;
        Ok(!passkeys.is_empty())
    }

    /// The way in a followed sign-in link gives, the link spent.
    async fn followed(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        link: &Secret,
    ) -> Result<WayIn, AppError> {
        let hash = self.ports.links.link_hasher.hash_raw(link.expose());
        let store = self.ports.links.magic_links.as_ref();
        let mut token = store
            .find_by_hash(tenant, &hash)
            .await
            .or_internal()?
            .ok_or_else(unproved_by_link)?;
        let way_in = WayIn::by_magic_link(&mut token, account, clock::now())
            .map_err(|_| unproved_by_link())?;
        if !store.consume(tenant, &hash).await.or_internal()? {
            return Err(unproved_by_link());
        }
        Ok(way_in)
    }
}

/// What the account gave beside its mailbox: its factor's answer, or
/// nothing when it has none.
fn beside_the_mailbox(answer: &FactorAnswer) -> BesideTheMailbox<'_> {
    match answer {
        FactorAnswer::NoneOnFile => BesideTheMailbox::Nothing,
        FactorAnswer::Answered(code) => BesideTheMailbox::SecondFactor(code),
    }
}

/// The refusal for a link that proves nothing of the account.
fn unproved_by_link() -> AppError {
    AppError::Forbidden(message!(
        "authentication-this-link-does-not-prove-who",
        "this link does not prove who you are"
    ))
}
