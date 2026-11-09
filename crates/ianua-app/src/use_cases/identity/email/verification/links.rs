//! Making and mailing the link that confirms a user's address, which every
//! path that leaves an address unconfirmed sends: registration, sign-up, an
//! admin's change of address, the tenant's directory opening or moving an
//! account, and asking for another link.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::tokens::secure::NewSecureToken;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{HttpsUrl, Lifetime, TokenHash};

use crate::email::{LinkScope, ResendCooldown};
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{EmailVerificationToken, VerificationTokenStore};
use crate::ports::shared::{MailRecipient, MailSetup, Mailer};
use crate::services::authentication::channels::{ensure_mail_reaches, mail_reaches};
use crate::tenancy::ScopedTenant;

/// How verification links are made.
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// How long a link stays good.
    pub lifetime: Lifetime,
    /// The address links are built on.
    pub base_url: HttpsUrl,
    /// The wait before another link may be asked for.
    pub resend_cooldown: ResendCooldown,
}

/// Whether a link reached the mailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkMailed {
    /// The mailer took it.
    Sent,
    /// The mailer refused it. The token is stored all the same, so asking
    /// again works.
    Undelivered,
    /// The deployment has no mail server, so neither a token nor a mail
    /// was made: the address stays unconfirmed.
    NoMailServer,
}

impl LinkMailed {
    /// Notes on `user` that the link went out, when the mailer took it, so
    /// their account raises the record of it. A refused mail notes nothing.
    pub(crate) fn note_on(self, user: &mut User<ResolvedTenant>) {
        if self == Self::Sent {
            user.note_verification_mailed();
        }
    }
}

/// Issues verification links: stores a fresh token for the address a user
/// has now, spends the ones sent before, and mails the link.
pub struct VerificationLinks {
    generator: Arc<dyn RefreshTokenGenerator>,
    policy: VerificationPolicy,
    tokens: Arc<dyn VerificationTokenStore>,
    mailer: Arc<dyn Mailer>,
    mail: Arc<dyn MailSetup>,
}

/// Where a [`VerificationLinks`] keeps its tokens and sends its mail.
pub struct VerificationLinkStores {
    /// Keeps the tokens.
    pub tokens: Arc<dyn VerificationTokenStore>,
    /// Sends the mail.
    pub mailer: Arc<dyn Mailer>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
}

impl VerificationLinks {
    /// Links made by `generator` under `policy`, kept and sent through
    /// `stores`.
    #[must_use]
    pub fn new(
        generator: Arc<dyn RefreshTokenGenerator>,
        policy: VerificationPolicy,
        stores: VerificationLinkStores,
    ) -> Self {
        Self {
            generator,
            policy,
            tokens: stores.tokens,
            mailer: stores.mailer,
            mail: stores.mail,
        }
    }

    /// Refuses a request that waits on a mailed link, on a deployment with
    /// no mail server, with `why`: the link would never arrive.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Forbidden` with `why` when no mail server is set
    /// up.
    pub(crate) fn ensure_mailable(&self, why: &str) -> Result<(), AppError> {
        ensure_mail_reaches(self.mail.as_ref(), why)
    }

    /// The policy links are made under.
    #[must_use]
    pub fn policy(&self) -> &VerificationPolicy {
        &self.policy
    }

    /// The hash a presented raw token is looked up by.
    #[must_use]
    pub fn hash_of(&self, raw_token: &str) -> TokenHash {
        self.generator.hash_raw(raw_token)
    }

    /// Mails `user` a new link to confirm the address they have now. Every
    /// link sent to them before stops working.
    ///
    /// On a deployment with no mail server nothing is made or mailed, and
    /// [`LinkMailed::NoMailServer`] says so: the account is still made or
    /// changed, its address left unconfirmed.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the token cannot be made or stored.
    pub(crate) async fn send(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
        scope: &LinkScope,
    ) -> Result<LinkMailed, AppError> {
        if !mail_reaches(self.mail.as_ref()) {
            return Ok(LinkMailed::NoMailServer);
        }
        self.tokens
            .consume_outstanding(tenant, user.id())
            .await
            .or_internal()?;
        let raw_token = self.stored_token(tenant, user).await?;
        Ok(self.mail(tenant, user, raw_token.expose(), scope).await)
    }

    /// Stores a new token for `user`'s address, returning the raw value for
    /// the link.
    async fn stored_token(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
    ) -> Result<Secret, AppError> {
        let (raw_token, token_hash) = self.generator.generate().or_internal()?.into_parts();
        let token = EmailVerificationToken::create(NewSecureToken {
            token_hash,
            user_id: *user.id(),
            sent_to: user.email().clone(),
            lifetime: self.policy.lifetime,
        })
        .map_err(AppError::from_domain)?;
        self.tokens.save(tenant, &token).await.or_internal()?;
        Ok(raw_token)
    }

    /// Mails the link to `user`'s address.
    async fn mail(
        &self,
        tenant: &ScopedTenant,
        user: &User<ResolvedTenant>,
        raw_token: &str,
        scope: &LinkScope,
    ) -> LinkMailed {
        let variables = HashMap::from([
            (
                TemplateVariable::UserName,
                user.display_name().as_str().to_owned(),
            ),
            (
                TemplateVariable::ActionUrl,
                scope.action_url(&self.policy.base_url, "verify-email", raw_token),
            ),
            (
                TemplateVariable::ExpiresAt,
                format!("{} hours", self.policy.lifetime.whole_seconds() / 3600),
            ),
        ]);
        let to = MailRecipient {
            email: user.email(),
            locale: user.locale(),
        };
        let sent = self
            .mailer
            .send_to_person(to, *tenant, EmailTemplateType::Verification, &variables)
            .await;
        match sent {
            Ok(()) => LinkMailed::Sent,
            Err(_) => LinkMailed::Undelivered,
        }
    }
}
