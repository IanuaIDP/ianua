//! Making a password reset link and mailing it: for a person who forgot
//! their password, for one whose sign-in found it must be changed first,
//! and for an admin who sends one rather than choosing the password.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::recovery::reset::{
    CreateResetParams, PasswordResetRequest, ResetInitiator,
};
use ianua_domain::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Email, HttpsUrl, Lifetime, Locale, Preference};

use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::ResetRequestStore;
use crate::ports::shared::{MailRecipient, MailSetup, Mailer};
use crate::services::authentication::channels::{NO_RESET_LINKS, ensure_mail_reaches};
use crate::tenancy::ScopedTenant;

/// How long a reset link works and the address it is built on.
#[derive(Debug, Clone)]
pub struct ResetRequestPolicy {
    /// How long the link works, at most an hour.
    pub lifetime: Lifetime,
    /// The base URL the link is built on.
    pub base_url: HttpsUrl,
}

/// The ports reset links are kept, made and mailed through.
#[derive(ianua_macros::Fakes)]
pub struct ResetMailPorts {
    /// Saves reset requests and supersedes earlier ones.
    pub reset_store: Arc<dyn ResetRequestStore>,
    /// Composes and sends the reset email.
    pub mailer: Arc<dyn Mailer>,
    /// Makes the link's token and its hash.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
}

impl ResetMailPorts {
    /// Where reset links are kept, made and mailed, under `policy`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Forbidden` on a deployment with no mail server,
    /// saying an administrator must reset the password: a link would never
    /// arrive.
    pub(crate) fn mailing<'a>(
        &'a self,
        policy: &'a ResetRequestPolicy,
    ) -> Result<ResetMailing<'a>, AppError> {
        ensure_mail_reaches(self.mail.as_ref(), NO_RESET_LINKS)?;
        Ok(ResetMailing {
            resets: self.reset_store.as_ref(),
            mailer: self.mailer.as_ref(),
            tokens: self.token_generator.as_ref(),
            policy,
        })
    }
}

/// Where reset links are kept, made and mailed, and how long they last.
pub(crate) struct ResetMailing<'a> {
    /// Saves reset requests and supersedes earlier ones.
    pub(crate) resets: &'a dyn ResetRequestStore,
    /// Composes and sends the reset email.
    pub(crate) mailer: &'a dyn Mailer,
    /// Makes the link's token and its hash.
    pub(crate) tokens: &'a dyn RefreshTokenGenerator,
    /// How long a link works and the address it is built on.
    pub(crate) policy: &'a ResetRequestPolicy,
}

/// A reset link on its way: where it goes, its raw token and the pages it
/// opens.
pub(crate) struct OutgoingReset<'a> {
    /// The address the request was made for.
    pub(crate) to: &'a Email,
    /// The language the account's holder reads.
    pub(crate) locale: &'a Preference<Locale>,
    /// The token the link carries, never stored.
    pub(crate) raw: &'a Secret,
    /// The organization or tenant whose reset page the link opens.
    pub(crate) scope: &'a LinkScope,
}

impl ResetMailing<'_> {
    /// A new reset for `holder`, started by `initiator`, with the raw token
    /// its link carries, or none when the domain gives the account no link:
    /// it may not sign in, or its address was never shown to reach its
    /// owner.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the configured lifetime is longer than a
    ///   reset link may live.
    /// - `AppError::Internal` when no token can be made.
    pub(crate) fn fresh(
        &self,
        holder: &User<ResolvedTenant>,
        initiator: ResetInitiator,
    ) -> Result<Option<(PasswordResetRequest, Secret)>, AppError> {
        let (raw, token_hash) = self
            .tokens
            .generate()
            .map(RefreshToken::into_parts)
            .or_internal()?;
        let params = CreateResetParams {
            initiator,
            token_hash,
            lifetime: self.policy.lifetime,
        };
        match PasswordResetRequest::create(holder, params) {
            Ok(request) => Ok(Some((request, raw))),
            Err(DomainError::Forbidden(_)) => Ok(None),
            Err(other) => Err(AppError::from_domain(other)),
        }
    }

    /// Supersedes the account's earlier links and keeps `request`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` on storage failure.
    pub(crate) async fn replace_links(
        &self,
        tenant: &ScopedTenant,
        request: &PasswordResetRequest,
    ) -> Result<(), AppError> {
        self.resets
            .expire_pending_for_user(tenant, request.user_id())
            .await
            .or_internal()?;
        self.resets.save(tenant, request).await.or_internal()
    }

    /// Mails the reset link. Delivery is best effort: the answer is the same
    /// either way, so it reveals nothing about the address.
    pub(crate) async fn mail(&self, tenant: &ScopedTenant, outgoing: OutgoingReset<'_>) {
        let variables = HashMap::from([
            (
                TemplateVariable::ActionUrl,
                outgoing.scope.action_url(
                    &self.policy.base_url,
                    "reset-password",
                    outgoing.raw.expose(),
                ),
            ),
            (
                TemplateVariable::ExpiresAt,
                format!("{} minutes", self.policy.lifetime.whole_seconds() / 60),
            ),
        ]);
        let to = MailRecipient {
            email: outgoing.to,
            locale: outgoing.locale,
        };
        let sent =
            self.mailer
                .send_to_person(to, *tenant, EmailTemplateType::PasswordReset, &variables);
        let _ = sent.await;
    }
}
