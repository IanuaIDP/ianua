//! Making and mailing the link that confirms a member's address, which
//! every path that leaves a member's address unconfirmed sends: a founder's
//! sign-up, a member an owner made, and asking for another link.
//!
//! Sending again spends every link sent before, so only the newest one
//! works and "send another" is safe to offer.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::tokens::email_verification::EmailVerification;
use ianua_domain::domains::organization::access::token::{NewOrgToken, OrgVerificationToken};
use ianua_domain::domains::organization::events::members::OrgVerificationEmailSent;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::security::secret::Secret;
use time::OffsetDateTime;

use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgTokenStore, OrgUserStore, OrganizationStore};
use crate::ports::shared::{MailSetup, Mailer};
use crate::services::authentication::channels::{ensure_mail_reaches, mail_reaches};
use crate::use_cases::identity::email::{LinkMailed, VerificationPolicy};
use crate::use_cases::organization::mail_labels::organization_name;

/// Where verification links for members are kept, how they are made and
/// how they go out.
#[derive(ianua_macros::Fakes)]
pub struct OrgVerificationMail {
    /// Loads members.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Reads a member's organization, for its name and sign-in pages.
    pub organization_store: Arc<dyn OrganizationStore>,
    /// Keeps the links.
    pub token_store: Arc<dyn OrgTokenStore<EmailVerification>>,
    /// Sends the mail.
    pub mailer: Arc<dyn Mailer>,
    /// Makes and hashes the links' tokens.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// How long a link lasts, the address it is built on, and the wait
    /// before another.
    pub policy: VerificationPolicy,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
}

/// One verification link to send.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::invitations) struct VerificationLink<'a> {
    /// The member whose address needs confirming.
    pub(in crate::use_cases::organization::invitations) member: &'a OrgUser,
    /// Where the link lands.
    pub(in crate::use_cases::organization::invitations) scope: &'a LinkScope,
}

impl OrgVerificationMail {
    /// Mails `member` of `organization` a link to confirm the address an
    /// owner just gave them, landing on the organization's own pages,
    /// answering what that records. Nobody who sets an address for someone
    /// else vouches for it, so the member confirms it here.
    ///
    /// # Errors
    ///
    /// - The errors of [`send`](Self::send).
    pub(in crate::use_cases::organization) async fn send_to_member(
        &self,
        member: &OrgUser,
        organization: &Organization,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let scope = LinkScope::organization(organization.slug().clone());
        self.send_unless_confirmed(VerificationLink {
            member,
            scope: &scope,
        })
        .await
    }

    /// Mails `link.member` a new link unless their address is already
    /// confirmed, answering what that records.
    ///
    /// A confirmed address is sent nothing, so a stray resend never leaves
    /// a live link for it.
    ///
    /// # Errors
    ///
    /// - The errors of [`send`](Self::send).
    pub(in crate::use_cases::organization::invitations) async fn send_unless_confirmed(
        &self,
        link: VerificationLink<'_>,
    ) -> Result<Vec<DomainEvent>, AppError> {
        if link.member.email_verified() {
            return Ok(Vec::new());
        }
        let mailed = self.send(link).await?;
        Ok(mailed_record(link.member, mailed))
    }

    /// Mails `link.member` a new link unless their address is already
    /// confirmed or their last link went out within the wait between
    /// links, answering what that records.
    ///
    /// For a resend anyone may ask for with an address: held back, it
    /// sends nothing and answers as though it sent, so a stranger can
    /// neither fill the inbox nor keep spending the link the person holds.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the last link cannot be read.
    /// - The errors of [`send`](Self::send).
    pub(in crate::use_cases::organization::invitations) async fn send_after_wait(
        &self,
        link: VerificationLink<'_>,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let last_sent_at = self.last_sent_at(link.member).await?;
        if self
            .policy
            .resend_cooldown
            .left_after(last_sent_at)
            .is_some()
        {
            return Ok(Vec::new());
        }
        self.send_unless_confirmed(link).await
    }

    /// When the last link to `member` was made, if one was.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on lookup failure.
    pub(in crate::use_cases::organization::invitations) async fn last_sent_at(
        &self,
        member: &OrgUser,
    ) -> Result<Option<OffsetDateTime>, AppError> {
        let latest = self
            .token_store
            .find_latest_by_user(member.id())
            .await
            .or_internal()?;
        Ok(latest.map(|token| token.created_at()))
    }

    /// Refuses a request that waits on a mailed link, on a deployment with
    /// no mail server, with `why`: the link would never arrive.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Forbidden` with `why` when no mail server is set
    /// up.
    pub(in crate::use_cases::organization) fn ensure_mailable(
        &self,
        why: &str,
    ) -> Result<(), AppError> {
        ensure_mail_reaches(self.mail.as_ref(), why)
    }

    /// Mails `link.member` a new link to confirm the address they have now.
    /// Every link sent to them before stops working.
    ///
    /// On a deployment with no mail server nothing is made or mailed, and
    /// [`LinkMailed::NoMailServer`] says so.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the policy's lifetime is longer than a link
    ///   may live.
    /// - `AppError::Internal` when the token cannot be made or stored.
    async fn send(&self, link: VerificationLink<'_>) -> Result<LinkMailed, AppError> {
        if !mail_reaches(self.mail.as_ref()) {
            return Ok(LinkMailed::NoMailServer);
        }
        self.token_store
            .consume_outstanding(link.member.id())
            .await
            .or_internal()?;
        let raw_token = self.stored_token(link.member).await?;
        Ok(self.mail(link, &raw_token).await)
    }

    /// The sign-in pages of `member`'s own organization, or nothing once it
    /// is gone.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on lookup failure.
    pub(in crate::use_cases::organization::invitations) async fn pages_of(
        &self,
        member: &OrgUser,
    ) -> Result<Option<LinkScope>, AppError> {
        let organization = self
            .organization_store
            .find_by_id(member.organization_id())
            .await
            .or_internal()?;
        Ok(organization.map(|organization| LinkScope::organization(organization.slug().clone())))
    }

    /// Stores a new token for `member`'s address, returning the raw value
    /// for the link.
    async fn stored_token(&self, member: &OrgUser) -> Result<Secret, AppError> {
        let (raw_token, token_hash) = self.token_generator.generate().or_internal()?.into_parts();
        let token = OrgVerificationToken::issue(NewOrgToken {
            token_hash,
            org_user_id: *member.id(),
            sent_to: member.email().clone(),
            lifetime: self.policy.lifetime,
        })
        .map_err(AppError::from_domain)?;
        self.token_store.save(&token).await.or_internal()?;
        Ok(raw_token)
    }

    /// Mails the link to the member's address.
    async fn mail(&self, link: VerificationLink<'_>, raw_token: &Secret) -> LinkMailed {
        let variables = self.variables(link, raw_token).await;
        let sent = self
            .mailer
            .send(
                link.member.email(),
                None,
                EmailTemplateType::OrgVerification,
                &variables,
            )
            .await;
        match sent {
            Ok(()) => LinkMailed::Sent,
            Err(_) => LinkMailed::Undelivered,
        }
    }

    /// What the verification template is filled with.
    async fn variables(
        &self,
        link: VerificationLink<'_>,
        raw_token: &Secret,
    ) -> HashMap<TemplateVariable, String> {
        HashMap::from([
            (
                TemplateVariable::UserName,
                link.member.display_name().as_str().to_owned(),
            ),
            (
                TemplateVariable::ActionUrl,
                link.scope
                    .action_url(&self.policy.base_url, "verify-email", raw_token.expose()),
            ),
            (
                TemplateVariable::ExpiresAt,
                format!("{} hours", self.policy.lifetime.whole_seconds() / 3600),
            ),
            (
                TemplateVariable::OrganizationName,
                organization_name(self.organization_store.as_ref(), link.member).await,
            ),
        ])
    }
}

/// What a link mailed to `member` records: that it went out, once the
/// mailer took it, and nothing when it did not.
fn mailed_record(member: &OrgUser, mailed: LinkMailed) -> Vec<DomainEvent> {
    (mailed == LinkMailed::Sent)
        .then(|| OrgVerificationEmailSent::observed(member))
        .into_iter()
        .collect()
}
