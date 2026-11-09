//! Mailing the link that finishes a sign-in which owes an email
//! confirmation.
//!
//! A sign-in that raised a risk signal, from someone with no second factor
//! to answer it with, is not finished by setting a factor up there and then.
//! The person confirms from their own mailbox first: a single-use link goes
//! to the account's address, and following it answers what the sign-in owes.
//! On a deployment with no mail server no such sign-in is owed, since the
//! person sets up a factor instead, and no link is ever mailed.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::address::MailReach;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::tokens::secure::{NewSecureToken, SecureToken};
use ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{HttpsUrl, Lifetime};

use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{SignInConfirmationToken, SignInLinkStore};
use crate::ports::shared::{MailRecipient, MailSetup, Mailer};
use crate::tenancy::ScopedTenant;

/// The page a confirmation link opens.
const CONFIRM_PAGE: &str = "confirm-sign-in";

/// How long a confirmation link lasts and the address it is built on.
#[derive(Debug, Clone)]
pub struct ConfirmationLinkPolicy {
    /// How long the link stays usable.
    pub lifetime: Lifetime,
    /// The address the dashboard's pages hang off.
    pub base_url: HttpsUrl,
}

/// Where confirmation links are kept and how they are made and mailed.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmationMailPorts {
    /// Keeps the single-use links.
    pub links: Arc<dyn SignInLinkStore<SignInConfirmation>>,
    /// Makes a link's token and its hash.
    pub link_tokens: Arc<dyn RefreshTokenGenerator>,
    /// Mails the link.
    pub mailer: Arc<dyn Mailer>,
    /// Whether the deployment can send mail at all.
    pub mail: Arc<dyn MailSetup>,
}

/// A confirmation link to mail on a deployment that has no mail server.
#[derive(Debug, thiserror::Error)]
#[error("no mail server is set up, so a sign-in confirmation link cannot be mailed")]
struct NoMailServer;

/// Refuses to mail a confirmation link where no mail server is set up: the
/// sign-in would wait for a link that never arrives.
///
/// # Errors
///
/// `AppError::Internal` when `mail` says no mail server is set up.
pub(crate) fn ensure_mail_reaches(mail: &dyn MailSetup) -> Result<(), AppError> {
    match mail.reach() {
        MailReach::Available => Ok(()),
        MailReach::NotSetUp => Err(AppError::internal(NoMailServer)),
    }
}

/// One confirmation link to mail: to whom, and where it lands.
pub(in crate::use_cases::authentication::password) struct Confirmation<'a> {
    /// The tenant signing in to.
    pub(in crate::use_cases::authentication::password) tenant: &'a ScopedTenant,
    /// The account signing in, whose address the link goes to.
    pub(in crate::use_cases::authentication::password) account: &'a User<ResolvedTenant>,
    /// Where the link lands.
    pub(in crate::use_cases::authentication::password) scope: &'a LinkScope,
}

impl ConfirmationMailPorts {
    /// Keeps a new single-use link for `to.account` and mails it to the
    /// address the account has now.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the policy's lifetime is longer than a
    ///   sign-in link may last.
    /// - `AppError::Internal` when no mail server is set up, before any link
    ///   is made, or when the link cannot be made, kept or mailed.
    pub(in crate::use_cases::authentication::password) async fn send(
        &self,
        to: Confirmation<'_>,
        policy: &ConfirmationLinkPolicy,
    ) -> Result<(), AppError> {
        ensure_mail_reaches(self.mail.as_ref())?;
        let (raw, link) = self.new_link(to.account, policy)?;
        self.links.save(to.tenant, &link).await.or_internal()?;
        let variables = mail_variables(&to, policy, &raw);
        let recipient = MailRecipient {
            email: to.account.email(),
            locale: to.account.locale(),
        };
        self.mailer
            .send_to_person(
                recipient,
                *to.tenant,
                EmailTemplateType::MagicLink,
                &variables,
            )
            .await
            .or_internal()
    }

    fn new_link(
        &self,
        account: &User<ResolvedTenant>,
        policy: &ConfirmationLinkPolicy,
    ) -> Result<(Secret, SignInConfirmationToken), AppError> {
        let (raw, token_hash) = self
            .link_tokens
            .generate()
            .map(RefreshToken::into_parts)
            .or_internal()?;
        let link = SecureToken::create(NewSecureToken {
            token_hash,
            user_id: *account.id(),
            sent_to: account.email().clone(),
            lifetime: policy.lifetime,
        })
        .map_err(AppError::from_domain)?;
        Ok((raw, link))
    }
}

/// Whether a sign-in owing `owed` waits for its person to confirm by email.
pub(crate) fn owes_email_confirmation(owed: SecondFactor) -> bool {
    matches!(
        owed,
        SecondFactor::ConfirmByEmail | SecondFactor::ConfirmThenEnrol
    )
}

fn mail_variables(
    to: &Confirmation<'_>,
    policy: &ConfirmationLinkPolicy,
    raw: &Secret,
) -> HashMap<TemplateVariable, String> {
    HashMap::from([
        (
            TemplateVariable::UserName,
            to.account.display_name().as_str().to_owned(),
        ),
        (
            TemplateVariable::ActionUrl,
            to.scope
                .action_url(&policy.base_url, CONFIRM_PAGE, raw.expose()),
        ),
        (
            TemplateVariable::ExpiresAt,
            format!("{} minutes", policy.lifetime.whole_seconds() / 60),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{TenantSlug, UserId};

    use super::*;
    use crate::test_support::identity::user_named;
    use crate::test_support::{FakeMailSetup, FakeMailer, block_on, test_ctx};

    fn policy() -> ConfirmationLinkPolicy {
        ConfirmationLinkPolicy {
            lifetime: Lifetime::seconds(900).unwrap(),
            base_url: HttpsUrl::new("https://app.acme.test").unwrap(),
        }
    }

    fn scope() -> LinkScope {
        let limits = DomainLimits::default();
        LinkScope::tenant(
            TenantSlug::new("acme", &limits.slug).unwrap(),
            TenantSlug::new("prod", &limits.slug).unwrap(),
        )
    }

    /// Missing mail setup fails confirmation delivery before any mail is sent.
    #[test]
    fn no_link_is_mailed_where_no_mail_server_is_set_up() {
        let mailer = Arc::new(FakeMailer::new());
        let ports = ConfirmationMailPorts {
            mailer: mailer.clone(),
            mail: FakeMailSetup::not_set_up(),
            ..ConfirmationMailPorts::fakes()
        };
        let ann = user_named(UserId::new(), "ann@acme.test", "Ann");
        let tenant = test_ctx().tenant();
        let to = Confirmation {
            tenant: &tenant,
            account: &ann,
            scope: &scope(),
        };

        let sent = block_on(ports.send(to, &policy()));

        assert!(matches!(sent, Err(AppError::Internal(_))));
        assert!(mailer.recipients().is_empty());
    }
}
