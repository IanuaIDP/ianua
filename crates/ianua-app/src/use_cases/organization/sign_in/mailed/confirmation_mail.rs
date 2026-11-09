//! Mailing the link that finishes a member's sign-in which owes an email
//! confirmation.
//!
//! A member with no second factor, signing in from a device the
//! organization does not know, is not let in on the password alone, nor by
//! setting a factor up there and then. They confirm from their own mailbox
//! first: a single-use link goes to their address, and following it, in
//! the browser that began the sign-in, answers what it owes. On a
//! deployment with no mail server they set up a factor instead, and no
//! link is ever mailed.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;
use ianua_domain::domains::organization::access::token::{NewOrgToken, OrgSignInConfirmationToken};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::security::secret::Secret;

use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgTokenStore;
use crate::ports::shared::{MailSetup, Mailer};
use crate::use_cases::authentication::password::ConfirmationLinkPolicy;
use crate::use_cases::authentication::password::sign_in::confirmation::ensure_mail_reaches;

/// The page a member's confirmation link opens.
const CONFIRM_PAGE: &str = "confirm-sign-in";

/// Where members' confirmation links are kept and how they are made and
/// mailed.
#[derive(ianua_macros::Fakes)]
pub struct OrgConfirmationMailPorts {
    /// Keeps the single-use links.
    pub links: Arc<dyn OrgTokenStore<SignInConfirmation>>,
    /// Makes a link's token and its hash.
    pub link_tokens: Arc<dyn RefreshTokenGenerator>,
    /// Mails the link.
    pub mailer: Arc<dyn Mailer>,
    /// Whether the deployment can send mail at all.
    pub mail: Arc<dyn MailSetup>,
}

/// The member a confirmation link goes to, and their organization.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::sign_in) struct MemberConfirming<'a> {
    /// The member signing in, whose address the link goes to.
    pub(in crate::use_cases::organization::sign_in) member: &'a OrgUser,
    /// Their organization, whose pages the link opens.
    pub(in crate::use_cases::organization::sign_in) organization: &'a Organization,
}

impl OrgConfirmationMailPorts {
    /// Supersedes the member's earlier confirmation links, keeps a new one,
    /// and mails it to the address the member has now.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the policy's lifetime is longer than a
    ///   confirmation link may last.
    /// - `AppError::Internal` when no mail server is set up, before any link
    ///   is made or an earlier one superseded, or when the link cannot be
    ///   made, kept or mailed.
    pub(in crate::use_cases::organization::sign_in) async fn send(
        &self,
        to: MemberConfirming<'_>,
        policy: &ConfirmationLinkPolicy,
    ) -> Result<(), AppError> {
        ensure_mail_reaches(self.mail.as_ref())?;
        let (raw, link) = self.new_link(to.member, policy)?;
        let links = self.links.as_ref();
        links
            .consume_outstanding(to.member.id())
            .await
            .or_internal()?;
        links.save(&link).await.or_internal()?;
        let variables = member_mail_variables(to, policy, &raw);
        self.mailer
            .send(
                to.member.email(),
                None,
                EmailTemplateType::MagicLink,
                &variables,
            )
            .await
            .or_internal()
    }

    fn new_link(
        &self,
        member: &OrgUser,
        policy: &ConfirmationLinkPolicy,
    ) -> Result<(Secret, OrgSignInConfirmationToken), AppError> {
        let (raw, token_hash) = self
            .link_tokens
            .generate()
            .map(RefreshToken::into_parts)
            .or_internal()?;
        let link = OrgSignInConfirmationToken::issue(NewOrgToken {
            token_hash,
            org_user_id: *member.id(),
            sent_to: member.email().clone(),
            lifetime: policy.lifetime,
        })
        .map_err(AppError::from_domain)?;
        Ok((raw, link))
    }
}

fn member_mail_variables(
    to: MemberConfirming<'_>,
    policy: &ConfirmationLinkPolicy,
    raw: &Secret,
) -> HashMap<TemplateVariable, String> {
    let scope = LinkScope::organization(to.organization.slug().clone());
    HashMap::from([
        (
            TemplateVariable::UserName,
            to.member.display_name().as_str().to_owned(),
        ),
        (
            TemplateVariable::OrganizationName,
            to.organization.name().as_str().to_owned(),
        ),
        (
            TemplateVariable::ActionUrl,
            scope.action_url(&policy.base_url, CONFIRM_PAGE, raw.expose()),
        ),
        (
            TemplateVariable::ExpiresAt,
            format!("{} minutes", policy.lifetime.whole_seconds() / 60),
        ),
    ])
}
