//! Mailing an invitation's link, the same way when it is first sent, sent
//! again by an admin, or renewed from a dead link. With no mail server, an
//! admin is handed the link to pass on instead.

use std::collections::HashMap;

use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::EventLabel;

use crate::email::{InvitationDelivery, InvitationMailing, InvitationPolicy, LinkScope};
use crate::error::AppError;
use crate::ports::shared::MailRecipient;
use crate::tenancy::ScopedTenant;

/// An invitation link on its way to the invited address.
pub(in crate::use_cases::identity) struct InvitationMail<'a> {
    /// The invited account, whose address the link goes to.
    pub(in crate::use_cases::identity) invitee: &'a User<ResolvedTenant>,
    /// The role accepting gives, when the mail names it.
    pub(in crate::use_cases::identity) role: Option<&'a EventLabel>,
    /// The token the link carries.
    pub(in crate::use_cases::identity) raw_token: &'a Secret,
    /// Where the link lands.
    pub(in crate::use_cases::identity) scope: &'a LinkScope,
}

/// Mails the invitation link through `mailing`, or, on a deployment with
/// no mail server, hands it back for the inviter to pass on and mails
/// nothing.
///
/// # Errors
///
/// - `AppError::Upstream` when the mail service refuses it.
pub(in crate::use_cases::identity) async fn deliver_invitation(
    mailing: &InvitationMailing,
    tenant: &ScopedTenant,
    mail: InvitationMail<'_>,
) -> Result<InvitationDelivery, AppError> {
    let link = accept_link(&mailing.policy, &mail);
    if let Some(handed) = mailing.handed_over_unless_mailed(&link) {
        return Ok(handed);
    }
    let variables = invitation_variables(&mailing.policy, &mail, link);
    let to = MailRecipient {
        email: mail.invitee.email(),
        locale: mail.invitee.locale(),
    };
    mailing
        .mailer
        .send_to_person(to, *tenant, EmailTemplateType::Invitation, &variables)
        .await
        .map_err(AppError::upstream)?;
    Ok(InvitationDelivery::Mailed)
}

/// The page the invitation's link opens, carrying its token.
fn accept_link(policy: &InvitationPolicy, mail: &InvitationMail<'_>) -> String {
    mail.scope
        .action_url(&policy.base_url, "accept-invite", mail.raw_token.expose())
}

/// What the invitation template is filled with, `action_url` among it.
fn invitation_variables(
    policy: &InvitationPolicy,
    mail: &InvitationMail<'_>,
    action_url: String,
) -> HashMap<TemplateVariable, String> {
    let mut variables = HashMap::from([
        (
            TemplateVariable::UserName,
            mail.invitee.display_name().as_str().to_owned(),
        ),
        (
            TemplateVariable::UserEmail,
            mail.invitee.email().as_str().to_owned(),
        ),
        (TemplateVariable::ActionUrl, action_url),
        (
            TemplateVariable::ExpiresAt,
            format!("{} days", policy.lifetime.whole_seconds() / 86_400),
        ),
    ]);
    if let Some(role) = mail.role {
        variables.insert(TemplateVariable::RoleName, role.as_str().to_owned());
    }
    variables
}
