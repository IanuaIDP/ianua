//! Mailing an organization invitation's link, the same way when an owner
//! first sends it and when they send it again. With no mail server, the
//! owner is handed the link to pass on instead.

use std::collections::HashMap;

use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::security::secret::Secret;

use crate::email::{InvitationDelivery, InvitationMailing, InvitationPolicy, LinkScope};
use crate::error::AppError;

/// An invitation link on its way to the invited member's address.
pub(in crate::use_cases::organization::invitations) struct OrgInvitationMail<'a> {
    /// The invited member, whose address the link goes to.
    pub(in crate::use_cases::organization::invitations) invitee: &'a OrgUser,
    /// The name of the organization they are invited into.
    pub(in crate::use_cases::organization::invitations) organization_name: &'a str,
    /// The token the link carries.
    pub(in crate::use_cases::organization::invitations) raw_token: &'a Secret,
    /// Where the link lands.
    pub(in crate::use_cases::organization::invitations) scope: &'a LinkScope,
}

/// Mails the invitation link to the invited member through `mailing`, or,
/// on a deployment with no mail server, hands it back for the inviter to
/// pass on and mails nothing.
///
/// # Errors
///
/// - `AppError::Upstream` when the mail service refuses it.
pub(in crate::use_cases::organization::invitations) async fn deliver_org_invitation(
    mailing: &InvitationMailing,
    mail: OrgInvitationMail<'_>,
) -> Result<InvitationDelivery, AppError> {
    let link = accept_link(&mailing.policy, &mail);
    if let Some(handed) = mailing.handed_over_unless_mailed(&link) {
        return Ok(handed);
    }
    let variables = org_invitation_variables(&mailing.policy, &mail, link);
    mailing
        .mailer
        .send(
            mail.invitee.email(),
            None,
            EmailTemplateType::OrgInvitation,
            &variables,
        )
        .await
        .map_err(AppError::upstream)?;
    Ok(InvitationDelivery::Mailed)
}

/// The page the invitation's link opens, carrying its token.
fn accept_link(policy: &InvitationPolicy, mail: &OrgInvitationMail<'_>) -> String {
    mail.scope
        .action_url(&policy.base_url, "accept-invite", mail.raw_token.expose())
}

/// What the organization invitation template is filled with, `action_url`
/// among it.
fn org_invitation_variables(
    policy: &InvitationPolicy,
    mail: &OrgInvitationMail<'_>,
    action_url: String,
) -> HashMap<TemplateVariable, String> {
    HashMap::from([
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
        (
            TemplateVariable::OrganizationName,
            mail.organization_name.to_owned(),
        ),
    ])
}
