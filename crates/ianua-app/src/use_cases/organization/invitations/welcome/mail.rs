//! Mailing a member that their account is ready and where to sign in, the
//! same way whether an owner made it ready or they finished joining
//! themselves.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::organization::events::members::OrgWelcomeEmailSent;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::HttpsUrl;

use crate::email::LinkScope;
use crate::ports::organization::{OrgUserStore, OrganizationStore};
use crate::ports::shared::Mailer;
use crate::use_cases::identity::email::LinkMailed;
use crate::use_cases::organization::mail_labels::organization_name;

/// Where a welcome mail reads its member and organization from, and how it
/// goes.
#[derive(ianua_macros::Fakes)]
pub struct OrgWelcomePorts {
    /// Loads the member being welcomed.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Reads the organization's name, which the mail welcomes them into.
    pub organization_store: Arc<dyn OrganizationStore>,
    /// Sends the mail.
    pub mailer: Arc<dyn Mailer>,
    /// The address sign-in links are built on.
    pub base_url: HttpsUrl,
}

/// One welcome mail to send.
pub(in crate::use_cases::organization::invitations) struct OrgWelcome<'a> {
    /// The member being welcomed.
    pub(in crate::use_cases::organization::invitations) member: &'a OrgUser,
    /// Where the sign-in link lands.
    pub(in crate::use_cases::organization::invitations) scope: &'a LinkScope,
    /// Which welcome it is.
    pub(in crate::use_cases::organization::invitations) template: EmailTemplateType,
}

/// Mails `welcome`, answering whether the mailer took it.
///
/// A refused send is no error: the mail is a courtesy, and failing here
/// would fail what already succeeded.
pub(in crate::use_cases::organization::invitations) async fn mail_org_welcome(
    ports: &OrgWelcomePorts,
    welcome: OrgWelcome<'_>,
) -> LinkMailed {
    let variables = welcome_variables(ports, &welcome).await;
    let sent = ports
        .mailer
        .send(welcome.member.email(), None, welcome.template, &variables)
        .await;
    match sent {
        Ok(()) => LinkMailed::Sent,
        Err(_) => LinkMailed::Undelivered,
    }
}

/// What the welcome template is filled with.
async fn welcome_variables(
    ports: &OrgWelcomePorts,
    welcome: &OrgWelcome<'_>,
) -> HashMap<TemplateVariable, String> {
    let member = welcome.member;
    HashMap::from([
        (
            TemplateVariable::UserName,
            member.display_name().as_str().to_owned(),
        ),
        (
            TemplateVariable::ActionUrl,
            welcome.scope.login_url(&ports.base_url),
        ),
        (
            TemplateVariable::OrganizationName,
            organization_name(ports.organization_store.as_ref(), member).await,
        ),
    ])
}

/// What a welcome to `member` records: that it went out, once the mailer
/// took it, and nothing when it did not.
pub(in crate::use_cases::organization::invitations) fn welcome_record(
    member: &OrgUser,
    mailed: LinkMailed,
) -> Vec<DomainEvent> {
    (mailed == LinkMailed::Sent)
        .then(|| OrgWelcomeEmailSent::observed(member))
        .into_iter()
        .collect()
}
