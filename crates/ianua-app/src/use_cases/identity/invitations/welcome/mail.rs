//! Mailing a user that their account is ready and where to sign in, the
//! same way whether an admin made it ready or they finished joining
//! themselves.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{HttpsUrl, UserId};

use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::shared::{MailRecipient, Mailer};
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;

/// Where a welcome mail reads its user and tenant from, and how it goes.
#[derive(ianua_macros::Fakes)]
pub struct WelcomePorts {
    /// Loads the user being welcomed.
    pub user_store: Arc<dyn UserStore>,
    /// Reads the tenant's name, which the mail welcomes them into.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Sends the mail.
    pub mailer: Arc<dyn Mailer>,
    /// The address sign-in links are built on.
    pub base_url: HttpsUrl,
}

/// One welcome mail to send.
pub(in crate::use_cases::identity) struct Welcome<'a> {
    /// The user being welcomed.
    pub(in crate::use_cases::identity) user_id: UserId,
    /// Where the sign-in link lands.
    pub(in crate::use_cases::identity) scope: &'a LinkScope,
    /// Which welcome it is.
    pub(in crate::use_cases::identity) template: EmailTemplateType,
}

/// Mails `welcome` in `tenant`, returning what the user's account raised
/// once the mailer took it, and nothing otherwise.
///
/// A user who is gone, or a refused send, is no error: the mail is a
/// courtesy, and failing here would fail what already succeeded.
///
/// # Errors
///
/// - `AppError::Internal` when the user cannot be read.
pub(in crate::use_cases::identity) async fn send_welcome(
    ports: &WelcomePorts,
    tenant: &ScopedTenant,
    welcome: Welcome<'_>,
) -> Result<Vec<DomainEvent>, AppError> {
    let Some(mut user) = ports
        .user_store
        .find_by_id(tenant, &welcome.user_id)
        .await
        .or_internal()?
    else {
        return Ok(Vec::new());
    };
    let variables = welcome_variables(ports, tenant, &user, &welcome).await;
    let to = MailRecipient {
        email: user.email(),
        locale: user.locale(),
    };
    let sent = ports
        .mailer
        .send_to_person(to, *tenant, welcome.template, &variables)
        .await;
    if sent.is_err() {
        return Ok(Vec::new());
    }
    user.note_welcome_mailed();
    Ok(user.take_events(tenant))
}

/// What the welcome mail to `user` fills in: their name, where to sign in
/// and the tenant's name.
async fn welcome_variables(
    ports: &WelcomePorts,
    tenant: &ScopedTenant,
    user: &User<ResolvedTenant>,
    welcome: &Welcome<'_>,
) -> HashMap<TemplateVariable, String> {
    HashMap::from([
        (
            TemplateVariable::UserName,
            user.display_name().as_str().to_owned(),
        ),
        (
            TemplateVariable::ActionUrl,
            welcome.scope.login_url(&ports.base_url),
        ),
        (
            TemplateVariable::TenantName,
            tenant_name(ports, tenant).await,
        ),
    ])
}

/// The tenant's display name, or empty when it cannot be read: the mail
/// still goes out without it.
async fn tenant_name(ports: &WelcomePorts, tenant: &ScopedTenant) -> String {
    ports
        .tenant_store
        .find_by_id(tenant)
        .await
        .ok()
        .flatten()
        .map(|found| found.display_name().as_str().to_owned())
        .unwrap_or_default()
}
