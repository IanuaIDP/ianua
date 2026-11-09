//! The links an email change mails: the confirmation sent to the new
//! address, made the same way on both planes when first asked for and when
//! renewed; the warning to the current address, with the link that stops
//! the change, when it is asked for; and the notice to the old address once
//! it lands.

use std::collections::HashMap;

use ianua_domain::domains::authentication::sessions::fresh_sign_in::FreshSignIn;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::email_change::{
    ChangingAccount, CreateEmailChangeParams, PendingEmailChange,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Email, Fact, HttpsUrl, IpAddress, Lifetime, Locale, Preference};

use crate::email::{LinkScope, ResendCooldown};
use crate::error::{AppError, OrInternal};
use crate::ports::shared::{MailRecipient, Mailer};
use crate::tenancy::ScopedTenant;
use crate::use_cases::identity::renewal::renewed_link;

/// How email change links are made.
#[derive(Debug, Clone)]
pub struct EmailChangePolicy {
    /// How long a confirmation link stays good.
    pub lifetime: Lifetime,
    /// The address links are built on.
    pub base_url: HttpsUrl,
    /// The wait before another link may be asked for.
    pub resend_cooldown: ResendCooldown,
}

/// A change just asked for, with the raw links it mails.
pub(crate) struct NewChange {
    /// The change, waiting on its confirmation.
    pub(crate) change: PendingEmailChange,
    /// The link that confirms it, for the new address.
    pub(in crate::use_cases::identity) confirm: Secret,
    /// The link that stops it, for the current address.
    pub(in crate::use_cases::identity) cancel: Secret,
}

/// A new change to `new_email`, made by `ask` from its links once whoever
/// asks was checked, and the raw links that confirm and stop it.
///
/// `ask` is the account's own rule for who may move it: a fresh proof of
/// the holder for a person, another operator for an operator.
///
/// # Errors
///
/// - `AppError::Forbidden` when `ask` refuses whoever asks.
/// - `AppError::Domain` when the new address is the one the account has.
/// - `AppError::Internal` when a link cannot be made.
pub(crate) fn new_change(
    generator: &dyn RefreshTokenGenerator,
    policy: &EmailChangePolicy,
    new_email: Email,
    ask: impl FnOnce(CreateEmailChangeParams) -> Result<PendingEmailChange, DomainError>,
) -> Result<NewChange, AppError> {
    let (confirm, renewed) = renewed_link(generator, policy.lifetime)?;
    let (raw_cancel, cancel) = renewed_link(generator, policy.lifetime)?;
    let change = ask(CreateEmailChangeParams {
        new_email,
        token_hash: renewed.token_hash,
        cancel_token_hash: cancel.token_hash,
        lifetime: policy.lifetime,
    })
    .map_err(AppError::from_domain)?;
    Ok(NewChange {
        change,
        confirm,
        cancel: raw_cancel,
    })
}

/// The address a holder asks to move to, and the fresh sign-in that proves
/// it is them asking.
pub(in crate::use_cases::identity) struct ProvedAddress<'a> {
    /// The address asked for.
    pub(in crate::use_cases::identity) new_email: Email,
    /// The fresh proof of the account's holder.
    pub(in crate::use_cases::identity) fresh: &'a FreshSignIn,
}

/// A change of `account`'s address to the one `proved` asks for, and the
/// raw links that confirm and stop it.
///
/// # Errors
///
/// - `AppError::Forbidden` when the proof is not a fresh one of the
///   account's holder.
/// - `AppError::Domain` when the new address is the one the account has.
/// - `AppError::Internal` when a link cannot be made.
pub(in crate::use_cases::identity) fn proved_change(
    generator: &dyn RefreshTokenGenerator,
    policy: &EmailChangePolicy,
    account: ChangingAccount<'_>,
    proved: ProvedAddress<'_>,
) -> Result<NewChange, AppError> {
    let ProvedAddress { new_email, fresh } = proved;
    new_change(generator, policy, new_email, |params| {
        PendingEmailChange::create(account, params, fresh)
    })
}

/// The plane a change's mail belongs to, and so its branding and language.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MailedIn<'a> {
    /// A tenant's: the mail carries its branding and is written in the
    /// language the person reads.
    Tenant {
        /// The scope whose branding is applied to the confirmation mail.
        tenant: ScopedTenant,
        /// The language the person reads, or that they follow the tenant's.
        locale: &'a Preference<Locale>,
    },
    /// The organization plane, whose mail carries the platform's.
    Organization,
}

/// A confirmation link on its way to the address a change waits on.
pub(in crate::use_cases::identity) struct ConfirmationMail<'a> {
    /// The new address, which is where the link goes.
    pub(in crate::use_cases::identity) to: &'a Email,
    /// The plane the mail belongs to.
    pub(in crate::use_cases::identity) mailed_in: MailedIn<'a>,
    /// The token the link carries.
    pub(in crate::use_cases::identity) raw_token: &'a Secret,
    /// Where the link lands.
    pub(in crate::use_cases::identity) scope: &'a LinkScope,
}

/// Mails the confirmation link.
///
/// # Errors
///
/// - `AppError::Internal` when the mail cannot be sent.
pub(in crate::use_cases::identity) async fn mail_confirmation(
    mailer: &dyn Mailer,
    policy: &EmailChangePolicy,
    mail: ConfirmationMail<'_>,
) -> Result<(), AppError> {
    let variables = HashMap::from([
        (TemplateVariable::UserEmail, mail.to.as_str().to_owned()),
        (
            TemplateVariable::ActionUrl,
            mail.scope.action_url(
                &policy.base_url,
                "confirm-email-change",
                mail.raw_token.expose(),
            ),
        ),
        (
            TemplateVariable::ExpiresAt,
            format!("{} hours", policy.lifetime.whole_seconds() / 3600),
        ),
    ]);
    let template = EmailTemplateType::EmailChangeVerification;
    deliver(mailer, mail.to, mail.mailed_in, template, &variables)
        .await
        .or_internal()
}

/// A warning on its way to the address an account has now, that someone
/// asked to move the account to another.
pub(in crate::use_cases::identity) struct ChangeWarning<'a> {
    /// The address the account has now.
    pub(in crate::use_cases::identity) to: &'a Email,
    /// The plane the mail belongs to.
    pub(in crate::use_cases::identity) mailed_in: MailedIn<'a>,
    /// The change asked for, to name the address it moves to.
    pub(in crate::use_cases::identity) change: &'a NewChange,
    /// Where the cancel link lands.
    pub(in crate::use_cases::identity) scope: &'a LinkScope,
    /// Where the request came from, when known.
    pub(in crate::use_cases::identity) requested_from: &'a Fact<IpAddress>,
}

/// Warns the current address of a change asked for, with the link that
/// stops it.
///
/// Whoever took over a signed-in session asks to move the account to their
/// own address; the owner still reads this one and stops it. So the
/// warning is not best effort: a change nobody was warned of is not asked
/// for.
///
/// # Errors
///
/// - `AppError::Internal` when the mail cannot be sent.
pub(in crate::use_cases::identity) async fn mail_change_warning(
    mailer: &dyn Mailer,
    policy: &EmailChangePolicy,
    warning: ChangeWarning<'_>,
) -> Result<(), AppError> {
    let template = match warning.mailed_in {
        MailedIn::Tenant { .. } => EmailTemplateType::EmailChangeRequested,
        MailedIn::Organization => EmailTemplateType::OrgEmailChangeRequested,
    };
    let variables = warning_variables(policy, &warning);
    deliver(mailer, warning.to, warning.mailed_in, template, &variables)
        .await
        .or_internal()
}

/// What the warning names: the address asked for, the link that stops it,
/// how long that works, and where the request came from.
fn warning_variables(
    policy: &EmailChangePolicy,
    warning: &ChangeWarning<'_>,
) -> HashMap<TemplateVariable, String> {
    let cancel_url = warning.scope.action_url(
        &policy.base_url,
        "cancel-email-change",
        warning.change.cancel.expose(),
    );
    let requested_from = warning
        .requested_from
        .known()
        .map_or_else(|| "an unknown address".to_owned(), ToString::to_string);
    let new_email = warning.change.change.new_email().as_str().to_owned();
    HashMap::from([
        (TemplateVariable::UserEmail, new_email),
        (TemplateVariable::ActionUrl, cancel_url),
        (
            TemplateVariable::ExpiresAt,
            format!("{} hours", policy.lifetime.whole_seconds() / 3600),
        ),
        (TemplateVariable::IpAddress, requested_from),
    ])
}

/// Where the mails of a change just asked for go, and what they say.
pub(crate) struct ChangeMails<'a> {
    /// The address the account has now, which is warned.
    pub(crate) current: &'a Email,
    /// The plane the mails belong to.
    pub(crate) mailed_in: MailedIn<'a>,
    /// Where the links land.
    pub(crate) scope: &'a LinkScope,
    /// Where the request came from.
    pub(crate) requested_from: Fact<IpAddress>,
}

/// Warns the current address of `asked`, then mails the new one the link
/// that confirms it. The warning goes first, so no confirmation is sent
/// for a change the owner was not told of.
///
/// # Errors
///
/// - `AppError::Internal` when either mail cannot be sent.
pub(crate) async fn mail_change_links(
    mailer: &dyn Mailer,
    policy: &EmailChangePolicy,
    asked: &NewChange,
    mails: ChangeMails<'_>,
) -> Result<(), AppError> {
    let warning = ChangeWarning {
        to: mails.current,
        mailed_in: mails.mailed_in,
        change: asked,
        scope: mails.scope,
        requested_from: &mails.requested_from,
    };
    mail_change_warning(mailer, policy, warning).await?;
    let confirmation = ConfirmationMail {
        to: asked.change.new_email(),
        mailed_in: mails.mailed_in,
        raw_token: &asked.confirm,
        scope: mails.scope,
    };
    mail_confirmation(mailer, policy, confirmation).await
}

/// Tells the old address where the account's email went. Best effort: the
/// change has already landed.
pub(in crate::use_cases::identity) async fn notify_old_address(
    mailer: &dyn Mailer,
    old_email: &Email,
    mailed_in: MailedIn<'_>,
    new_email: &Email,
) {
    let variables = HashMap::from([(TemplateVariable::UserEmail, new_email.as_str().to_owned())]);
    let template = EmailTemplateType::EmailChanged;
    let sent = deliver(mailer, old_email, mailed_in, template, &variables);
    let _ = sent.await;
}

/// Sends `template` to `to` as the plane `mailed_in` writes it: in a
/// tenant's branding and the person's language, or as the platform's.
async fn deliver(
    mailer: &dyn Mailer,
    to: &Email,
    mailed_in: MailedIn<'_>,
    template: EmailTemplateType,
    variables: &HashMap<TemplateVariable, String>,
) -> Result<(), DomainError> {
    match mailed_in {
        MailedIn::Tenant { tenant, locale } => {
            let recipient = MailRecipient { email: to, locale };
            mailer
                .send_to_person(recipient, tenant, template, variables)
                .await
        }
        MailedIn::Organization => mailer.send(to, None, template, variables).await,
    }
}
