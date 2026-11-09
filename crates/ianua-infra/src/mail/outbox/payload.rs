//! A queued mail as its job carries it: written out in a versioned
//! envelope and sealed, since its values hold live links, and read back
//! through the domain's own checks.

use std::collections::HashMap;

use ianua_app::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use ianua_app::ports::shared::OutgoingMail;
use ianua_domain::domains::branding::config::MailSender;
use ianua_domain::domains::branding::email_template::{
    EmailHtmlBody, EmailTemplate, EmailTemplateRow, EmailTemplateType, EmailTextBody,
    MAX_SUBJECT_LENGTH, TemplateLocale, TemplateVariable,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, Label, Locale, Preference, SealedSecret, TenantId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::mail::outbox::MAIL_JOB;
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _, stored_words};

/// The shape a queued mail is written in.
const MAIL: Kept = Kept {
    entity: "queued mail",
    column: "payload",
    shape: 2,
};

/// What a refusal of a queued mail names.
const QUEUED: Stored = Stored("queued mail");

stored_words! {
    TemplateVariable as "mail value" {
        UserName => "user_name",
        UserEmail => "user_email",
        TenantName => "tenant_name",
        OrganizationName => "organization_name",
        ActionUrl => "action_url",
        ActionLink => "action_link",
        ExpiresAt => "expires_at",
        DeviceName => "device_name",
        IpAddress => "ip_address",
        RemainingCodes => "remaining_codes",
        ErasureDate => "erasure_date",
        RoleName => "role_name",
        ProviderName => "provider_name",
        OneTimeCode => "one_time_code",
        RequesterName => "requester_name",
        Reason => "reason",
        NoticeTitle => "notice_title",
        NoticeBody => "notice_body",
        Year => "year",
    }
}

/// A queued mail as it is written out.
#[derive(Serialize, Deserialize)]
struct MailShape {
    to: String,
    tenant: Option<Uuid>,
    template_type: String,
    template: Option<TemplateShape>,
    locale: Option<String>,
    sender: Option<String>,
    sender_name: Option<String>,
    values: Vec<ValueShape>,
}

/// The tenant's own template a queued mail is rendered from.
#[derive(Serialize, Deserialize)]
struct TemplateShape {
    locale: Option<String>,
    subject: Option<String>,
    body_html: Option<String>,
    body_text: Option<String>,
}

/// One value a queued mail is filled with.
#[derive(Serialize, Deserialize)]
struct ValueShape {
    name: String,
    value: String,
}

/// A queued mail, read back. It has no `Debug`: its values hold live
/// links.
pub(crate) struct QueuedMail {
    /// The address it goes to.
    pub(crate) to: Email,
    /// The tenant it is sent for, or none for mail of no tenant.
    pub(crate) tenant: Option<TenantId>,
    /// Which mail it is.
    pub(crate) template_type: EmailTemplateType,
    /// The tenant's template, or none for the platform's mail.
    pub(crate) template: Option<EmailTemplate>,
    /// The locale the recipient reads, or none when it is not known.
    pub(crate) locale: Option<Locale>,
    /// The tenant's address it is sent from, or none for the platform's.
    pub(crate) sender: Option<Email>,
    /// The name it is sent under, when the tenant set one.
    pub(crate) sender_name: Option<Label>,
    /// The values it is filled with.
    pub(crate) values: HashMap<TemplateVariable, String>,
}

impl QueuedMail {
    /// Whose address it goes out from.
    pub(crate) fn sender(&self) -> MailSender<'_> {
        self.sender
            .as_ref()
            .map_or(MailSender::Platform, MailSender::Tenant)
    }
}

/// Where a mail queued for `tenant`, or for no tenant, is sealed for: a
/// payload of the mail lane, owned by the tenant the job is queued for. A
/// payload moved into another tenant's job, or a job of another lane, does
/// not open there.
fn queued_for(tenant: Option<TenantId>) -> SealedFor {
    SealedFor::new(SealOwner::from(tenant), SealedField::QueuedMail, MAIL_JOB)
}

/// `mail`, written out and sealed with `secrets`, as its job's payload.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be written out or
/// sealed.
pub(crate) async fn sealed(
    mail: &OutgoingMail<'_>,
    secrets: &dyn SecretEncryptor,
) -> Result<String, DomainError> {
    let written = MAIL.seal(&shape_of(mail))?;
    let plain = Zeroizing::new(serde_json::to_vec(&written).map_err(DomainError::infra)?);
    let place = queued_for(mail.tenant.map(|tenant| **tenant));
    Ok(secrets.encrypt(&plain, &place).await?.as_str().to_owned())
}

/// The mail `payload`, of a job queued for `tenant`, holds, opened with
/// `secrets`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the payload does not open
/// for the job's tenant, is written in a shape this release does not read,
/// or holds a value that no longer passes the domain's checks.
pub(crate) async fn opened(
    payload: &str,
    tenant: Option<TenantId>,
    secrets: &dyn SecretEncryptor,
) -> Result<QueuedMail, DomainError> {
    let sealed = SealedSecret::new(payload).map_err(DomainError::infra)?;
    let plain = Zeroizing::new(secrets.decrypt(&sealed, &queued_for(tenant)).await?);
    let written: serde_json::Value = serde_json::from_slice(&plain).map_err(DomainError::infra)?;
    MAIL.open::<MailShape>(written)?.into_mail()
}

/// The shape `mail` is written in.
fn shape_of(mail: &OutgoingMail<'_>) -> MailShape {
    MailShape {
        to: mail.to.as_str().to_owned(),
        tenant: mail.tenant.map(|tenant| *tenant.as_uuid()),
        template_type: mail.template_type.word().to_owned(),
        template: mail
            .template
            .value()
            .map(|template| template_shape(template)),
        locale: mail.locale.map(|locale| locale.as_str().to_owned()),
        sender: match mail.sender {
            MailSender::Platform => None,
            MailSender::Tenant(address) => Some(address.as_str().to_owned()),
        },
        sender_name: mail.sender_name.map(|name| name.as_str().to_owned()),
        values: mail
            .variables
            .iter()
            .map(|(variable, value)| ValueShape {
                name: variable.word().to_owned(),
                value: value.clone(),
            })
            .collect(),
    }
}

/// The shape `template`'s parts are written in.
fn template_shape(template: &EmailTemplate) -> TemplateShape {
    TemplateShape {
        locale: template
            .locale()
            .locale()
            .map(|locale| locale.as_str().to_owned()),
        subject: template
            .subject()
            .value()
            .map(|subject| subject.as_str().to_owned()),
        body_html: template
            .body_html()
            .value()
            .map(|body| body.as_str().to_owned()),
        body_text: template
            .body_text()
            .value()
            .map(|body| body.as_str().to_owned()),
    }
}

impl MailShape {
    /// The mail this shape holds, through the domain's checks.
    fn into_mail(self) -> Result<QueuedMail, DomainError> {
        let template_type = QUEUED.choice(&self.template_type)?;
        let template = self
            .template
            .map(|template| template.into_template(template_type))
            .transpose()?;
        let values: HashMap<TemplateVariable, String> = self
            .values
            .into_iter()
            .map(|value| Ok((QUEUED.choice(&value.name)?, value.value)))
            .collect::<Result<_, DomainError>>()?;
        Ok(QueuedMail {
            to: QUEUED.value("recipient", Email::new(self.to))?,
            tenant: self.tenant.map(TenantId::from_uuid),
            template_type,
            template,
            locale: self
                .locale
                .map(|tag| QUEUED.value("recipient locale", Locale::new(tag)))
                .transpose()?,
            sender: self
                .sender
                .map(|address| QUEUED.value("sender", Email::new(address)))
                .transpose()?,
            sender_name: self
                .sender_name
                .map(|name| QUEUED.value("sender name", Label::new("sender_name", name)))
                .transpose()?,
            values,
        })
    }
}

impl TemplateShape {
    /// The tenant's template this shape holds, of `template_type`, through
    /// the domain's checks.
    fn into_template(self, template_type: EmailTemplateType) -> Result<EmailTemplate, DomainError> {
        let locale = self
            .locale
            .map(|tag| QUEUED.value("locale", Locale::new(tag)))
            .transpose()?;
        let subject = self
            .subject
            .map(|text| {
                QUEUED.value(
                    "subject",
                    Label::with_max_length("email_subject", text, MAX_SUBJECT_LENGTH),
                )
            })
            .transpose()?;
        let body_html = self
            .body_html
            .map(|body| QUEUED.value("HTML body", EmailHtmlBody::new(body)))
            .transpose()?;
        let body_text = self
            .body_text
            .map(|body| QUEUED.value("text body", EmailTextBody::new(body)))
            .transpose()?;
        EmailTemplate::reconstitute(EmailTemplateRow {
            template_type,
            locale: TemplateLocale::from_stored(locale),
            subject: Preference::from_stored(subject),
            body_html: Preference::from_stored(body_html),
            body_text: Preference::from_stored(body_text),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
    use ianua_domain::domains::branding::control::BrandingControl;
    use ianua_domain::test_support::authority::anyone_holding;
    use serde_json::json;

    use super::*;
    use crate::crypto::keys::KEY_BYTES;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};

    fn secrets() -> Arc<dyn SecretEncryptor> {
        Arc::new(AesGcmSecretEncryptor::new(
            SealingKey::new("k1", [5; KEY_BYTES]).unwrap(),
            Vec::new(),
        ))
    }

    fn reset_values() -> HashMap<TemplateVariable, String> {
        HashMap::from([
            (TemplateVariable::UserName, "Ann".to_owned()),
            (
                TemplateVariable::ActionUrl,
                "https://acme.test/reset?token=live-token".to_owned(),
            ),
        ])
    }

    fn acme_reset() -> EmailTemplate {
        EmailTemplate::custom(
            EmailTemplateType::PasswordReset,
            Preference::Own(Label::new("subject", "Reset for {{ user_name }}").unwrap()),
            Preference::Inherited,
            Preference::Own(EmailTextBody::new("Reset: {{ action_link }}").unwrap()),
            &BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
                BrandingAction::Update,
            )])),
        )
        .unwrap()
    }

    /// A queued mail written out and opened again is the same mail: its
    /// address, tenant, template, sender and values.
    #[tokio::test]
    async fn a_queued_mail_opens_to_itself() {
        let secrets = secrets();
        let (to, from) = (
            Email::new("ann@acme.test").unwrap(),
            Email::new("hello@acme.test").unwrap(),
        );
        let tenant = ScopedTenant::for_background(TenantId::new());
        let (template, values) = (acme_reset(), reset_values());
        let german = Locale::new("de-DE").unwrap();
        let mail = OutgoingMail {
            to: &to,
            tenant: Some(&tenant),
            template_type: EmailTemplateType::PasswordReset,
            template: Preference::Own(&template),
            locale: Some(&german),
            sender: MailSender::Tenant(&from),
            sender_name: None,
            variables: &values,
        };

        let payload = sealed(&mail, secrets.as_ref()).await.unwrap();
        let opened = opened(&payload, Some(*tenant), secrets.as_ref())
            .await
            .unwrap();

        assert_eq!(opened.to, to);
        assert_eq!(opened.tenant, Some(*tenant));
        assert_eq!(opened.template_type, EmailTemplateType::PasswordReset);
        assert!(opened.template.is_some());
        assert_eq!(opened.locale, Some(german));
        assert_eq!(opened.sender(), MailSender::Tenant(&from));
        assert_eq!(opened.values, values);
    }

    /// A sealed mail payload contains neither the live reset token nor the
    /// recipient's address in plain text.
    #[tokio::test]
    async fn the_payload_shows_no_link_and_no_address() {
        let secrets = secrets();
        let to = Email::new("ann@acme.test").unwrap();
        let values = reset_values();
        let mail = OutgoingMail {
            to: &to,
            tenant: None,
            template_type: EmailTemplateType::PasswordReset,
            template: Preference::Inherited,
            locale: None,
            sender: MailSender::Platform,
            sender_name: None,
            variables: &values,
        };

        let payload = sealed(&mail, secrets.as_ref()).await.unwrap();

        assert!(!payload.contains("live-token"));
        assert!(!payload.contains("ann@acme.test"));
    }

    /// Opening a malformed sealed-mail payload returns an infrastructure error.
    #[tokio::test]
    async fn a_payload_that_does_not_open_is_refused() {
        let opened = opened("s2.k1.not-a-sealed-mail", None, secrets().as_ref()).await;

        assert!(matches!(opened, Err(DomainError::Infrastructure(_))));
    }

    /// Mail sealed for Acme cannot be opened for another tenant or for the
    /// platform.
    #[tokio::test]
    async fn a_payload_moved_to_another_tenants_job_does_not_open() {
        let secrets = secrets();
        let to = Email::new("ann@acme.test").unwrap();
        let acme = ScopedTenant::for_background(TenantId::new());
        let values = reset_values();
        let mail = OutgoingMail {
            to: &to,
            tenant: Some(&acme),
            template_type: EmailTemplateType::PasswordReset,
            template: Preference::Inherited,
            locale: None,
            sender: MailSender::Platform,
            sender_name: None,
            variables: &values,
        };
        let payload = sealed(&mail, secrets.as_ref()).await.unwrap();

        let in_globex = opened(&payload, Some(TenantId::new()), secrets.as_ref()).await;
        let in_platform = opened(&payload, None, secrets.as_ref()).await;

        assert!(matches!(in_globex, Err(DomainError::Infrastructure(_))));
        assert!(matches!(in_platform, Err(DomainError::Infrastructure(_))));
    }

    /// The shape a queued mail is written in, pinned: a change to it raises
    /// the shape and adds a step reading the old one.
    #[test]
    fn the_written_shape_is_pinned() {
        let written = MAIL.seal(&sample_shape()).unwrap();

        assert_eq!(
            written,
            json!({"v": 2, "value": {
                "to": "ann@acme.test",
                "tenant": null,
                "template_type": "PasswordReset",
                "template": {
                    "locale": "de-DE",
                    "subject": "Reset",
                    "body_html": null,
                    "body_text": "Reset: {{ action_link }}",
                },
                "locale": "de-AT",
                "sender": null,
                "sender_name": null,
                "values": [{"name": "user_name", "value": "Ann"}],
            }})
        );
    }

    /// A queued reset with distinct template and recipient locales for the stored-shape check.
    fn sample_shape() -> MailShape {
        MailShape {
            to: "ann@acme.test".to_owned(),
            tenant: None,
            template_type: "PasswordReset".to_owned(),
            template: Some(TemplateShape {
                locale: Some("de-DE".to_owned()),
                subject: Some("Reset".to_owned()),
                body_html: None,
                body_text: Some("Reset: {{ action_link }}".to_owned()),
            }),
            locale: Some("de-AT".to_owned()),
            sender: None,
            sender_name: None,
            values: vec![ValueShape {
                name: "user_name".to_owned(),
                value: "Ann".to_owned(),
            }],
        }
    }

    /// Every value is written as its placeholder's own name, so a stored
    /// mail reads the same whatever the variants are called in code.
    #[test]
    fn every_value_is_written_as_its_placeholder() {
        for variable in [
            TemplateVariable::UserName,
            TemplateVariable::ActionUrl,
            TemplateVariable::OneTimeCode,
            TemplateVariable::Year,
        ] {
            assert_eq!(variable.word(), variable.key());
        }
    }
}
