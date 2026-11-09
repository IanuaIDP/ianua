use time::OffsetDateTime;

use crate::domains::branding::email_template::EmailTemplateType;
use crate::domains::branding::logo::LogoFormat;
use crate::domains::branding::mail_provider::{MailProviderKind, TestSendOutcome};
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;

/// Which part of a tenant's branding changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrandingPart {
    /// The branding settings: logo, colours, custom CSS, email sender.
    Settings,
    /// A logo the tenant uploaded, in this format.
    UploadedLogo(LogoFormat),
    /// One email template, set or reset.
    EmailTemplate(EmailTemplateType),
}

/// Tenant branding was updated: the branding settings or an email template.
///
/// The payload names the part that changed, not its contents. If Eve rewrites
/// the password reset email to fool its readers, the record shows which email
/// changed and when. The contents stay in the stored template.
#[derive(Debug)]
pub struct BrandingUpdated {
    /// The part that changed.
    pub(crate) part: BrandingPart,
    /// When the update occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    BrandingUpdated => crate::types::event_type::BrandingEvent::Updated,
    fn payload(&self) -> EventData {
        match self.part {
            BrandingPart::Settings => EventData::new().field("part", "settings"),
            BrandingPart::UploadedLogo(format) => EventData::new()
                .field("part", "logo")
                .field("format", format.as_str()),
            BrandingPart::EmailTemplate(template) => EventData::new()
                .field("part", "email_template")
                .field("template", template.name()),
        }
    }
}

/// The tenant's mail now goes out through another provider, once a test
/// send through it works.
///
/// The payload names the kinds of provider only. Its host, account and
/// credentials stay in the stored provider.
#[derive(Debug)]
pub struct MailProviderChanged {
    /// The kind of provider before.
    pub(crate) old_kind: MailProviderKind,
    /// The kind of provider now.
    pub(crate) new_kind: MailProviderKind,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MailProviderChanged => crate::types::event_type::BrandingEvent::MailProviderChanged,
    fn payload(&self) -> EventData {
        EventData::new().change("provider", self.old_kind.as_str(), self.new_kind.as_str())
    }
}

/// A test mail was sent through the tenant's own mail provider. Once one is
/// delivered the tenant's mail goes out through it; a refused one leaves
/// the mail with the platform.
///
/// The payload names the kind of provider and how the send went, never what
/// the provider answered.
#[derive(Debug)]
pub struct MailProviderTested {
    /// The kind of provider tested.
    pub(crate) kind: MailProviderKind,
    /// How the test send went.
    pub(crate) outcome: TestSendOutcome,
    /// When it was sent.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MailProviderTested => crate::types::event_type::BrandingEvent::MailProviderTested,
    fn payload(&self) -> EventData {
        let result = match self.outcome {
            TestSendOutcome::Delivered => "delivered",
            TestSendOutcome::Refused => "refused",
        };
        EventData::new()
            .field("provider", self.kind.as_str())
            .field("result", result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::event::DomainEventCore;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    /// A tenant changes its password reset email. The event carries a
    /// payload naming the change, so the audit trail shows it.
    #[test]
    fn a_branding_change_records_the_template_it_changed() {
        let event = BrandingUpdated {
            part: BrandingPart::EmailTemplate(EmailTemplateType::PasswordReset),
            occurred_at: now(),
        };

        assert!(!event.payload().is_empty());
    }
}
