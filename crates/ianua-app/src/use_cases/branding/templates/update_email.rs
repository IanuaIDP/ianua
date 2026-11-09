//! Update email template: the tenant writes one of its transactional mails
//! in its own words.

use std::sync::Arc;

use ianua_domain::domains::branding::control::BrandingControl;
use ianua_domain::domains::branding::email_template::{
    EmailHtmlBody, EmailTemplate, EmailTemplateType, EmailTextBody, TemplateLocale, TemplateSlot,
};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, Preference};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::branding::EmailTemplateStore;
use crate::use_case::Command;

/// Request to customize an email template.
pub struct UpdateEmailTemplateRequest {
    /// Which email type to customize.
    pub template_type: EmailTemplateType,
    /// Which recipients this version is written for: one locale, or every
    /// locale without a version of its own.
    pub locale: TemplateLocale,
    /// Custom subject line, or the platform's.
    pub subject: Preference<Label>,
    /// Custom HTML body, or the platform's.
    pub body_html: Preference<EmailHtmlBody>,
    /// Custom plain-text body, or the platform's.
    pub body_text: Preference<EmailTextBody>,
}

/// The ports [`UpdateEmailTemplateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateEmailTemplatePorts {
    /// The tenant's custom templates.
    pub template_store: Arc<dyn EmailTemplateStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Saves a tenant's own version of a transactional email.
pub struct UpdateEmailTemplateUseCase {
    ports: UpdateEmailTemplatePorts,
}

impl UpdateEmailTemplateUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdateEmailTemplatePorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateEmailTemplateUseCase {
    type Caller = CallerContext;
    type Input = UpdateEmailTemplateRequest;
    type Output = Result<(), AppError>;

    /// Saves the tenant's template for one email type and locale, replacing
    /// the one it wrote for them before, and records `branding.updated`,
    /// naming the email.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change branding.
    /// - `AppError::Domain` when the subject or a body holds template code
    ///   beyond the placeholders the email fills, or places the link where
    ///   it could be taken apart.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateEmailTemplateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let slot = TemplateSlot {
            template_type: request.template_type,
            locale: request.locale,
        };
        let mut template = EmailTemplate::custom(
            slot,
            request.subject,
            request.body_html,
            request.body_text,
            &BrandingControl::new(&authority),
        )
        .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        self.ports
            .template_store
            .save(&tenant, &template)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), template.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::email_template::MAX_SUBJECT_LENGTH;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::branding::FakeEmailTemplateStore;
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: UpdateEmailTemplateUseCase,
        store: Arc<FakeEmailTemplateStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn new() -> Self {
            Self::with(UpdateEmailTemplatePorts::fakes())
        }

        fn refusing(authorities: FakeTenantAuthorities) -> Self {
            Self::with(UpdateEmailTemplatePorts {
                tenant_authorities: Arc::new(authorities),
                ..UpdateEmailTemplatePorts::fakes()
            })
        }

        fn with(ports: UpdateEmailTemplatePorts) -> Self {
            let store = Arc::new(FakeEmailTemplateStore::empty());
            Self {
                uc: UpdateEmailTemplateUseCase::new(UpdateEmailTemplatePorts {
                    template_store: store.clone(),
                    ..ports
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn update_as(
            &self,
            ctx: &CallerContext,
            request: UpdateEmailTemplateRequest,
        ) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(ctx, &test_auditor(self.audit.clone()), request),
            )
        }

        fn update(&self, request: UpdateEmailTemplateRequest) -> Result<(), AppError> {
            self.update_as(&test_ctx(), request)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn subject(s: &str) -> Label {
        Label::with_max_length("email_subject", s, MAX_SUBJECT_LENGTH).unwrap()
    }

    fn subject_only(s: &str) -> UpdateEmailTemplateRequest {
        UpdateEmailTemplateRequest {
            template_type: EmailTemplateType::Verification,
            locale: TemplateLocale::Fallback,
            subject: Preference::Own(subject(s)),
            body_html: Preference::Inherited,
            body_text: Preference::Inherited,
        }
    }

    /// Fay writes Acme's verification mail with its own subject and bodies.
    /// It is saved and the change recorded.
    #[test]
    fn update_template_and_audits() {
        let setup = Setup::new();
        let request = UpdateEmailTemplateRequest {
            template_type: EmailTemplateType::Verification,
            locale: TemplateLocale::Fallback,
            subject: Preference::Own(subject("Verify your email")),
            body_html: Preference::Own(EmailHtmlBody::new("<h1>Hello {{user_name}}</h1>").unwrap()),
            body_text: Preference::Own(EmailTextBody::new("Hello {{user_name}}").unwrap()),
        };

        setup.update(request).unwrap();

        assert_eq!(setup.store.count(), 1);
        assert_eq!(setup.recorded(), vec!["branding.updated"]);
    }

    /// Fay writes the verification mail for everyone, then again for German
    /// readers. Acme keeps both, one per locale.
    #[test]
    fn a_template_for_a_locale_is_kept_beside_the_one_for_everyone() {
        let setup = Setup::new();
        setup.update(subject_only("Verify your email")).unwrap();
        let german = UpdateEmailTemplateRequest {
            locale: TemplateLocale::For(ianua_domain::types::Locale::new("de-DE").unwrap()),
            ..subject_only("Bestätigen Sie Ihre E-Mail")
        };

        setup.update(german).unwrap();

        assert_eq!(setup.store.count(), 2);
    }

    /// Fay changes the verification subject twice. Acme keeps one template,
    /// with the second subject.
    #[test]
    fn update_template_overwrites_existing() {
        let setup = Setup::new();
        setup.update(subject_only("First")).unwrap();

        setup.update(subject_only("Second")).unwrap();

        let saved = block_on(setup.store.find(
            &test_ctx().tenant(),
            &EmailTemplateType::Verification.into(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(setup.store.count(), 1);
        assert_eq!(saved.subject().value().map(Label::as_str), Some("Second"));
    }

    /// A template that transforms the action link beyond the supported
    /// placeholders is refused without saving a template or audit event.
    #[test]
    fn template_code_beyond_the_placeholders_is_refused() {
        let setup = Setup::new();
        let request = UpdateEmailTemplateRequest {
            body_text: Preference::Own(
                EmailTextBody::new("Go to {{ action_link | replace('a', 'b') }}").unwrap(),
            ),
            ..subject_only("Verify")
        };

        let result = setup.update(request);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.store.count(), 0);
        assert!(setup.recorded().is_empty());
    }

    /// Without the branding update right, changing the verification email
    /// is forbidden and no template is saved.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let setup = Setup::refusing(FakeTenantAuthorities::holding(&[]));

        let result = setup.update(subject_only("Verify"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.store.count(), 0);
    }

    /// A signed-out session cannot change the verification email template.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::refusing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.update(subject_only("Verify"));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot change a tenant's
    /// email template, and no template is saved.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::new();

        let result = setup.update_as(&operator_without_grant(), subject_only("Verify"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.store.count(), 0);
    }
}
