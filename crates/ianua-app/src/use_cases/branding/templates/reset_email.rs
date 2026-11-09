//! Reset email template: the tenant goes back to the platform's mail.

use std::sync::Arc;

use ianua_domain::domains::branding::control::BrandingControl;
use ianua_domain::domains::branding::email_template::TemplateSlot;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::branding::EmailTemplateStore;
use crate::use_case::Command;
use crate::use_cases::branding::lookup::existing_template;

/// The ports [`ResetEmailTemplateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetEmailTemplatePorts {
    /// The tenant's custom templates.
    pub template_store: Arc<dyn EmailTemplateStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes a tenant's own version of a transactional email.
pub struct ResetEmailTemplateUseCase {
    ports: ResetEmailTemplatePorts,
}

impl ResetEmailTemplateUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ResetEmailTemplatePorts) -> Self {
        Self { ports }
    }
}

impl Command for ResetEmailTemplateUseCase {
    type Caller = CallerContext;
    type Input = TemplateSlot;
    type Output = Result<(), AppError>;

    /// Removes the tenant's template in `slot`, so its recipients get the
    /// next template that fits them or the platform's mail again, and
    /// records `branding.updated`, naming the email.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change branding.
    /// - `AppError::NotFound` when the tenant has no template of its own for
    ///   this email and locale.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        slot: TemplateSlot,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = BrandingControl::new(&authority);
        control.ensure_may_change().map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut template =
            existing_template(self.ports.template_store.as_ref(), &tenant, &slot).await?;
        template.remove(&control).map_err(AppError::from_domain)?;
        self.ports
            .template_store
            .delete(&tenant, &slot)
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
    use ianua_domain::domains::branding::email_template::{
        EmailHtmlBody, EmailTemplate, EmailTemplateRow, EmailTemplateType, TemplateLocale,
    };
    use ianua_domain::types::{Locale, Preference};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::branding::FakeEmailTemplateStore;
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: ResetEmailTemplateUseCase,
        store: Arc<FakeEmailTemplateStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(ports: ResetEmailTemplatePorts) -> Self {
            let store = Arc::new(FakeEmailTemplateStore::empty());
            Self {
                uc: ResetEmailTemplateUseCase::new(ResetEmailTemplatePorts {
                    template_store: store.clone(),
                    ..ports
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::with(ResetEmailTemplatePorts::fakes())
        }

        fn refusing(authorities: FakeTenantAuthorities) -> Self {
            Self::with(ResetEmailTemplatePorts {
                tenant_authorities: Arc::new(authorities),
                ..ResetEmailTemplatePorts::fakes()
            })
        }

        fn seeded_for(self, locale: TemplateLocale) -> Self {
            let template = EmailTemplate::reconstitute(EmailTemplateRow {
                template_type: EmailTemplateType::Verification,
                locale,
                subject: Preference::Inherited,
                body_html: Preference::Own(EmailHtmlBody::new("<h1>Custom</h1>").unwrap()),
                body_text: Preference::Inherited,
            })
            .unwrap();
            block_on(self.store.save(&test_ctx().tenant(), &template)).unwrap();
            self
        }

        fn seeded(self) -> Self {
            self.seeded_for(TemplateLocale::Fallback)
        }

        fn reset_slot(&self, ctx: &CallerContext, slot: TemplateSlot) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(ctx, &test_auditor(self.audit.clone()), slot),
            )
        }

        fn reset_as(&self, ctx: &CallerContext) -> Result<(), AppError> {
            self.reset_slot(ctx, EmailTemplateType::Verification.into())
        }

        fn reset(&self) -> Result<(), AppError> {
            self.reset_as(&test_ctx())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Fay resets Acme's verification mail. Its own version is gone and the
    /// change recorded.
    #[test]
    fn reset_template_and_audits() {
        let setup = Setup::new().seeded();

        setup.reset().unwrap();

        assert_eq!(setup.store.count(), 0);
        assert_eq!(setup.recorded(), vec!["branding.updated"]);
    }

    /// Acme wrote its verification mail for everyone and again in German.
    /// Fay resets the German one. The one for everyone stays.
    #[test]
    fn resetting_one_locale_keeps_the_others() {
        let german = TemplateLocale::For(Locale::new("de-DE").unwrap());
        let setup = Setup::new().seeded().seeded_for(german.clone());

        setup
            .reset_slot(
                &test_ctx(),
                TemplateSlot {
                    template_type: EmailTemplateType::Verification,
                    locale: german,
                },
            )
            .unwrap();

        assert_eq!(setup.store.count(), 1);
    }

    /// Acme never wrote its own verification mail. Resetting it is not
    /// found, and nothing is recorded.
    #[test]
    fn reset_nonexistent_template_returns_not_found() {
        let setup = Setup::new();

        let result = setup.reset();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Without the branding update right, resetting a custom email is
    /// forbidden and the template remains stored.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let setup = Setup::refusing(FakeTenantAuthorities::holding(&[])).seeded();

        let result = setup.reset();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.store.count(), 1);
    }

    /// A signed-out session cannot reset a custom email template.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::refusing(FakeTenantAuthorities::refusing(Refusal::SignedOut)).seeded();

        let result = setup.reset();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot reset a tenant's
    /// custom email, and its template remains stored.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::new().seeded();

        let result = setup.reset_as(&operator_without_grant());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.store.count(), 1);
    }
}
