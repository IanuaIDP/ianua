//! List email templates: the transactional mails a tenant wrote itself.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
use ianua_domain::domains::branding::email_template::EmailTemplate;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::branding::{EmailTemplateSortField, EmailTemplateStore};
use crate::use_case::Query;

/// Which page of the tenant's customized templates to list, and in what
/// order.
pub struct ListEmailTemplatesRequest {
    /// The field and direction to order by.
    pub sort: SortOrder<EmailTemplateSortField>,
    /// Which page of the ordered templates to return.
    pub page: PageRequest,
}

/// The ports [`ListEmailTemplatesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListEmailTemplatesPorts {
    /// The tenant's custom templates.
    pub template_store: Arc<dyn EmailTemplateStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's custom email templates.
pub struct ListEmailTemplatesUseCase {
    ports: ListEmailTemplatesPorts,
}

impl ListEmailTemplatesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListEmailTemplatesPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListEmailTemplatesUseCase {
    type Caller = CallerContext;
    type Input = ListEmailTemplatesRequest;
    type Output = Result<Page<EmailTemplate>, AppError>;

    /// One page of the tenant's customized templates, in the order asked.
    /// Emails sent as the platform wrote them are not listed.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view branding.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListEmailTemplatesRequest,
    ) -> Result<Page<EmailTemplate>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Branding(BrandingAction::View))
            .map_err(AppError::from_domain)?;
        let ListEmailTemplatesRequest { sort, page } = request;
        self.ports
            .template_store
            .list_all(&ctx.tenant(), &sort, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::email_template::{
        EmailHtmlBody, EmailTemplateRow, EmailTemplateType, TemplateLocale,
    };
    use ianua_domain::types::Preference;

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::branding::FakeEmailTemplateStore;
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::{block_on, test_ctx};

    fn request(sort: SortOrder<EmailTemplateSortField>) -> ListEmailTemplatesRequest {
        ListEmailTemplatesRequest {
            sort,
            page: PageRequest::default(),
        }
    }

    fn store_with(kinds: &[EmailTemplateType]) -> Arc<FakeEmailTemplateStore> {
        let store = Arc::new(FakeEmailTemplateStore::empty());
        for kind in kinds {
            let template = EmailTemplate::reconstitute(EmailTemplateRow {
                template_type: *kind,
                locale: TemplateLocale::Fallback,
                subject: Preference::Inherited,
                body_html: Preference::Own(EmailHtmlBody::new("<h1>Custom</h1>").unwrap()),
                body_text: Preference::Inherited,
            })
            .unwrap();
            block_on(store.save(&test_ctx().tenant(), &template)).unwrap();
        }
        store
    }

    fn listing(store: Arc<FakeEmailTemplateStore>) -> ListEmailTemplatesUseCase {
        ListEmailTemplatesUseCase::new(ListEmailTemplatesPorts {
            template_store: store,
            ..ListEmailTemplatesPorts::fakes()
        })
    }

    fn refusing(authorities: FakeTenantAuthorities) -> ListEmailTemplatesUseCase {
        ListEmailTemplatesUseCase::new(ListEmailTemplatesPorts {
            template_store: store_with(&[EmailTemplateType::Verification]),
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// Acme wrote none of its mails. Ann sees an empty list.
    #[test]
    fn no_customized_templates_returns_empty_page() {
        let uc = listing(store_with(&[]));

        let page = block_on(uc.execute(&test_ctx(), request(SortOrder::default()))).unwrap();

        assert!(page.is_empty());
        assert_eq!(page.items.len(), 0);
    }

    /// Acme wrote its own verification mail. Ann sees it listed.
    #[test]
    fn list_returns_customized() {
        let uc = listing(store_with(&[EmailTemplateType::Verification]));

        let page = block_on(uc.execute(&test_ctx(), request(SortOrder::default()))).unwrap();

        assert_eq!(page.items.len(), 1);
    }

    /// Ann orders Acme's templates by email type, last first.
    #[test]
    fn sorts_by_template_type_descending() {
        let uc = listing(store_with(&[
            EmailTemplateType::Verification,
            EmailTemplateType::PasswordReset,
        ]));
        let sort = SortOrder::single(Sort::descending(EmailTemplateSortField::TemplateType));

        let page = block_on(uc.execute(&test_ctx(), request(sort))).unwrap();

        assert_eq!(
            page.items[0].template_type(),
            EmailTemplateType::Verification
        );
        assert_eq!(
            page.items[1].template_type(),
            EmailTemplateType::PasswordReset
        );
    }

    /// Listing custom email templates requires the branding view right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let uc = refusing(FakeTenantAuthorities::holding(&[]));

        let result = block_on(uc.execute(&test_ctx(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list custom email templates.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let uc = refusing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = block_on(uc.execute(&test_ctx(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot list a tenant's
    /// custom email templates.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let uc = listing(store_with(&[EmailTemplateType::Verification]));

        let result = block_on(uc.execute(&operator_without_grant(), request(SortOrder::default())));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
