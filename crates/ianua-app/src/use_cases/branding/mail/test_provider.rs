//! Test mail provider: send one mail through the provider a tenant named,
//! to the person asking, and keep how it went.
//!
//! A provider is used for the tenant's real mail only once a test send
//! through it worked. A failed one leaves the mail with the platform, so a
//! mistyped key never stops people getting their reset links.

use std::sync::Arc;

use ianua_domain::domains::branding::control::BrandingControl;
use ianua_domain::domains::branding::mail_provider::{MailProvider, TestSendOutcome};
use ianua_domain::domains::branding::renderer::RenderedEmail;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::Email;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::branding::{
    AddressedMail, BrandingStore, MailProviderTransport, TenantMailProviderStore,
    mail_credential_place,
};
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::organization::OrgUserStore;
use crate::services::branding::sender::{SentAs, TenantSenders};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::branding::lookup::{caller_address, current_mail_provider};

/// The subject of every test mail.
const TEST_SUBJECT: &str = "Your mail provider works";

/// The body of every test mail.
const TEST_BODY: &str = "This test mail went out through the mail provider your tenant named. \
     Your tenant's mail now goes out through it.";

/// The ports [`TestMailProviderUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct TestMailProviderPorts {
    /// Where each tenant's mail provider is kept.
    pub provider_store: Arc<dyn TenantMailProviderStore>,
    /// Delivers mail through a named provider, with a timeout.
    pub transport: Arc<dyn MailProviderTransport>,
    /// What a caller holds in their tenant, and who is signed in.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Organization members, for the address of a member asking.
    pub org_users: Arc<dyn OrgUserStore>,
    /// The tenant's sender address and name.
    pub branding: Arc<dyn BrandingStore>,
    /// The domains the sender address must be on.
    pub domains: Arc<dyn RegisteredDomainStore>,
}

/// Sends a test mail through the tenant's named provider.
pub struct TestMailProviderUseCase {
    ports: TestMailProviderPorts,
    senders: TenantSenders,
}

impl TestMailProviderUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: TestMailProviderPorts) -> Self {
        let senders = TenantSenders::new(Arc::clone(&ports.branding), Arc::clone(&ports.domains));
        Self { ports, senders }
    }

    /// Whether the test mail to `to` went through `provider`, the one
    /// `tenant` named, from the address the tenant's mail goes out from, as
    /// `sent_as` says. A refusal is logged by kind only, never with what the
    /// provider said.
    async fn sent(
        &self,
        tenant: &ScopedTenant,
        provider: &MailProvider,
        to: &Email,
        sent_as: &SentAs,
    ) -> TestSendOutcome {
        let rendered = RenderedEmail::text_only(TEST_SUBJECT, TEST_BODY);
        let mail = AddressedMail {
            to,
            sender: sent_as.sender(),
            sender_name: sent_as.sender_name(),
            rendered: &rendered,
        };
        let credential = mail_credential_place(Some(**tenant));
        let delivered = self
            .ports
            .transport
            .deliver(provider, &credential, &mail)
            .await;
        let Err(error) = delivered else {
            return TestSendOutcome::Delivered;
        };
        tracing::warn!(kind = provider.kind().as_str(), %error, "mail provider test send refused");
        TestSendOutcome::Refused
    }
}

impl Command for TestMailProviderUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<TestSendOutcome, AppError>;

    /// Sends one test mail through the provider the tenant `ctx` acts in
    /// named, to the person asking, keeps how it went, records
    /// `branding.mail_provider_tested` and returns it. Once one is delivered
    /// the tenant's mail goes out through the provider, so when that
    /// happened stays on record.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change branding, or
    ///   came as an operator, who has no address to send to.
    /// - `AppError::Conflict` when the tenant sends through the platform's
    ///   own mail, which is not tested per tenant.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<TestSendOutcome, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        BrandingControl::new(&authority)
            .ensure_may_change()
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.provider_store.as_ref();
        let mut named = current_mail_provider(store, &tenant).await?;
        ensure_own_provider(named.provider())?;
        let to = caller_address(
            self.ports.tenant_authorities.as_ref(),
            self.ports.org_users.as_ref(),
            ctx,
        )
        .await?;
        let sent_as = self.senders.of(&tenant).await.or_internal()?;
        let outcome = self.sent(&tenant, named.provider(), &to, &sent_as).await;
        named
            .record_test_send(outcome)
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &named).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), named.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(outcome)
    }
}

/// Refuses testing the platform's own mail, which is not tested per
/// tenant, before any mail goes out.
fn ensure_own_provider(provider: &MailProvider) -> Result<(), AppError> {
    if *provider == MailProvider::Platform {
        return Err(AppError::Conflict(message!(
            "branding-the-platform-s-own-mail-is",
            "the platform's own mail is not tested per tenant"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
    use ianua_domain::domains::branding::config::TenantBranding;
    use ianua_domain::domains::branding::mail_provider::{
        MailProviderKind, ProviderCheck, TenantMailProvider, TenantMailProviderRow,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::DomainName;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::branding::{
        FakeBrandingStore, FakeMailProviderTransport, FakeTenantMailProviderStore,
        sendgrid_provider,
    };
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::routing::verified_domains;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: TestMailProviderUseCase,
        providers: Arc<FakeTenantMailProviderStore>,
        transport: Arc<FakeMailProviderTransport>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn over(
            providers: FakeTenantMailProviderStore,
            transport: FakeMailProviderTransport,
            authorities: FakeTenantAuthorities,
        ) -> Self {
            let providers = Arc::new(providers);
            let transport = Arc::new(transport);
            Self {
                uc: TestMailProviderUseCase::new(TestMailProviderPorts {
                    provider_store: providers.clone(),
                    transport: transport.clone(),
                    tenant_authorities: Arc::new(authorities),
                    ..TestMailProviderPorts::fakes()
                }),
                providers,
                transport,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn naming_sendgrid(transport: FakeMailProviderTransport) -> Self {
            Self::over(
                FakeTenantMailProviderStore::holding(test_ctx().tenant_id(), untested_sendgrid()),
                transport,
                FakeTenantAuthorities::holding_everything(),
            )
        }

        fn test_as(&self, ctx: &CallerContext) -> Result<TestSendOutcome, AppError> {
            let auditor = test_auditor(self.audit.clone());
            block_on(self.uc.execute(ctx, &auditor, ()))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn check(&self) -> ProviderCheck {
            self.providers
                .stored(test_ctx().tenant_id())
                .unwrap()
                .check()
        }
    }

    /// Acme's SendGrid account, named and not yet tested.
    fn untested_sendgrid() -> TenantMailProvider<ResolvedTenant> {
        TenantMailProvider::reconstitute(TenantMailProviderRow {
            provider: sendgrid_provider(),
            check: ProviderCheck::Unverified,
            updated_at: clock::now(),
        })
        .unwrap()
    }

    /// Ann tests Acme's SendGrid. The mail reaches her through SendGrid,
    /// Acme's mail now goes out through it, and the test is recorded.
    #[test]
    fn a_delivered_test_puts_the_provider_to_use() {
        let setup = Setup::naming_sendgrid(FakeMailProviderTransport::delivering());

        let outcome = setup.test_as(&test_ctx()).unwrap();

        assert_eq!(outcome, TestSendOutcome::Delivered);
        assert_eq!(setup.transport.delivered()[0].0, MailProviderKind::SendGrid);
        assert!(matches!(setup.check(), ProviderCheck::Verified { .. }));
        assert_eq!(setup.recorded(), ["branding.mail_provider_tested"]);
    }

    /// With a sender on the tenant's verified domain, the provider test
    /// uses that sender address for its outgoing mail.
    #[test]
    fn the_test_goes_out_from_the_tenants_own_address() {
        let tenant = test_ctx().tenant();
        let domains = verified_domains(&tenant, &["acme.com"]);
        let name = DomainName::new("acme.com").unwrap();
        let acme_com = block_on(domains.find_by_tenant_and_name(&tenant, &name))
            .unwrap()
            .unwrap();
        let mut branding = TenantBranding::default_branding();
        let editor = BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::Update,
        )]));
        let hello = Email::new("hello@acme.com").unwrap();
        branding
            .send_from(hello.clone(), &acme_com, &editor)
            .unwrap();
        let transport = Arc::new(FakeMailProviderTransport::delivering());
        let uc = TestMailProviderUseCase::new(TestMailProviderPorts {
            provider_store: Arc::new(FakeTenantMailProviderStore::holding(
                test_ctx().tenant_id(),
                untested_sendgrid(),
            )),
            transport: transport.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
            branding: Arc::new(FakeBrandingStore::holding(*tenant, branding)),
            domains,
            ..TestMailProviderPorts::fakes()
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));

        block_on(uc.execute(&test_ctx(), &auditor, ())).unwrap();

        assert_eq!(transport.senders(), [Some(hello)]);
    }

    /// SendGrid refuses the key Ann typed. The test is kept as failed,
    /// Acme's mail stays with the platform, and the refusal is recorded.
    #[test]
    fn a_refused_test_leaves_mail_with_the_platform() {
        let setup = Setup::naming_sendgrid(FakeMailProviderTransport::refusing());

        let outcome = setup.test_as(&test_ctx()).unwrap();

        assert_eq!(outcome, TestSendOutcome::Refused);
        let stored = setup.providers.stored(test_ctx().tenant_id()).unwrap();
        assert_eq!(*stored.delivers_through(), MailProvider::Platform);
        let tested = setup.audit.payload_of("branding.mail_provider_tested");
        assert_eq!(tested.get("result"), Some("refused"));
    }

    /// Acme sends through the platform's own mail. There is nothing of its
    /// own to test, and nothing is sent.
    #[test]
    fn the_platforms_own_mail_is_not_tested() {
        let setup = Setup::over(
            FakeTenantMailProviderStore::empty(),
            FakeMailProviderTransport::delivering(),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = setup.test_as(&test_ctx());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.transport.delivered().is_empty());
    }

    /// The branding view right does not permit testing a provider; no mail
    /// is sent and the provider remains unverified.
    #[test]
    fn a_caller_who_may_only_view_branding_is_refused() {
        let setup = Setup::over(
            FakeTenantMailProviderStore::holding(test_ctx().tenant_id(), untested_sendgrid()),
            FakeMailProviderTransport::delivering(),
            FakeTenantAuthorities::holding(&[SystemPermission::Branding(BrandingAction::View)]),
        );

        let result = setup.test_as(&test_ctx());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.transport.delivered().is_empty());
        assert_eq!(setup.check(), ProviderCheck::Unverified);
    }

    /// A signed-out session cannot test the provider, and no mail is sent.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::over(
            FakeTenantMailProviderStore::holding(test_ctx().tenant_id(), untested_sendgrid()),
            FakeMailProviderTransport::delivering(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.test_as(&test_ctx());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.transport.delivered().is_empty());
    }

    /// An operator without an impersonation grant cannot test a tenant's
    /// provider, and no mail is sent.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::naming_sendgrid(FakeMailProviderTransport::delivering());

        let result = setup.test_as(&operator_without_grant());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.transport.delivered().is_empty());
    }
}
