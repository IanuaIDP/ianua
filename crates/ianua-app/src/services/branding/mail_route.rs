//! Sending a tenant's mail through the provider it goes out through now.
//!
//! A tenant that named its own mail provider has its password resets,
//! invitations and sign-in links sent from its own account, but only once a
//! test send through that provider worked
//! ([`TenantMailProvider::delivers_through`]). Until then, and for mail of
//! no tenant, the platform's own mail sends it, so a mistyped password
//! never stops people getting their reset links.

use std::sync::Arc;

use ianua_domain::domains::branding::mail_provider::{MailProvider, TenantMailProvider};
use ianua_domain::shared::errors::DomainError;

use crate::ports::branding::{
    AddressedMail, MailProviderTransport, TenantMailProviderStore, mail_credential_place,
};
use crate::tenancy::ScopedTenant;

/// Sends mail through the provider each tenant's mail goes out through.
///
/// The mail adapter sends every composed email through this, rather than
/// straight to one deployment-wide transport.
pub struct TenantMailRoute {
    providers: Arc<dyn TenantMailProviderStore>,
    transport: Arc<dyn MailProviderTransport>,
}

impl TenantMailRoute {
    /// A route reading each tenant's provider from `providers` and
    /// delivering through `transport`.
    #[must_use]
    pub fn new(
        providers: Arc<dyn TenantMailProviderStore>,
        transport: Arc<dyn MailProviderTransport>,
    ) -> Self {
        Self {
            providers,
            transport,
        }
    }

    /// Delivers `mail` through the provider `tenant`'s mail goes out
    /// through now, or the platform's own mail for mail of no tenant.
    ///
    /// # Errors
    ///
    /// - `DomainError::Infrastructure` when the tenant's provider cannot be
    ///   read, or the provider does not take the mail.
    /// - The errors of [`MailProviderTransport::deliver`].
    pub async fn send(
        &self,
        tenant: Option<&ScopedTenant>,
        mail: &AddressedMail<'_>,
    ) -> Result<(), DomainError> {
        let provider = self.provider_for(tenant).await?;
        let credential = mail_credential_place(tenant.map(|tenant| **tenant));
        self.transport.deliver(&provider, &credential, mail).await
    }

    /// The provider `tenant`'s mail goes out through now.
    async fn provider_for(
        &self,
        tenant: Option<&ScopedTenant>,
    ) -> Result<MailProvider, DomainError> {
        let Some(tenant) = tenant else {
            return Ok(MailProvider::Platform);
        };
        let named = self.providers.find(tenant).await?;
        Ok(named
            .as_ref()
            .map(TenantMailProvider::delivers_through)
            .cloned()
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::config::MailSender;
    use ianua_domain::domains::branding::mail_provider::{
        MailProviderKind, ProviderCheck, TenantMailProviderRow, TestSendOutcome,
    };
    use ianua_domain::domains::branding::renderer::RenderedEmail;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::types::Email;

    use super::*;
    use crate::test_support::branding::{
        FakeMailProviderTransport, FakeTenantMailProviderStore, sendgrid_provider,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Acme's provider as it stands after naming SendGrid, tested as
    /// `tested` says.
    fn acme_sendgrid(tested: Option<TestSendOutcome>) -> TenantMailProvider<ResolvedTenant> {
        let mut provider = TenantMailProvider::reconstitute(TenantMailProviderRow {
            provider: sendgrid_provider(),
            check: ProviderCheck::Unverified,
            updated_at: clock::now(),
        })
        .unwrap();
        if let Some(outcome) = tested {
            provider.record_test_send(outcome).unwrap();
        }
        provider
    }

    fn send_for(
        providers: FakeTenantMailProviderStore,
        tenant: Option<&ScopedTenant>,
    ) -> Vec<MailProviderKind> {
        let transport = Arc::new(FakeMailProviderTransport::delivering());
        let route = TenantMailRoute::new(Arc::new(providers), transport.clone());
        let to = Email::new("ann@acme.com").unwrap();
        let rendered = RenderedEmail::text_only("Hi", "Hello");
        let mail = AddressedMail {
            to: &to,
            sender: MailSender::Platform,
            sender_name: None,
            rendered: &rendered,
        };
        block_on(route.send(tenant, &mail)).unwrap();
        transport
            .delivered()
            .into_iter()
            .map(|(kind, _)| kind)
            .collect()
    }

    /// Acme's SendGrid passed its test send. Acme's mail goes out through
    /// SendGrid.
    #[test]
    fn a_tested_provider_sends_the_tenants_mail() {
        let providers = FakeTenantMailProviderStore::holding(
            test_ctx().tenant_id(),
            acme_sendgrid(Some(TestSendOutcome::Delivered)),
        );

        let kinds = send_for(providers, Some(&test_ctx().tenant()));

        assert_eq!(kinds, [MailProviderKind::SendGrid]);
    }

    /// Acme named SendGrid but never tested it. Its reset links still go
    /// out through the platform, so a mistyped key never stops them.
    #[test]
    fn an_untested_provider_leaves_mail_with_the_platform() {
        let providers =
            FakeTenantMailProviderStore::holding(test_ctx().tenant_id(), acme_sendgrid(None));

        let kinds = send_for(providers, Some(&test_ctx().tenant()));

        assert_eq!(kinds, [MailProviderKind::Platform]);
    }

    /// Acme's SendGrid failed its last test send. Mail goes through the
    /// platform until it passes.
    #[test]
    fn a_provider_that_failed_its_test_leaves_mail_with_the_platform() {
        let providers = FakeTenantMailProviderStore::holding(
            test_ctx().tenant_id(),
            acme_sendgrid(Some(TestSendOutcome::Refused)),
        );

        let kinds = send_for(providers, Some(&test_ctx().tenant()));

        assert_eq!(kinds, [MailProviderKind::Platform]);
    }

    /// Mail of no tenant, such as to an organization member, goes through
    /// the platform.
    #[test]
    fn mail_of_no_tenant_goes_through_the_platform() {
        let kinds = send_for(FakeTenantMailProviderStore::empty(), None);

        assert_eq!(kinds, [MailProviderKind::Platform]);
    }
}
