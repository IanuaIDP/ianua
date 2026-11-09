//! The mail provider each tenant's mail goes out through, one row per
//! tenant, under row-level security.
//!
//! The provider's credential, an SMTP password or an API key, reaches the
//! store already sealed by the crypto adapter, as the domain holds it, and
//! is kept as it came; it is opened only by the transport that delivers
//! through it. Each kind of provider fills its own columns, so a change of
//! kind empties the others.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::branding::TenantMailProviderStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::branding::mail_provider::TenantMailProvider;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;

use self::record::{ProviderColumns, ProviderRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of tenants' mail providers.
pub struct PgTenantMailProviderStore {
    databases: Arc<Databases>,
}

impl PgTenantMailProviderStore {
    /// A store keeping mail providers in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgTenantMailProviderStore {}

#[async_trait]
impl TenantMailProviderStore for PgTenantMailProviderStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<TenantMailProvider<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ProviderRecord,
                    "queries/tenant_mail_providers/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ProviderRecord::into_provider).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        provider: &TenantMailProvider<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ProviderColumns::of(provider);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/tenant_mail_providers/save.sql",
                    tenant_id.as_uuid(),
                    columns.kind,
                    columns.smtp_host,
                    columns.smtp_port,
                    columns.smtp_security,
                    columns.smtp_username,
                    columns.ses_region,
                    columns.ses_access_key_id,
                    columns.mailgun_domain,
                    columns.mailgun_region,
                    columns.credential,
                    columns.check_state,
                    columns.checked_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::mail_provider::{
        AwsAccessKeyId, MailProvider, MailgunRegion, ProviderCheck, SesRegion,
        TenantMailProviderRow,
    };
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::branding::{mail_provider_row, sealed, smtp_provider};
    use crate::test_support::rows::domain::domain_name;

    /// A fresh database, the store on it, and one tenant.
    async fn fixture() -> (TestDb, PgTenantMailProviderStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgTenantMailProviderStore::new(Arc::clone(&db.databases));
        (db, store, ScopedTenant::for_background(TenantId::new()))
    }

    fn provider(row: TenantMailProviderRow) -> TenantMailProvider<ResolvedTenant> {
        TenantMailProvider::reconstitute(row).unwrap()
    }

    /// Every kind of provider reads back as it was saved, credentials still
    /// sealed, each replacing the last.
    #[tokio::test]
    async fn every_kind_of_provider_reads_back_as_saved() {
        let (_db, store, acme) = fixture().await;
        for kind in [
            MailProvider::Platform,
            smtp_provider(),
            MailProvider::SendGrid {
                api_key: sealed("sendgrid"),
            },
            MailProvider::Ses {
                region: SesRegion::new("eu-west-1").unwrap(),
                access_key_id: AwsAccessKeyId::new("AKIAIOSFODNN7EXAMPLE").unwrap(),
                secret_access_key: sealed("ses"),
            },
            MailProvider::Postmark {
                server_token: sealed("postmark"),
            },
            MailProvider::Mailgun {
                domain: domain_name("mg.acme.example"),
                region: MailgunRegion::Eu,
                api_key: sealed("mailgun"),
            },
        ] {
            store
                .save(&acme, &provider(mail_provider_row(kind.clone())))
                .await
                .unwrap();

            let found = store.find(&acme).await.unwrap().unwrap();
            assert_eq!(found.provider(), &kind);
        }
    }

    /// A test send's outcome and when it happened are kept.
    #[tokio::test]
    async fn a_test_send_is_kept() {
        let (_db, store, acme) = fixture().await;
        let tested = provider(TenantMailProviderRow {
            check: ProviderCheck::Verified { at: at(30) },
            ..mail_provider_row(smtp_provider())
        });

        store.save(&acme, &tested).await.unwrap();

        let found = store.find(&acme).await.unwrap().unwrap();
        assert_eq!(found.check(), ProviderCheck::Verified { at: at(30) });
        assert_eq!(found.updated_at(), at(0));
    }

    /// A tenant that never named a provider has none, and another tenant
    /// does not see this one's.
    #[tokio::test]
    async fn a_provider_is_found_only_by_its_tenant() {
        let (_db, store, acme) = fixture().await;
        store
            .save(&acme, &provider(mail_provider_row(smtp_provider())))
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        assert!(store.find(&other).await.unwrap().is_none());
    }

    /// Reading a mail provider whose stored SMTP host is localhost
    /// reports corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_provider_is_refused() {
        let (db, store, acme) = fixture().await;
        store
            .save(&acme, &provider(mail_provider_row(smtp_provider())))
            .await
            .unwrap();
        db.tamper("UPDATE tenant_mail_providers SET smtp_host = 'localhost'")
            .await;

        let read = store.find(&acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
