//! The certificates registered domains serve: the two stores of
//! `ports/domain/certificates.rs`, sharing one mapping.
//!
//! A certificate is kept beside the claim on its domain's name, in the
//! platform database, not with the registration in the tenant's: the proxy
//! and the renewal sweep find it by its domain with no tenant in hand, and
//! a handover moves the claim, and with it the certificate, to the
//! receiving tenant by the foreign key's `ON UPDATE CASCADE`. Removing the
//! domain releases the claim and takes its certificates with it. Every call
//! runs as platform work, each query naming its tenant where it has one.
//!
//! The private key is sealed with the platform's secret encryptor before it
//! is written, and opened as it is read; the store never writes it plain.

pub(crate) mod record;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::domain::{
    CertificateStore, CrossTenantCertificateStore, certificate_key_place,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::tenant::custom_domains::certificate::CertificateBundle;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateId, DomainId, TenantId};
use time::Duration;

use self::record::{CertificateColumns, CertificateRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// Seals and opens certificates' private keys around the queries.
pub(crate) struct Keys {
    encryptor: Arc<dyn SecretEncryptor>,
}

impl Keys {
    /// Keys sealed and opened by `encryptor`.
    pub(crate) fn new(encryptor: Arc<dyn SecretEncryptor>) -> Self {
        Self { encryptor }
    }

    /// The bundle `record` holds, its key opened for the certificate it
    /// was sealed for.
    pub(crate) async fn opened(
        &self,
        record: CertificateRecord,
    ) -> Result<CertificateBundle, DomainError> {
        let place = certificate_key_place(&CertificateId::from_uuid(record.id));
        let plain = self
            .encryptor
            .decrypt(&record.sealed_key()?, &place)
            .await?;
        let key = String::from_utf8(plain).map_err(|_| {
            DomainError::corrupt_row("certificate", "a private key that does not open to text")
        })?;
        record.into_bundle(Secret::new(key))
    }

    /// The bundle `record` holds, if any, its key opened.
    async fn opened_if(
        &self,
        record: Option<CertificateRecord>,
    ) -> Result<Option<CertificateBundle>, DomainError> {
        let Some(record) = record else {
            return Ok(None);
        };
        self.opened(record).await.map(Some)
    }
}

/// The Postgres store of one tenant's certificates.
pub struct PgCertificateStore {
    databases: Arc<Databases>,
    keys: Keys,
}

impl PgCertificateStore {
    /// A store keeping certificates in `databases`, their keys sealed by
    /// `encryptor`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, encryptor: Arc<dyn SecretEncryptor>) -> Self {
        Self {
            databases,
            keys: Keys { encryptor },
        }
    }
}

impl TenantScoped for PgCertificateStore {}

#[async_trait]
impl CertificateStore for PgCertificateStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        cert: &CertificateBundle,
    ) -> Result<(), DomainError> {
        let columns = CertificateColumns::of(cert);
        let sealed = self
            .keys
            .encryptor
            .encrypt(
                cert.private_key_pem().expose().as_bytes(),
                &certificate_key_place(cert.id()),
            )
            .await?;
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/domain_certificates/save.sql",
                columns.id,
                tenant_id.as_uuid(),
                columns.domain_id,
                columns.certificate_pem,
                sealed.as_str(),
                columns.issued_at,
                columns.expires_at,
                columns.source,
                columns.issuer,
                columns.subject_names.as_deref(),
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }

    async fn find_current(
        &self,
        tenant_id: &ScopedTenant,
        domain_id: &DomainId,
    ) -> Result<Option<CertificateBundle>, DomainError> {
        let record = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                CertificateRecord,
                "queries/domain_certificates/current.sql",
                tenant_id.as_uuid(),
                domain_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        self.keys.opened_if(record).await
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &CertificateId,
    ) -> Result<bool, DomainError> {
        let deleted = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/domain_certificates/delete.sql",
                tenant_id.as_uuid(),
                id.as_uuid()
            )
            .execute(connection)
            .await
        })
        .await?;
        Ok(deleted.rows_affected() > 0)
    }
}

/// The Postgres store of the certificate questions the sweeps and the
/// proxy ask across every tenant.
pub struct PgCrossTenantCertificateStore {
    databases: Arc<Databases>,
    keys: Keys,
}

impl PgCrossTenantCertificateStore {
    /// A store reading certificates from `databases`, their keys opened by
    /// `encryptor`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, encryptor: Arc<dyn SecretEncryptor>) -> Self {
        Self {
            databases,
            keys: Keys { encryptor },
        }
    }

    /// The bundle `record` holds, with its tenant, its key opened.
    async fn listed(
        &self,
        record: CertificateRecord,
    ) -> Result<(TenantId, CertificateBundle), DomainError> {
        let tenant = record.tenant();
        Ok((tenant, self.keys.opened(record).await?))
    }
}

#[async_trait]
impl CrossTenantCertificateStore for PgCrossTenantCertificateStore {
    async fn find_by_domain_id(
        &self,
        domain_id: &DomainId,
    ) -> Result<Option<CertificateBundle>, DomainError> {
        let record = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                CertificateRecord,
                "queries/domain_certificates/of_domain.sql",
                domain_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        self.keys.opened_if(record).await
    }

    async fn list_expiring(
        &self,
        within_days: u32,
    ) -> Result<Vec<(TenantId, CertificateBundle)>, DomainError> {
        let before =
            clock::now().saturating_add(Duration::days(i64::from(within_days).saturating_add(1)));
        let records = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                CertificateRecord,
                "queries/domain_certificates/expiring.sql",
                before
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        try_join_all(records.into_iter().map(|record| self.listed(record))).await
    }

    async fn cleanup(&self, domain_id: &DomainId) -> Result<u64, DomainError> {
        let deleted = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/domain_certificates/cleanup.sql",
                domain_id.as_uuid()
            )
            .execute(connection)
            .await
        })
        .await?;
        Ok(deleted.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::domain::RegisteredDomainStore;
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_app::test_support::authentication::FakeEncryptor;
    use ianua_domain::domains::tenant::custom_domains::certificate::{
        CertificateBundleRow, Renewal,
    };
    use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::postgres::domain::PgRegisteredDomainStore;
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::test_support::TestDb;
    use crate::test_support::rows::domain::{
        certificate_row, proved_domain_row, saved_tenant, uploaded_certificate_row,
    };

    /// Seconds from the fixed moment to a time long past, for expiry, which
    /// is compared against the real clock.
    const LONG_AGO: i64 = -100_000_000;

    struct Fixture {
        database: TestDb,
        domains: PgRegisteredDomainStore,
        store: PgCertificateStore,
        across: PgCrossTenantCertificateStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, one saved tenant, and the stores on it.
    async fn fixture() -> Fixture {
        sealing_with(Arc::new(FakeEncryptor)).await
    }

    /// The same, the stores sealing keys with `encryptor`.
    async fn sealing_with(encryptor: Arc<dyn SecretEncryptor>) -> Fixture {
        let database = TestDb::fresh().await;
        let databases = &database.databases;
        Fixture {
            domains: PgRegisteredDomainStore::new(Arc::clone(databases)),
            store: PgCertificateStore::new(Arc::clone(databases), Arc::clone(&encryptor)),
            across: PgCrossTenantCertificateStore::new(Arc::clone(databases), encryptor),
            tenant: saved_tenant(databases).await,
            database,
        }
    }

    impl Fixture {
        /// A proved registration of `name` saved for `tenant`.
        async fn registered(&self, tenant: &ScopedTenant, name: &str) -> DomainId {
            let domain: RegisteredDomain<ResolvedTenant> =
                RegisteredDomain::reconstitute(proved_domain_row(name)).unwrap();
            self.domains.save(tenant, &domain).await.unwrap();
            *domain.id()
        }
    }

    fn bundle(row: CertificateBundleRow) -> CertificateBundle {
        CertificateBundle::reconstitute(row).unwrap()
    }

    /// A saved certificate is the one its domain serves, its key opened as
    /// it was saved; the newest saved wins.
    #[tokio::test]
    async fn the_newest_certificate_saved_is_the_current_one() {
        let db = fixture().await;
        let domain = db.registered(&db.tenant, "login.acme.example").await;
        let older = bundle(certificate_row(domain, 0));
        let newer = bundle(certificate_row(domain, 10));

        db.store.save(&db.tenant, &older).await.unwrap();
        db.store.save(&db.tenant, &newer).await.unwrap();

        let current = db
            .store
            .find_current(&db.tenant, &domain)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.id(), newer.id());
        assert_eq!(current.certificate_pem(), newer.certificate_pem());
        assert_eq!(
            current.private_key_pem().expose(),
            newer.private_key_pem().expose()
        );
        assert_eq!(current.expires_at(), newer.expires_at());
        assert_eq!(current.renewal(), Renewal::ByPlatform);
    }

    /// Saves `certificate`, waits at `step` for the other change, and saves
    /// the domain it serves, as an upload and a provisioning job both do.
    async fn certificate_then_domain(
        db: &Fixture,
        certificate: &CertificateBundle,
        domain: &RegisteredDomain<ResolvedTenant>,
        step: &tokio::sync::Barrier,
    ) -> Result<(), DomainError> {
        db.store.save(&db.tenant, certificate).await?;
        step.wait().await;
        db.domains.save(&db.tenant, domain).await
    }

    /// Tess uploads a certificate for login.acme.example while the
    /// platform's job saves one for it too: each saves its certificate,
    /// then the domain, and both changes are kept rather than one being
    /// broken off as a deadlock.
    #[tokio::test]
    async fn two_changes_saving_a_certificate_and_its_domain_both_commit() {
        let db = fixture().await;
        let domain: RegisteredDomain<ResolvedTenant> =
            RegisteredDomain::reconstitute(proved_domain_row("login.acme.example")).unwrap();
        db.domains.save(&db.tenant, &domain).await.unwrap();
        let uploaded = bundle(certificate_row(*domain.id(), 0));
        let provisioned = bundle(certificate_row(*domain.id(), 10));
        let step = tokio::sync::Barrier::new(2);

        let (upload, job) = tokio::join!(
            atomically(
                &PgUnitOfWork,
                certificate_then_domain(&db, &uploaded, &domain, &step),
                settled
            ),
            atomically(
                &PgUnitOfWork,
                certificate_then_domain(&db, &provisioned, &domain, &step),
                settled
            ),
        );

        assert!(
            matches!(upload, Ok(Ok(()))),
            "the upload is kept: {upload:?}"
        );
        assert!(matches!(job, Ok(Ok(()))), "the job's save is kept: {job:?}");
    }

    /// Keeps a change that went through, and drops one that did not.
    fn settled(outcome: &Result<(), DomainError>) -> Settlement {
        match outcome {
            Ok(()) => Settlement::Commit,
            Err(_) => Settlement::Rollback,
        }
    }

    /// An uploaded certificate reads back with what it says about itself.
    #[tokio::test]
    async fn an_uploaded_certificate_keeps_its_details() {
        let db = fixture().await;
        let domain = db.registered(&db.tenant, "login.acme.example").await;
        let upload = bundle(uploaded_certificate_row(domain, "login.acme.example"));

        db.store.save(&db.tenant, &upload).await.unwrap();

        let current = db
            .store
            .find_current(&db.tenant, &domain)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.source(), upload.source());
        assert_eq!(current.renewal(), Renewal::ByTenant);
    }

    /// Another tenant finds none of this tenant's certificates and cannot
    /// delete one; the tenant's own delete says whether there was one.
    #[tokio::test]
    async fn a_certificate_belongs_to_its_tenant() {
        let db = fixture().await;
        let domain = db.registered(&db.tenant, "login.acme.example").await;
        let cert = bundle(certificate_row(domain, 0));
        db.store.save(&db.tenant, &cert).await.unwrap();
        let other = saved_tenant(&db.database.databases).await;

        let seen = db.store.find_current(&other, &domain).await.unwrap();
        let theirs = db.store.delete(&other, cert.id()).await.unwrap();
        let own = db.store.delete(&db.tenant, cert.id()).await.unwrap();
        let again = db.store.delete(&db.tenant, cert.id()).await.unwrap();

        assert!(seen.is_none());
        assert!(!theirs);
        assert!(own);
        assert!(!again);
        assert!(
            db.store
                .find_current(&db.tenant, &domain)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Saving a certificate for another tenant's domain returns an
    /// infrastructure error and leaves that domain without a certificate.
    #[tokio::test]
    async fn a_certificate_for_a_domain_the_tenant_does_not_hold_is_refused() {
        let db = fixture().await;
        let domain = db.registered(&db.tenant, "login.acme.example").await;
        let other = saved_tenant(&db.database.databases).await;

        let saved = db
            .store
            .save(&other, &bundle(certificate_row(domain, 0)))
            .await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
        assert!(
            db.across
                .find_by_domain_id(&domain)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A domain's current certificate is found by the domain alone, and the
    /// ones running out are listed with their tenants, whoever holds them.
    #[tokio::test]
    async fn certificates_are_found_and_listed_across_tenants() {
        let db = fixture().await;
        let other = saved_tenant(&db.database.databases).await;
        let ours = db.registered(&db.tenant, "login.acme.example").await;
        let theirs = db.registered(&other, "login.globex.example").await;
        let fresh = db.registered(&db.tenant, "shop.acme.example").await;
        let running_out = bundle(certificate_row(ours, LONG_AGO));
        let also = bundle(certificate_row(theirs, LONG_AGO));
        db.store.save(&db.tenant, &running_out).await.unwrap();
        db.store.save(&other, &also).await.unwrap();
        db.store
            .save(&db.tenant, &bundle(certificate_row(fresh, 0)))
            .await
            .unwrap();

        let found = db.across.find_by_domain_id(&theirs).await.unwrap();
        let mut expiring: Vec<(TenantId, CertificateId)> = db
            .across
            .list_expiring(30)
            .await
            .unwrap()
            .into_iter()
            .map(|(tenant, cert)| (tenant, *cert.id()))
            .collect();
        expiring.sort_by_key(|(_, id)| *id.as_uuid());
        let mut wanted = vec![(*db.tenant, *running_out.id()), (*other, *also.id())];
        wanted.sort_by_key(|(_, id)| *id.as_uuid());

        assert_eq!(found.unwrap().id(), also.id());
        assert_eq!(expiring, wanted);
    }

    /// Cleaning up a domain keeps its newest certificate and says how many
    /// older ones went; another domain's are untouched.
    #[tokio::test]
    async fn cleanup_keeps_the_newest_certificate() {
        let db = fixture().await;
        let domain = db.registered(&db.tenant, "login.acme.example").await;
        let elsewhere = db.registered(&db.tenant, "shop.acme.example").await;
        for issued in [0, 10, 20] {
            db.store
                .save(&db.tenant, &bundle(certificate_row(domain, issued)))
                .await
                .unwrap();
        }
        let kept = bundle(certificate_row(elsewhere, 0));
        db.store.save(&db.tenant, &kept).await.unwrap();

        let removed = db.across.cleanup(&domain).await.unwrap();
        let again = db.across.cleanup(&domain).await.unwrap();

        assert_eq!(removed, 2);
        assert_eq!(again, 0);
        assert_eq!(
            db.across
                .find_by_domain_id(&elsewhere)
                .await
                .unwrap()
                .unwrap()
                .id(),
            kept.id()
        );
    }

    /// A removed domain takes its certificates with it, and a handed over
    /// one keeps them, now the receiving tenant's.
    #[tokio::test]
    async fn certificates_follow_their_domain() {
        let db = fixture().await;
        let removed = db.registered(&db.tenant, "old.acme.example").await;
        let moving: RegisteredDomain<ResolvedTenant> =
            RegisteredDomain::reconstitute(proved_domain_row("login.acme.example")).unwrap();
        db.domains.save(&db.tenant, &moving).await.unwrap();
        db.store
            .save(&db.tenant, &bundle(certificate_row(removed, 0)))
            .await
            .unwrap();
        let cert = bundle(certificate_row(*moving.id(), 0));
        db.store.save(&db.tenant, &cert).await.unwrap();
        let receiver = saved_tenant(&db.database.databases).await;

        db.domains.delete(&db.tenant, &removed).await.unwrap();
        db.domains.save(&receiver, &moving).await.unwrap();
        db.domains.delete(&db.tenant, moving.id()).await.unwrap();

        let gone = db.across.find_by_domain_id(&removed).await.unwrap();
        let theirs = db.store.find_current(&receiver, moving.id()).await.unwrap();
        assert!(gone.is_none());
        assert_eq!(theirs.unwrap().id(), cert.id());
    }

    /// An invalid stored subject hostname makes reading the domain's
    /// current certificate return an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_certificate_is_refused() {
        let db = fixture().await;
        let domain = db.registered(&db.tenant, "login.acme.example").await;
        db.store
            .save(
                &db.tenant,
                &bundle(uploaded_certificate_row(domain, "login.acme.example")),
            )
            .await
            .unwrap();
        db.database
            .tamper("UPDATE domain_certificates SET subject_names = ARRAY['not a host']")
            .await;

        let read = db.store.find_current(&db.tenant, &domain).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Copying a sealed key to another domain's certificate makes that
    /// certificate unreadable; the original certificate remains readable.
    #[tokio::test]
    async fn a_key_moved_to_another_certificate_does_not_open() {
        let sealer =
            AesGcmSecretEncryptor::new(SealingKey::new("k1", [7; 32]).unwrap(), Vec::new());
        let db = sealing_with(Arc::new(sealer)).await;
        let login = db.registered(&db.tenant, "login.acme.example").await;
        let shop = db.registered(&db.tenant, "shop.acme.example").await;
        let source = bundle(certificate_row(login, 0));
        db.store.save(&db.tenant, &source).await.unwrap();
        db.store
            .save(&db.tenant, &bundle(certificate_row(shop, 0)))
            .await
            .unwrap();
        db.database
            .tamper(&format!(
                "UPDATE domain_certificates SET private_key = source.private_key \
                 FROM domain_certificates source \
                 WHERE source.id = '{}' AND domain_certificates.domain_id = '{}'",
                source.id().as_uuid(),
                shop.as_uuid()
            ))
            .await;

        let moved = db.store.find_current(&db.tenant, &shop).await;
        let own = db.store.find_current(&db.tenant, &login).await;

        assert!(matches!(moved, Err(DomainError::Infrastructure(_))));
        assert!(own.unwrap().is_some());
    }
}
