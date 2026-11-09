//! The LDAP client certificates of a tenant's people, each table row under
//! row-level security.
//!
//! A certificate is found by the fingerprint a TLS-verified connection
//! presented, and a fingerprint names one certificate of the tenant, so a
//! bind never has to pick between two. A certificate goes with the account
//! it was issued to.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::directory::LdapCertificateStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::ldap_certificate::LdapClientCertificate;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificateFingerprint, LdapCertificateId, UserId};

use self::record::{CertificateColumns, CertificateRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a fingerprint to one certificate of a tenant.
const FINGERPRINT_KEY: &str = "ldap_certificates_fingerprint_key";

/// The Postgres store of LDAP client certificates.
pub struct PgLdapCertificateStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgLdapCertificateStore {}

impl PgLdapCertificateStore {
    /// A store keeping LDAP client certificates in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt(
    record: Option<CertificateRecord>,
) -> Result<Option<LdapClientCertificate<ResolvedTenant>>, DomainError> {
    record.map(CertificateRecord::into_certificate).transpose()
}

#[async_trait]
impl LdapCertificateStore for PgLdapCertificateStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        certificate: &LdapClientCertificate<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = CertificateColumns::of(certificate);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/ldap_certificates/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.user_id,
                    columns.fingerprint,
                    columns.device_label,
                    columns.issued_at,
                    columns.expires_at,
                    columns.revoked_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, FINGERPRINT_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-certificate-of-the-tenant-has",
                "another certificate of the tenant has this fingerprint"
            ))),
        }
    }

    async fn find_by_fingerprint(
        &self,
        tenant_id: &ScopedTenant,
        fingerprint: &CertificateFingerprint,
    ) -> Result<Option<LdapClientCertificate<ResolvedTenant>>, DomainError> {
        let written = fingerprint.to_string();
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    CertificateRecord,
                    "queries/ldap_certificates/by_fingerprint.sql",
                    tenant_id.as_uuid(),
                    written
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &LdapCertificateId,
    ) -> Result<Option<LdapClientCertificate<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    CertificateRecord,
                    "queries/ldap_certificates/by_ids.sql",
                    tenant_id.as_uuid(),
                    ids.as_slice()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records.into_iter().next())
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<LdapClientCertificate<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    CertificateRecord,
                    "queries/ldap_certificates/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(CertificateRecord::into_certificate)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::authentication::ldap_certificate::LdapClientCertificateRow;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{Revocation, TenantId};

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::directory::certificate_row;
    use crate::test_support::rows::identity::user_row;

    struct Fixture {
        db: TestDb,
        store: PgLdapCertificateStore,
        tenant: ScopedTenant,
        ann: UserId,
    }

    /// A fresh database, one tenant holding the user Ann, and the store on
    /// it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let ann = a_user(&db, &tenant, "ann@acme.example").await;
        Fixture {
            store: PgLdapCertificateStore::new(Arc::clone(&db.databases)),
            tenant,
            ann,
            db,
        }
    }

    /// Saves a user of `tenant` at `email` through their store.
    async fn a_user(db: &TestDb, tenant: &ScopedTenant, email: &str) -> UserId {
        let user: User<ResolvedTenant> = User::reconstitute(user_row(email)).unwrap();
        users(db).save(tenant, &user).await.unwrap();
        *user.id()
    }

    fn users(db: &TestDb) -> PgUserStore {
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
    }

    fn certificate(row: LdapClientCertificateRow) -> LdapClientCertificate<ResolvedTenant> {
        LdapClientCertificate::reconstitute(row).unwrap()
    }

    fn fingerprint(byte: u8) -> CertificateFingerprint {
        CertificateFingerprint::from_digest([byte; 32])
    }

    impl Fixture {
        async fn save(&self, certificate: &LdapClientCertificate<ResolvedTenant>) {
            self.store.save(&self.tenant, certificate).await.unwrap();
        }
    }

    /// Ann's laptop certificate is found by its id and by its fingerprint,
    /// as it was saved.
    #[tokio::test]
    async fn a_saved_certificate_is_found_by_id_and_by_fingerprint() {
        let fx = fixture().await;
        let laptop = certificate(certificate_row(fx.ann, 1));
        fx.save(&laptop).await;

        let by_id = fx
            .store
            .find_by_id(&fx.tenant, laptop.id())
            .await
            .unwrap()
            .unwrap();
        let by_fingerprint = fx
            .store
            .find_by_fingerprint(&fx.tenant, &fingerprint(1))
            .await
            .unwrap()
            .unwrap();

        for found in [&by_id, &by_fingerprint] {
            assert_eq!(found.id(), laptop.id());
            assert_eq!(found.user_id(), &fx.ann);
            assert_eq!(found.device_label(), laptop.device_label());
            assert_eq!(found.issued_at(), laptop.issued_at());
            assert_eq!(found.expires_at(), laptop.expires_at());
            assert!(found.revoked_at().is_none());
        }
    }

    /// An id or fingerprint nobody has finds nothing, and another tenant
    /// does not find this tenant's certificate.
    #[tokio::test]
    async fn a_certificate_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let laptop = certificate(certificate_row(fx.ann, 1));
        fx.save(&laptop).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let unknown = fx
            .store
            .find_by_fingerprint(&fx.tenant, &fingerprint(2))
            .await
            .unwrap();
        let by_id = fx.store.find_by_id(&other, laptop.id()).await.unwrap();
        let by_fingerprint = fx
            .store
            .find_by_fingerprint(&other, &fingerprint(1))
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(by_id.is_none());
        assert!(by_fingerprint.is_none());
    }

    /// Ann's certificates list in the order they were issued, and none of
    /// Bob's.
    #[tokio::test]
    async fn a_persons_certificates_are_listed_in_the_order_issued() {
        let fx = fixture().await;
        let bob = a_user(&fx.db, &fx.tenant, "bob@acme.example").await;
        let later = certificate(LdapClientCertificateRow {
            issued_at: at(5),
            expires_at: at(5) + time::Duration::days(30),
            ..certificate_row(fx.ann, 2)
        });
        let first = certificate(certificate_row(fx.ann, 1));
        for saved in [&later, &first, &certificate(certificate_row(bob, 3))] {
            fx.save(saved).await;
        }

        let listed = fx.store.list_by_user(&fx.tenant, &fx.ann).await.unwrap();

        let ids: Vec<_> = listed.iter().map(|found| *found.id()).collect();
        assert_eq!(ids, [*first.id(), *later.id()]);
    }

    /// Ann revokes her laptop's certificate: saving it again keeps the
    /// revocation.
    #[tokio::test]
    async fn saving_again_keeps_the_revocation() {
        let fx = fixture().await;
        let laptop = certificate(certificate_row(fx.ann, 1));
        fx.save(&laptop).await;
        let revoked = certificate(LdapClientCertificateRow {
            id: *laptop.id(),
            revocation: Revocation::Revoked { at: at(9) },
            ..certificate_row(fx.ann, 1)
        });

        fx.save(&revoked).await;

        let found = fx
            .store
            .find_by_id(&fx.tenant, laptop.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.revoked_at(), Some(at(9)));
    }

    /// Saving a second certificate with the same tenant fingerprint
    /// returns a conflict.
    #[tokio::test]
    async fn a_fingerprint_another_certificate_has_is_refused() {
        let fx = fixture().await;
        fx.save(&certificate(certificate_row(fx.ann, 1))).await;

        let second = fx
            .store
            .save(&fx.tenant, &certificate(certificate_row(fx.ann, 1)))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Deleting Ann takes her certificates with her.
    #[tokio::test]
    async fn a_deleted_persons_certificates_go_with_them() {
        let fx = fixture().await;
        let laptop = certificate(certificate_row(fx.ann, 1));
        fx.save(&laptop).await;

        users(&fx.db).delete(&fx.tenant, &fx.ann).await.unwrap();

        assert!(
            fx.store
                .find_by_id(&fx.tenant, laptop.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A certificate whose stored device label is blank is rejected as
    /// corrupt storage on read.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_certificate_is_refused() {
        let fx = fixture().await;
        let laptop = certificate(certificate_row(fx.ann, 1));
        fx.save(&laptop).await;
        fx.db
            .tamper("UPDATE ldap_certificates SET device_label = ''")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, laptop.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
