//! Real storage and keys shared by platform certificate and DNS tests.

use std::sync::Arc;

use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::domain::{
    PlatformCertificateStore as _, PlatformCertificateTarget, PlatformZoneSettings,
};
use ianua_app::ports::tenant::TenantStore as _;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::tenant::control::TenantControl;
use ianua_domain::domains::tenant::hosts::{
    PlatformCertificate, PlatformCertificateRow, ReadableAddress,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::test_support::authority::assumed_authority;
use ianua_domain::types::{
    CertificateId, CertificatePem, DomainName, Human, HumanAccount, IpAddress, PersonKey, UserId,
};

use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
use crate::postgres::domain::platform::PgPlatformCertificateStore;
use crate::postgres::tenant::PgTenantStore;
use crate::test_support::TestDb;
use crate::test_support::rows::domain::{domain_name, nameserver_bases, saved_tenant};

/// One saved tenant with real encryption and the platform's certificate store.
pub(crate) struct Fixture {
    pub(crate) db: TestDb,
    pub(crate) tenant: ScopedTenant,
    pub(crate) store: PgPlatformCertificateStore,
    pub(crate) encryptor: Arc<dyn SecretEncryptor>,
}

impl Fixture {
    /// Creates an active tenant whose readable addresses start disabled.
    pub(crate) async fn new() -> Self {
        let db = TestDb::fresh().await;
        let tenant = saved_tenant(&db.databases).await;
        let encryptor: Arc<dyn SecretEncryptor> = Arc::new(AesGcmSecretEncryptor::new(
            SealingKey::new("test1", [7; 32]).unwrap(),
            Vec::new(),
        ));
        let store = PgPlatformCertificateStore::new(db.databases.clone(), encryptor.clone());
        Self {
            db,
            tenant,
            store,
            encryptor,
        }
    }

    /// Records consent after the fixture's saved time through the tenant's own mutation.
    pub(crate) async fn consent(&self, choice: ReadableAddress) {
        let tenants = PgTenantStore::new(self.db.databases.clone(), DomainLimits::default());
        let mut tenant = tenants.find_by_id(&self.tenant).await.unwrap().unwrap();
        let _clock = clock::freeze(tenant.updated_at() + time::Duration::SECOND);
        let person = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("admin@acme.test").unwrap(),
        );
        let authority = assumed_authority(
            &person,
            *self.tenant,
            &[SystemPermission::ManageTenantSettings],
            &[],
        );
        tenant
            .change_readable_address(TenantControl::new(authority), choice)
            .unwrap();
        tenants.save(&tenant).await.unwrap();
    }

    /// Desired root belonging to this tenant, with its consent requirement explicit.
    pub(crate) fn target(
        &self,
        root: &str,
        readable: ReadableAddress,
    ) -> PlatformCertificateTarget {
        PlatformCertificateTarget {
            tenant_id: *self.tenant,
            root: domain_name(root),
            readable,
        }
    }

    /// Reconciles the complete desired catalog, with valid nameservers and a gateway address.
    pub(crate) async fn synchronize(&self, targets: &[PlatformCertificateTarget]) {
        self.store
            .synchronize(
                targets,
                Some(&PlatformZoneSettings {
                    nameservers: nameserver_bases(),
                    address: IpAddress::new("203.0.113.9").unwrap(),
                }),
            )
            .await
            .unwrap();
    }

    /// A currently valid certificate pair bound to the claimed attempt, with a real key.
    pub(crate) fn certificate(&self, id: CertificateId, root: &DomainName) -> PlatformCertificate {
        let issued =
            rcgen::generate_simple_self_signed(vec![root.to_string(), format!("*.{root}")])
                .unwrap();
        PlatformCertificate::reconstitute(PlatformCertificateRow {
            id,
            tenant_id: *self.tenant,
            root: root.clone(),
            certificate_pem: CertificatePem::new(issued.cert.pem()).unwrap(),
            private_key_pem: Secret::new(issued.signing_key.serialize_pem()),
            issued_at: clock::now() - time::Duration::MINUTE,
            expires_at: clock::now() + time::Duration::days(90),
        })
        .unwrap()
    }
}
