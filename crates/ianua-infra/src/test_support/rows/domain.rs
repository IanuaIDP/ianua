//! Rows of the domain context: registered domains, the certificates that
//! serve them, ACME challenges and handover offers, the record sets a
//! delegated zone answers with, and the saved tenant a claim on a name
//! belongs to.

use std::sync::Arc;

use ianua_app::ports::organization::OrganizationStore;
use ianua_app::ports::tenant::TenantStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::tenant::custom_domains::acme_challenge::{
    AcmeChallengeRow, ChallengeToken, KeyAuthorization,
};
use ianua_domain::domains::tenant::custom_domains::certificate::{
    CertificateBundleRow, CertificateSource,
};
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    RecordKind, RecordName, RecordSet, RecordValue, Ttl,
};
use ianua_domain::domains::tenant::custom_domains::handover_offer::{
    HandoverOfferRow, HandoverOfferState,
};
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    DomainConnection, DomainProof, DomainVerificationToken, RegisteredDomainRow,
};
use ianua_domain::domains::tenant::custom_domains::uploaded_certificate::{
    CertificateIssuer, UploadedDetails,
};
use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateId, CertificatePem, DomainId, DomainName, TenantId};

use crate::postgres::Databases;
use crate::postgres::organization::PgOrganizationStore;
use crate::postgres::tenant::PgTenantStore;
use crate::test_support::rows::at;
use crate::test_support::rows::organization::organization_row;
use crate::test_support::rows::tenant::tenant_row;

/// Ninety days, in seconds, the life of a certificate the platform issues.
const NINETY_DAYS: i64 = 90 * 24 * 3600;

/// The chain every test certificate holds.
const CHAIN: &str = "-----BEGIN CERTIFICATE-----\nTUlJQnRlc3RjZXJ0\n-----END CERTIFICATE-----\n";

/// A tenant saved with an organization of its own in `databases`, as the
/// platform's claims on names point at a tenant the platform keeps.
///
/// # Panics
///
/// When the organization or the tenant cannot be saved, which is a broken
/// test database.
pub async fn saved_tenant(databases: &Arc<Databases>) -> ScopedTenant {
    let key = TenantId::new().as_uuid().simple().to_string();
    let organization = Organization::reconstitute(organization_row(&format!("o{key}"), "Acme"))
        .expect("a valid organization");
    PgOrganizationStore::new(Arc::clone(databases), DomainLimits::default())
        .save(&organization)
        .await
        .expect("the organization is saved");
    let tenant = Tenant::reconstitute(tenant_row(*organization.id(), &format!("t{key}")))
        .expect("a valid tenant");
    PgTenantStore::new(Arc::clone(databases), DomainLimits::default())
        .save(&tenant)
        .await
        .expect("the tenant is saved");
    ScopedTenant::for_background(*tenant.id())
}

/// A domain name.
///
/// # Panics
///
/// When `name` is not one, which is a mistake in the test.
#[must_use]
pub fn domain_name(name: &str) -> DomainName {
    DomainName::new(name).expect("a valid domain name")
}

/// A self-managed registration of `name`, not yet proved, registered at
/// the fixed moment.
///
/// # Panics
///
/// When `name` is not a domain name, which is a mistake in the test.
#[must_use]
pub fn registered_domain_row(name: &str) -> RegisteredDomainRow {
    RegisteredDomainRow {
        id: DomainId::new(),
        domain: domain_name(name),
        connection: DomainConnection::SelfManaged,
        proof: DomainProof::Unproved,
        dns_challenge_token: DomainVerificationToken::new("ianua-token").expect("a valid token"),
        tls_status: TlsStatus::NotRequired,
        created_at: at(0),
    }
}

/// A registration of `name` delegated to us and proved a second after it
/// was registered, waiting for its certificate.
#[must_use]
pub fn proved_domain_row(name: &str) -> RegisteredDomainRow {
    RegisteredDomainRow {
        connection: DomainConnection::Delegated,
        proof: DomainProof::Verified { at: at(1) },
        tls_status: TlsStatus::Provisioning,
        ..registered_domain_row(name)
    }
}

/// A certificate the platform issued for the registration `domain`, at
/// `issued` seconds from the fixed moment, good for ninety days.
///
/// # Panics
///
/// Never: the chain is a fixed, valid one.
#[must_use]
pub fn certificate_row(domain: DomainId, issued: i64) -> CertificateBundleRow {
    CertificateBundleRow {
        id: CertificateId::new(),
        domain_id: domain,
        certificate_pem: CertificatePem::new(CHAIN).expect("a valid chain"),
        private_key_pem: Secret::new("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----"),
        issued_at: at(issued),
        expires_at: at(issued.saturating_add(NINETY_DAYS)),
        source: CertificateSource::Acme,
    }
}

/// A certificate the tenant uploaded for the registration `domain`, naming
/// `name`, issued at the fixed moment and good for ninety days.
///
/// # Panics
///
/// When `name` is not a domain name, which is a mistake in the test.
#[must_use]
pub fn uploaded_certificate_row(domain: DomainId, name: &str) -> CertificateBundleRow {
    let issued = certificate_row(domain, 0);
    let details = UploadedDetails::stored(
        CertificateIssuer::new("Acme Issuing CA").expect("a valid issuer"),
        vec![domain_name(name)],
        issued.expires_at,
    )
    .expect("an upload naming one host");
    CertificateBundleRow {
        source: CertificateSource::Uploaded(details),
        ..issued
    }
}

/// An outstanding challenge under `token` for `login.acme.example`,
/// expiring `expires` seconds from the fixed moment.
///
/// # Panics
///
/// When `token` is not a challenge token, which is a mistake in the test.
#[must_use]
pub fn acme_challenge_row(token: &str, expires: i64) -> AcmeChallengeRow {
    AcmeChallengeRow {
        token: ChallengeToken::new(token).expect("a valid token"),
        key_authorization: KeyAuthorization::new(format!("{token}.thumbprint"))
            .expect("a valid key authorization"),
        domain: domain_name("login.acme.example"),
        expires_at: at(expires),
    }
}

/// A registration of `name` delegated to us and not yet proved.
#[must_use]
pub fn delegated_domain_row(name: &str) -> RegisteredDomainRow {
    RegisteredDomainRow {
        connection: DomainConnection::Delegated,
        ..registered_domain_row(name)
    }
}

/// A registration of `name` delegated to us, proved and then lost a second
/// later.
#[must_use]
pub fn lost_domain_row(name: &str) -> RegisteredDomainRow {
    RegisteredDomainRow {
        proof: DomainProof::Lost {
            verified_at: at(1),
            failed_at: at(2),
        },
        ..proved_domain_row(name)
    }
}

/// The shared names every registration's own nameservers are named under.
#[must_use]
pub fn nameserver_bases() -> Vec<DomainName> {
    vec![
        domain_name("ns1.ianua.example"),
        domain_name("ns2.ianua.example"),
    ]
}

/// The set answering `name` with the one value `value` of `kind`, cached
/// for the standard time.
///
/// # Panics
///
/// When `name` is not a record name or `value` does not read as `kind`,
/// which is a mistake in the test.
#[must_use]
pub fn record_set(name: &str, kind: RecordKind, value: &str) -> RecordSet {
    RecordSet::new(
        RecordName::new(name).expect("a valid record name"),
        Ttl::standard(),
        vec![RecordValue::parse(kind, value).expect("a value of its type")],
    )
    .expect("a set of one value")
}

/// An offer of `domain` from `from` to `to`, made at the fixed moment and
/// waiting.
///
/// # Panics
///
/// When `domain` is not a domain name, which is a mistake in the test.
#[must_use]
pub fn handover_offer_row(from: TenantId, to: TenantId, domain: &str) -> HandoverOfferRow {
    HandoverOfferRow {
        from,
        to,
        domain: domain_name(domain),
        offered_at: at(0),
        state: HandoverOfferState::Waiting,
    }
}
