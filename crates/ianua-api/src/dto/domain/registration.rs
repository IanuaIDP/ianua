//! Domain registration bodies: a domain to register, a registered domain as
//! it is read back, and the DNS records that bring its traffic here.

use std::sync::Arc;

use ianua_app::error::AppError;
use ianua_app::use_cases::domain::registration::{AddDomainRequest, DomainDetail};
use ianua_assembly::domain::DnsFacts;
use ianua_domain::domains::tenant::custom_domains::dns_zone::DelegationLabel;
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    DomainConnection, RegisteredDomain,
};
use ianua_domain::domains::tenant::custom_domains::traffic_record::{
    TrafficInstructions, TrafficRecord,
};
use ianua_domain::domains::tenant::custom_domains::verification_status::{
    TlsStatus, VerificationStatus,
};
use ianua_domain::domains::tenant::hosts::{PlatformAddressing, PlatformLabel};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{DomainId, DomainName, Fact};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::domain::certificates::CertificateResponse;
use crate::dto::domain::verification::verification_name;
use crate::error::ApiError;

/// A domain to register.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AddDomainBody {
    /// The domain to register, such as `acme.com`.
    pub domain: String,
    /// Who runs the DNS: `SelfManaged` or `Delegated`. Defaults to
    /// `SelfManaged`, the choice that takes nothing over.
    #[serde(default)]
    pub connection: Option<String>,
}

impl TryFrom<AddDomainBody> for AddDomainRequest {
    type Error = ApiError;

    fn try_from(body: AddDomainBody) -> Result<Self, Self::Error> {
        Ok(Self {
            domain: DomainName::new(body.domain).map_err(ApiError::validation)?,
            connection: connection(body.connection.as_deref())?,
        })
    }
}

/// What a domain's DNS instructions depend on outside the domain itself:
/// the hostname the tenant already answers on, and the deployment's facts.
pub(crate) struct DnsSetup {
    host: DomainName,
    facts: Arc<DnsFacts>,
}

impl DnsSetup {
    /// Uses the tenant's permanent root when platform DNS is enabled;
    /// custom-only deployments use the operator's gateway hostname.
    ///
    /// # Errors
    ///
    /// Returns an internal error when the configured base leaves no room for a tenant label.
    pub(crate) fn new(label: &PlatformLabel, facts: Arc<DnsFacts>) -> Result<Self, ApiError> {
        let host = match facts.addressing {
            PlatformAddressing::Disabled => facts.base_domain.clone(),
            PlatformAddressing::Flat | PlatformAddressing::Nested => {
                DomainName::new(format!("{}.{}", label.as_str(), facts.base_domain))
                    .map_err(AppError::internal)?
            }
        };
        Ok(Self { host, facts })
    }

    /// What the tenant adds to their DNS for `domain`.
    ///
    /// A delegated domain is handed to this registration's own
    /// nameservers, not the shared ones: the names prove whose delegation
    /// it is. A delegated domain with no nameservers configured falls back
    /// to the self-managed records, the less wrong pair, since they name a
    /// host that resolves.
    fn instructions(&self, domain: &RegisteredDomain<ResolvedTenant>) -> TrafficInstructions {
        if let Some(delegated) = self.delegated(domain) {
            return delegated;
        }
        TrafficInstructions::self_managed(
            domain.domain(),
            self.host.clone(),
            Fact::from_option(self.facts.proxy_address.clone()),
        )
    }

    /// The records for a domain handed to this registration's own
    /// nameservers, or nothing when it is self-managed or no nameservers are
    /// configured.
    fn delegated(&self, domain: &RegisteredDomain<ResolvedTenant>) -> Option<TrafficInstructions> {
        if domain.connection() != DomainConnection::Delegated {
            return None;
        }
        let assigned = DelegationLabel::for_registration(domain.id())
            .nameservers(&self.facts.nameservers)
            .ok()?;
        TrafficInstructions::delegated(domain.domain(), &assigned).ok()
    }
}

/// A registered domain.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DomainResponse {
    /// The registration's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: DomainId,
    /// The registered domain name.
    pub domain: String,
    /// Who holds the DNS: `SelfManaged` (the tenant adds records at their
    /// own provider) or `Delegated` (they handed the hostname to us with an
    /// `NS` record, and we write its records).
    pub connection: &'static str,
    /// `Pending`, `Verified` or `Failed`.
    pub verification_status: &'static str,
    /// `NotRequired`, `Provisioning`, `Active`, `Expired` or
    /// `NoCertificate` (the tenant removed the certificate it uploaded and
    /// has not uploaded or asked for another).
    pub tls_status: &'static str,
    /// DNS record name to add for verification. Absent for a `Delegated`
    /// domain, whose `NS` records prove it instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_record_name: Option<String>,
    /// DNS record value to add for verification. Absent when delegated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_record_value: Option<String>,
    /// When DNS verification completed, if it has.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub verified_at: Option<OffsetDateTime>,
    /// When this domain was registered.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Whether the domain arrived verified, because the operator vouches
    /// for it.
    pub is_auto_verified: bool,
    /// Suggested CAA record for a tenant who writes their own records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caa_record: Option<String>,
    /// The records that actually bring traffic here. Verifying proves
    /// ownership and routes nothing: until one of these is added, the
    /// domain resolves wherever it always did.
    pub traffic_records: TrafficRecordsResponse,
}

impl DomainResponse {
    /// `domain` as read back, its instructions built against `dns`.
    #[must_use]
    pub(crate) fn new(domain: &RegisteredDomain<ResolvedTenant>, dns: &DnsSetup) -> Self {
        let self_managed = domain.connection() == DomainConnection::SelfManaged;
        let name = domain.domain().as_str();
        Self {
            id: *domain.id(),
            domain: name.to_owned(),
            connection: domain.connection().as_str(),
            verification_status: verification_name(domain.verification_status()),
            tls_status: tls_name(domain.tls_status()),
            dns_record_name: self_managed.then(|| format!("_ianua-verify.{name}")),
            dns_record_value: self_managed
                .then(|| format!("ianua-verify={}", domain.dns_challenge_token())),
            verified_at: domain.verified_at(),
            created_at: domain.created_at(),
            is_auto_verified: dns.facts.trusted.covers(domain.domain())
                && domain.verification_status() == VerificationStatus::Verified,
            caa_record: self_managed.then(|| "0 issue \"letsencrypt.org\"".to_owned()),
            traffic_records: TrafficRecordsResponse::from(&dns.instructions(domain)),
        }
    }
}

/// A registered domain read on its own, with the certificate it serves.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DomainDetailResponse {
    /// The registration, as the list answers it.
    #[serde(flatten)]
    pub domain: DomainResponse,
    /// The certificate it serves; `null` when it was never given one or
    /// the tenant removed it.
    pub certificate: Option<CertificateResponse>,
}

impl DomainDetailResponse {
    /// `detail` as read back, its instructions built against `dns`.
    #[must_use]
    pub(crate) fn new(detail: DomainDetail, dns: &DnsSetup) -> Self {
        Self {
            domain: DomainResponse::new(&detail.domain, dns),
            certificate: detail.certificate.map(CertificateResponse::from),
        }
    }
}

/// The ways a tenant can point a domain at the proxy.
///
/// A `SelfManaged` domain gets `subdomain` and, when an address is
/// configured, `bare_domain`: one is used, never both, depending on whether
/// the name is a zone apex, where DNS forbids a `CNAME`. A `Delegated`
/// domain gets `delegation` instead.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TrafficRecordsResponse {
    /// For a subdomain, such as `hello.acme.com`. Absent when delegated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<TrafficRecordResponse>,
    /// For a bare domain, such as `acme.com`, which may not hold a `CNAME`.
    /// Absent when no proxy address is configured, and when delegated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bare_domain: Option<TrafficRecordResponse>,
    /// Add every one of these to hand the hostname over. Empty unless the
    /// domain is delegated.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub delegation: Vec<TrafficRecordResponse>,
}

impl From<&TrafficInstructions> for TrafficRecordsResponse {
    fn from(instructions: &TrafficInstructions) -> Self {
        Self {
            subdomain: instructions.alias().map(TrafficRecordResponse::from),
            bare_domain: instructions.address().map(TrafficRecordResponse::from),
            delegation: instructions
                .nameservers()
                .iter()
                .map(TrafficRecordResponse::from)
                .collect(),
        }
    }
}

/// One DNS record, as a tenant would type it into their provider.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TrafficRecordResponse {
    /// `CNAME`, `A` or `NS`.
    pub record_type: &'static str,
    /// The name to create the record at.
    pub name: String,
    /// What the record points at.
    pub value: String,
}

impl From<&TrafficRecord> for TrafficRecordResponse {
    fn from(record: &TrafficRecord) -> Self {
        Self {
            record_type: record.kind(),
            name: record.name().as_str().to_owned(),
            value: record.target(),
        }
    }
}

/// Who the tenant asked to run the DNS. Absent means `SelfManaged`: a
/// caller who says nothing has not asked us to hold their zone.
fn connection(value: Option<&str>) -> Result<DomainConnection, ApiError> {
    let Some(value) = value else {
        return Ok(DomainConnection::SelfManaged);
    };
    DomainConnection::parse(value).ok_or_else(|| {
        ApiError::validation(message!(
            "api-invalid-connection-expected-selfmanaged-or-delegated",
            format!("invalid connection: expected SelfManaged or Delegated, got {value}")
        ))
    })
}

/// The certificate state by the name the dashboard reads.
fn tls_name(status: TlsStatus) -> &'static str {
    match status {
        TlsStatus::NotRequired => "NotRequired",
        TlsStatus::Provisioning => "Provisioning",
        TlsStatus::Active => "Active",
        TlsStatus::Expired => "Expired",
        TlsStatus::NoCertificate => "NoCertificate",
    }
}
