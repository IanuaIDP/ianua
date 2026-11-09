//! Custom domain endpoints: a tenant's registered domains, their proof and
//! certificates, handover between tenants, and the records of a delegated
//! zone.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::domain::certificates::{CertificateResponse, UploadCertificateBody};
use crate::dto::domain::dns_records::{
    DnsRecordSetResponse, RemoveDnsRecordBody, SetDnsRecordBody,
};
use crate::dto::domain::handover::{AcceptHandoverBody, HandoverOfferResponse, OfferHandoverBody};
use crate::dto::domain::registration::{
    AddDomainBody, DomainDetailResponse, DomainResponse, TrafficRecordResponse,
    TrafficRecordsResponse,
};
use crate::dto::domain::verification::VerificationStatusResponse;
use crate::handlers::domain::{certificates, dns_records, handover, registration, verification};
use crate::method::{get, post, put, shared};
use crate::state::ApiState;

/// The custom domain endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let tenant = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";
    let domains = format!("{tenant}/domains");
    registration_routes(&domains).merge(ownership_routes(tenant, &domains))
}

/// Registers custom domains and the certificates proving their TLS identity.
fn registration_routes(domains: &str) -> Router<ApiState> {
    Router::new()
        .route(
            domains,
            get(registration::list_domains).post(shared(registration::add_domain)),
        )
        .route(
            &format!("{domains}/{{id}}"),
            get(registration::get_domain).delete(shared(registration::remove_domain)),
        )
        .route(
            &format!("{domains}/{{id}}/certificate"),
            put(certificates::upload_certificate).delete(shared(certificates::remove_certificate)),
        )
        .route(
            &format!("{domains}/{{id}}/verify"),
            post(verification::verify_domain),
        )
        .route(
            &format!("{domains}/{{id}}/provision-tls"),
            post(certificates::provision_tls),
        )
}

/// Registers domain handovers and delegated DNS record changes.
fn ownership_routes(tenant: &str, domains: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{domains}/{{id}}/handover"),
            post(handover::offer_domain_handover),
        )
        .route(
            &format!("{tenant}/domain-handovers/accept"),
            post(handover::accept_domain_handover),
        )
        .route(
            &format!("{domains}/{{id}}/dns"),
            get(dns_records::list_dns_records)
                .put(shared(dns_records::set_dns_record))
                .delete(shared(dns_records::remove_dns_record)),
        )
}

/// The custom domain part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        registration::list_domains,
        registration::add_domain,
        registration::get_domain,
        registration::remove_domain,
        verification::verify_domain,
        certificates::provision_tls,
        certificates::upload_certificate,
        certificates::remove_certificate,
        handover::offer_domain_handover,
        handover::accept_domain_handover,
        dns_records::list_dns_records,
        dns_records::set_dns_record,
        dns_records::remove_dns_record,
    ),
    components(schemas(
        AddDomainBody,
        DomainResponse,
        DomainDetailResponse,
        UploadCertificateBody,
        CertificateResponse,
        TrafficRecordsResponse,
        TrafficRecordResponse,
        VerificationStatusResponse,
        OfferHandoverBody,
        HandoverOfferResponse,
        AcceptHandoverBody,
        SetDnsRecordBody,
        RemoveDnsRecordBody,
        DnsRecordSetResponse,
    ))
)]
pub(crate) struct Document;
