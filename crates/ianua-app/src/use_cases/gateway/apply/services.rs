//! Writing the services a document declares, through the same domain steps
//! and checks as creating and editing one by hand.
//!
//! A document never carries a client key. A declared client certificate is
//! matched against the one the live service presents, and its sealed key is
//! kept; one the store has no key for is refused, since its key is given
//! only through the service's own TLS settings, where it is sealed.

use ianua_domain::domains::routing::backend::tls::{
    UpstreamClientCertificate, UpstreamTls, UpstreamTlsParams, UpstreamTrust,
};
use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::{CreateServiceParams, Service};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, ServiceId, Setting};

use crate::error::AppError;
use crate::ports::limits::ResourceKind;
use crate::use_cases::gateway::apply::state::{
    Apply, declared, ensure_within_limit, invalid, settle_status,
};
use crate::use_cases::gateway::document::ServiceDeclaration;
use crate::use_cases::routing::connectors::lookup::ensure_upstream_reachable;
use crate::use_cases::routing::lookup::routes_to;

/// Writes the service the document declares under `name`.
///
/// App sign-in is set later, once the routes it is checked against are in
/// place. Until then a service keeps the sign-in it had if the document
/// still gives it one, so it does not stop for the length of the import.
/// One the document drops is turned off here, before its upstream changes.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not create or update
///   routing, or a new service would exceed the plan.
/// - `AppError::NotFound` when it names a connector the tenant does not
///   have.
/// - `AppError::Domain` when the service refuses the change, such as an
///   upstream that pins no audience a signed-in route needs, an upstream it
///   may not reach, a revoked connector, or a client certificate whose key
///   is not on record.
/// - `AppError::Conflict` when the store refuses the name.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn write_service(apply: &mut Apply<'_>, name: &Label) -> Result<(), AppError> {
    let desired = apply.desired;
    let want = declared(&desired.services, name, |s| &s.name)?;
    let tenant = apply.tenant();
    let existing = apply.services.get(name).cloned();
    let upstream = deployable_upstream(apply, want, existing.as_ref())?;
    let ports = apply.applier.ports;
    ensure_upstream_reachable(
        ports.records.connector_store.as_ref(),
        &tenant,
        &upstream,
        &ports.checks.upstream_networks,
    )
    .await?;
    let service = service_as_declared(apply, want, upstream, existing).await?;
    ports
        .records
        .service_store
        .save(&tenant, &service)
        .await
        .map_err(AppError::from_domain)?;
    apply.services.insert(name.clone(), service);
    Ok(())
}

/// The service `want` declares, forwarding to `upstream`: `existing`
/// changed to it, or a new one when there is none.
///
/// # Errors
///
/// - `AppError::Forbidden` when a new service would exceed the plan.
/// - `AppError::Domain` when the service refuses the change.
/// - `AppError::Internal` on storage failure.
async fn service_as_declared(
    apply: &Apply<'_>,
    want: &ServiceDeclaration,
    upstream: Upstream,
    existing: Option<Service<ResolvedTenant>>,
) -> Result<Service<ResolvedTenant>, AppError> {
    let by = &apply.applier.by;
    let Some(existing) = existing else {
        ensure_within_limit(apply.applier, ResourceKind::Services).await?;
        return created_service(want, upstream, by);
    };
    let routes = routes_to(
        apply.applier.ports.records.route_store.as_ref(),
        &apply.tenant(),
        existing.id(),
    )
    .await?;
    updated_service(existing, want, upstream, &routes, by).map_err(AppError::from_domain)
}

/// The upstream `want` declares, with the live service's sealed client key
/// and the connector it names put back.
///
/// # Errors
///
/// - `AppError::Domain` when the declared upstream carries a client key
///   itself, names a connector the tenant does not have, or presents a
///   client certificate the live service holds no key for.
fn deployable_upstream(
    apply: &Apply<'_>,
    want: &ServiceDeclaration,
    existing: Option<&Service<ResolvedTenant>>,
) -> Result<Upstream, AppError> {
    let declared_tls = want.upstream.tls();
    if declared_tls.is_some_and(|tls| tls.client_certificate().is_some()) {
        return Err(invalid(format!(
            "service '{}' carries a client key; a document names the certificate alone",
            want.name
        )));
    }
    let upstream = with_client_certificate(want, existing)?;
    let Setting::Set(connector) = &want.connector else {
        return Ok(upstream);
    };
    let found = apply
        .connectors
        .iter()
        .find(|held| held.name() == connector)
        .ok_or_else(|| {
            invalid(format!(
                "service '{}' is reached through connector '{connector}', which the tenant \
                 does not have",
                want.name
            ))
        })?;
    Ok(upstream.through_connector(*found.id()))
}

/// The declared upstream, presenting the client certificate `want` names
/// with the key `existing` holds for it.
fn with_client_certificate(
    want: &ServiceDeclaration,
    existing: Option<&Service<ResolvedTenant>>,
) -> Result<Upstream, AppError> {
    let Setting::Set(certificate) = &want.client_certificate else {
        return Ok(want.upstream.clone());
    };
    let held = existing
        .and_then(|service| service.upstream().tls())
        .and_then(UpstreamTls::client_certificate)
        .filter(|held| held.certificate() == certificate)
        .ok_or_else(|| unknown_client_certificate(&want.name))?;
    let tls = tls_presenting(want.upstream.tls(), held).map_err(AppError::from_domain)?;
    Ok(want.upstream.clone().with_tls(tls))
}

/// `declared` TLS settings, or the public roots when none are declared,
/// presenting `held`.
fn tls_presenting(
    declared: Option<&UpstreamTls>,
    held: &UpstreamClientCertificate,
) -> Result<UpstreamTls, DomainError> {
    let (trust, server_name) = declared.map_or((UpstreamTrust::default(), Setting::Unset), |tls| {
        (
            tls.trust().clone(),
            Setting::from_stored(tls.server_name().cloned()),
        )
    });
    UpstreamTls::new(UpstreamTlsParams {
        trust,
        client_certificate: Setting::Set(held.clone()),
        server_name,
    })
    .map_err(DomainError::from)
}

/// The refusal of a client certificate the store holds no key for.
fn unknown_client_certificate(service: &Label) -> AppError {
    invalid(format!(
        "service '{service}' presents a client certificate whose key is not on record; give \
         it through the service's TLS settings, where the key is sealed"
    ))
}

/// A new service as `want` declares it, forwarding to `upstream`, without
/// app sign-in yet.
fn created_service(
    want: &ServiceDeclaration,
    upstream: Upstream,
    by: &RoutingControl<'_>,
) -> Result<Service<ResolvedTenant>, AppError> {
    let mut service = Service::create(
        CreateServiceParams {
            id: ServiceId::new(),
            name: want.name.clone(),
            upstream,
            health_check: want.health_check.clone(),
        },
        by,
    )
    .map_err(AppError::from_domain)?;
    settle_status(&mut service, want.status, by).map_err(AppError::from_domain)?;
    Ok(service)
}

/// `service` changed to what `want` declares, forwarding to `upstream` and
/// held to the `routes` that forward to it.
fn updated_service(
    mut service: Service<ResolvedTenant>,
    want: &ServiceDeclaration,
    upstream: Upstream,
    routes: &[Route<ResolvedTenant>],
    by: &RoutingControl<'_>,
) -> Result<Service<ResolvedTenant>, DomainError> {
    drop_sign_in_left_out(&mut service, want, by)?;
    if service.upstream() != &upstream {
        service.replace_upstream(upstream, routes, by)?;
    }
    if service.health_check() != &want.health_check {
        service.change_health_check(want.health_check.clone(), by)?;
    }
    settle_status(&mut service, want.status, by)?;
    Ok(service)
}

/// Turns off the sign-in settings `want` no longer gives `service`.
fn drop_sign_in_left_out(
    service: &mut Service<ResolvedTenant>,
    want: &ServiceDeclaration,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    if want.app_sign_in.is_unset() && service.app_sign_in().is_some() {
        service.change_app_sign_in(Setting::Unset, by)?;
    }
    if want.accepts_app_sign_in.is_unset() && service.accepted_sign_in().is_some() {
        service.accept_app_sign_in_of(Setting::Unset, by)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{CertificatePem, SealedSecret};

    use super::*;
    use crate::test_support::routing::{pinned_upstream, service_named};
    use crate::use_cases::gateway::document::GatewayConfig;
    use crate::use_cases::gateway::lookup::LiveGateway;

    fn certificate() -> CertificatePem {
        CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
            .unwrap()
    }

    fn presenting(certificate: CertificatePem) -> Service<ResolvedTenant> {
        let tls = tls_presenting(
            None,
            &UpstreamClientCertificate::new(
                certificate,
                SealedSecret::new("v1.sealed-client-key").unwrap(),
            ),
        )
        .unwrap();
        service_named(
            "payroll",
            pinned_upstream("https://payroll:8443", "payroll").with_tls(tls),
        )
    }

    fn declared_with(certificate: CertificatePem) -> ServiceDeclaration {
        let live = presenting(certificate.clone());
        let mut declared = GatewayConfig::of(&LiveGateway {
            services: vec![live],
            pipelines: Vec::new(),
            routes: Vec::new(),
            stream_routes: Vec::new(),
            egress_policies: Vec::new(),
            consumers: Vec::new(),
            connectors: Vec::new(),
        })
        .unwrap()
        .services
        .remove(0);
        declared.client_certificate = Setting::Set(certificate);
        declared
    }

    /// Ann's document names the certificate the payroll service presents.
    /// The sealed key on record is kept, never read from the document.
    #[test]
    fn a_declared_certificate_keeps_the_key_on_record() {
        let live = presenting(certificate());

        let upstream = with_client_certificate(&declared_with(certificate()), Some(&live)).unwrap();

        assert_eq!(&upstream, live.upstream());
    }

    /// A declared client certificate is refused when no existing service
    /// holds its sealed key.
    #[test]
    fn a_certificate_without_a_key_on_record_is_refused() {
        let result = with_client_certificate(&declared_with(certificate()), None);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }
}
