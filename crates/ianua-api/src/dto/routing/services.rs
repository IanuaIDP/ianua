//! Service bodies: the backends a tenant's routes forward to, and how their
//! backends are probed.

use ianua_app::ports::routing::{BackendHealth, BackendVerdict};
use ianua_app::use_cases::routing::services::upstream_tls::{
    ClientCertificateRequest, UpstreamTlsRequest,
};
use ianua_app::use_cases::routing::services::{
    ChangeTlsRequest, CreateRequest, LiveHealth, ServiceHealth, UpdateRequest,
};
use ianua_domain::domains::routing::backend::health_check::{
    ActiveHealthCheck, ActiveHealthCheckParams, HealthCheckPolicy,
};
use ianua_domain::domains::routing::backend::tls::{UpstreamTls, UpstreamTrust};
use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CertificatePem, DomainName, Label, Seconds, ServiceId, Setting, UrlPath,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::routing::sign_in::{AppSignInView, SignInDeliveryBody};
use crate::error::ApiError;

/// Probe settings on the wire.
///
/// `enabled: false` turns probing off, which means every backend is always
/// eligible, not "unknown health". An unprobed backend that could not receive
/// traffic would be a liveness signal failing closed.
///
/// Every field is optional and falls back to the platform default, so turning
/// probing on at a chosen path does not oblige a caller to supply five timing
/// numbers as well. The defaults live in the domain and are read from there.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(default)]
pub(crate) struct HealthCheckBody {
    /// Whether backends are probed at all.
    pub enabled: bool,
    /// Path requested on each backend.
    pub path: String,
    /// Seconds between probes. At least 5.
    pub interval_secs: u32,
    /// Seconds a single probe may take. Must be shorter than the interval.
    pub timeout_secs: u32,
    /// Consecutive successes before a backend is eligible again.
    pub healthy_threshold: u32,
    /// Consecutive failures before a backend is taken out.
    pub unhealthy_threshold: u32,
    /// Below this share of healthy backends, health is ignored entirely and
    /// traffic balances across all of them. Zero turns that off.
    pub panic_threshold_percent: u32,
}

impl Default for HealthCheckBody {
    fn default() -> Self {
        Self::from(&ActiveHealthCheck::default())
    }
}

impl From<&ActiveHealthCheck> for HealthCheckBody {
    fn from(check: &ActiveHealthCheck) -> Self {
        Self {
            enabled: true,
            path: check.path().as_str().to_owned(),
            interval_secs: check.interval_secs().get(),
            timeout_secs: check.timeout_secs().get(),
            healthy_threshold: check.healthy_threshold(),
            unhealthy_threshold: check.unhealthy_threshold(),
            panic_threshold_percent: check.panic_threshold_percent(),
        }
    }
}

impl TryFrom<HealthCheckBody> for HealthCheckPolicy {
    type Error = ApiError;

    fn try_from(body: HealthCheckBody) -> Result<Self, Self::Error> {
        if !body.enabled {
            return Ok(Self::Disabled);
        }
        let check = ActiveHealthCheck::new(ActiveHealthCheckParams {
            path: UrlPath::new(body.path).map_err(ApiError::validation)?,
            interval_secs: Seconds::new(body.interval_secs),
            timeout_secs: Seconds::new(body.timeout_secs),
            healthy_threshold: body.healthy_threshold,
            unhealthy_threshold: body.unhealthy_threshold,
            panic_threshold_percent: body.panic_threshold_percent,
        })
        .map_err(ApiError::validation)?;
        Ok(Self::Active(check))
    }
}

/// Reads a health-check policy from the wire.
///
/// Omitting the field means "no opinion": the default on create, no change on
/// update. Sending one with `enabled: false` turns probing off.
fn health_check(body: Option<HealthCheckBody>) -> Result<Option<HealthCheckPolicy>, ApiError> {
    body.map(HealthCheckPolicy::try_from).transpose()
}

/// How the gateway is to open TLS to a service's upstream, as an
/// administrator gives it. Verification is never switched off: a backend on
/// a private PKI names the CA that signed it instead.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpstreamTlsBody {
    /// The PEM bundle of the CAs the upstream's certificate must chain to.
    /// Omit to check it against the public roots.
    #[serde(default)]
    pub ca_certificates: Option<String>,
    /// The certificate the gateway presents when the upstream asks for
    /// one, with its private key. Omit for none.
    #[serde(default)]
    pub client_certificate: Option<ClientCertificateBody>,
    /// The name sent as SNI and checked against the upstream's
    /// certificate, when it is not the host in the upstream's address. One
    /// name, never a wildcard.
    #[serde(default)]
    pub server_name: Option<String>,
}

/// A client certificate and its private key. The key is sealed before it
/// is stored and is never answered back; the type has no `Debug`, so it
/// never prints.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ClientCertificateBody {
    /// The PEM certificate chain presented.
    pub certificate: String,
    /// The PEM private key.
    pub private_key: String,
}

impl TryFrom<UpstreamTlsBody> for UpstreamTlsRequest {
    type Error = ApiError;

    fn try_from(body: UpstreamTlsBody) -> Result<Self, Self::Error> {
        let trust = match body.ca_certificates {
            None => UpstreamTrust::PublicRoots,
            Some(pem) => {
                UpstreamTrust::PrivateCa(CertificatePem::new(pem).map_err(ApiError::validation)?)
            }
        };
        let client_certificate = body
            .client_certificate
            .map(ClientCertificateRequest::try_from)
            .transpose()?;
        let server_name = body
            .server_name
            .map(DomainName::new)
            .transpose()
            .map_err(ApiError::validation)?;
        Ok(Self {
            trust,
            client_certificate: Setting::from_stored(client_certificate),
            server_name: Setting::from_stored(server_name),
        })
    }
}

impl TryFrom<ClientCertificateBody> for ClientCertificateRequest {
    type Error = ApiError;

    fn try_from(body: ClientCertificateBody) -> Result<Self, Self::Error> {
        Ok(Self {
            certificate: CertificatePem::new(body.certificate).map_err(ApiError::validation)?,
            private_key: Secret::new(body.private_key),
        })
    }
}

/// Reads optional upstream TLS from the wire: `None` is no TLS settings of
/// the service's own.
fn upstream_tls(body: Option<UpstreamTlsBody>) -> Result<Setting<UpstreamTlsRequest>, ApiError> {
    let tls = body.map(UpstreamTlsRequest::try_from).transpose()?;
    Ok(Setting::from_stored(tls))
}

/// Request body for setting a service's upstream TLS.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeServiceTlsBody {
    /// The TLS to open to the upstream from now on.
    pub tls: UpstreamTlsBody,
}

impl ChangeServiceTlsBody {
    /// The change this body asks of `service`.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] for a certificate that is not PEM or
    /// a server name that is not a domain name.
    pub(crate) fn into_request(self, service: ServiceId) -> Result<ChangeTlsRequest, ApiError> {
        Ok(ChangeTlsRequest {
            service_id: service,
            tls: upstream_tls(Some(self.tls))?,
        })
    }
}

/// How the gateway opens TLS to a service's upstream, as it is read back.
/// The client certificate's private key is never answered.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UpstreamTlsView {
    /// The PEM bundle of the CAs trusted, or `null` for the public roots.
    pub ca_certificates: Option<String>,
    /// The PEM certificate presented to the upstream, or `null` for none.
    pub client_certificate: Option<String>,
    /// The name sent as SNI, or `null` for the host in the address.
    pub server_name: Option<String>,
}

impl From<&UpstreamTls> for UpstreamTlsView {
    fn from(tls: &UpstreamTls) -> Self {
        let ca_certificates = match tls.trust() {
            UpstreamTrust::PublicRoots => None,
            UpstreamTrust::PrivateCa(bundle) => Some(bundle.as_str().to_owned()),
        };
        Self {
            ca_certificates,
            client_certificate: tls
                .client_certificate()
                .map(|client| client.certificate().as_str().to_owned()),
            server_name: tls.server_name().map(|name| name.as_str().to_owned()),
        }
    }
}

/// Request body for creating a service.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateServiceBody {
    /// Service name, unique within the tenant.
    pub name: String,
    /// Where requests go, and how they are addressed: its backends,
    /// retries, balancing, circuit breaker, assertion audience, and
    /// `reach` (`"direct"`, or `{"connector": <id>}` to be dialled through
    /// one of the tenant's connectors). It carries no TLS; that is `tls`.
    #[schema(value_type = Object)]
    pub upstream: Upstream,
    /// How this service's backends are probed. Omit for the platform default.
    #[serde(default)]
    pub health_check: Option<HealthCheckBody>,
    /// How the gateway opens TLS to the upstream. Omit to check it against
    /// the public roots with no client certificate.
    #[serde(default)]
    pub tls: Option<UpstreamTlsBody>,
}

impl TryFrom<CreateServiceBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateServiceBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            upstream: body.upstream,
            health_check: health_check(body.health_check)?.unwrap_or_default(),
            tls: upstream_tls(body.tls)?,
        })
    }
}

/// Request body for changing a service. Every field is optional; an omitted
/// one is left as it is.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateServiceBody {
    /// A new name.
    pub name: Option<String>,
    /// A new upstream. It carries no TLS: the service keeps its own, set
    /// at `.../services/{id}/tls`.
    #[schema(value_type = Option<Object>)]
    pub upstream: Option<Upstream>,
    /// Replace the probe settings. Omit to leave them as they are.
    #[serde(default)]
    pub health_check: Option<HealthCheckBody>,
}

impl UpdateServiceBody {
    /// The change this body asks of `service`.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] for an invalid name or probe
    /// configuration.
    pub(crate) fn into_request(self, service: ServiceId) -> Result<UpdateRequest, ApiError> {
        Ok(UpdateRequest {
            service_id: service,
            name: self
                .name
                .map(|name| Label::new("name", name))
                .transpose()
                .map_err(ApiError::validation)?,
            upstream: self.upstream,
            health_check: health_check(self.health_check)?,
        })
    }
}

/// The upstream destination, health checks and transport settings used by routes.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ServiceResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// Service name.
    pub name: String,
    /// Where requests go, and how they are addressed. Its TLS is answered
    /// on its own, in `tls`.
    #[schema(value_type = Object)]
    pub upstream: Upstream,
    /// How the gateway opens TLS to the upstream, or `null` for the public
    /// roots with no client certificate.
    pub tls: Option<UpstreamTlsView>,
    /// `null` when probing is off: every backend always eligible.
    pub health_check: Option<HealthCheckBody>,
    /// Where and how people sign in on the service's hosts; `null` for none.
    pub app_sign_in: Option<AppSignInView>,
    /// The service whose app sign-in this one accepts instead, if any.
    pub accepts_app_sign_in_of: Option<Uuid>,
    /// How that sign-in reaches this service; `null` when it accepts none.
    pub sign_in_delivery: Option<SignInDeliveryBody>,
    /// `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::route_status)]
    pub status: RouteStatus,
    /// When the service was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Service<ResolvedTenant>> for ServiceResponse {
    fn from(s: Service<ResolvedTenant>) -> Self {
        Self {
            id: *s.id().as_uuid(),
            name: s.name().as_str().to_owned(),
            upstream: s.upstream().without_tls(),
            tls: s.upstream().tls().map(UpstreamTlsView::from),
            health_check: s.health_check().active().map(HealthCheckBody::from),
            app_sign_in: s.app_sign_in().map(AppSignInView::from),
            accepts_app_sign_in_of: s.accepts_app_sign_in_of().map(|id| *id.as_uuid()),
            sign_in_delivery: s
                .accepted_sign_in()
                .map(|accepted| SignInDeliveryBody::from(accepted.delivery())),
            status: s.status(),
            created_at: s.created_at(),
            updated_at: s.updated_at(),
        }
    }
}

/// What the gateway's health checks last saw of a service's backends.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ServiceHealthResponse {
    /// How the backends are probed; `null` when probing is off.
    pub health_check: Option<HealthCheckBody>,
    /// `not_probed` (probing is off, every backend gets traffic),
    /// `unknown` (probed, and no gateway reported in the last few probe
    /// intervals) or `reported`.
    pub state: &'static str,
    /// When the gateway's probes last reported; `null` unless `reported`.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub observed_at: Option<OffsetDateTime>,
    /// Each backend probed and its verdict; empty unless `reported`.
    pub backends: Vec<BackendHealthView>,
}

/// One backend and what its health checks last concluded.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct BackendHealthView {
    /// The backend, as the gateway dials it.
    pub backend: String,
    /// `up` (it gets traffic) or `down` (it failed its checks in a row and
    /// gets none until it passes again).
    pub verdict: &'static str,
}

impl From<ServiceHealth> for ServiceHealthResponse {
    fn from(health: ServiceHealth) -> Self {
        let health_check = health.check.active().map(HealthCheckBody::from);
        match health.live {
            LiveHealth::NotProbed => Self::without_report(health_check, "not_probed"),
            LiveHealth::Unknown => Self::without_report(health_check, "unknown"),
            LiveHealth::Reported(report) => Self {
                health_check,
                state: "reported",
                observed_at: Some(report.observed_at),
                backends: report
                    .backends
                    .into_iter()
                    .map(BackendHealthView::from)
                    .collect(),
            },
        }
    }
}

impl ServiceHealthResponse {
    /// The answer for a service with no health report yet: its check, if
    /// it has one, and `state`.
    fn without_report(health_check: Option<HealthCheckBody>, state: &'static str) -> Self {
        Self {
            health_check,
            state,
            observed_at: None,
            backends: Vec::new(),
        }
    }
}

impl From<BackendHealth> for BackendHealthView {
    fn from(backend: BackendHealth) -> Self {
        Self {
            backend: backend.backend.as_str().to_owned(),
            verdict: match backend.verdict {
                BackendVerdict::Up => "up",
                BackendVerdict::Down => "down",
            },
        }
    }
}

/// The id of a newly created service.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateServiceResponse {
    /// The new service.
    pub id: Uuid,
}

impl From<ServiceId> for CreateServiceResponse {
    fn from(id: ServiceId) -> Self {
        Self { id: *id.as_uuid() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A health check that names only its path takes every timing and
    /// threshold from the platform default.
    #[test]
    fn a_health_check_naming_only_a_path_takes_the_platform_timings() {
        let body: HealthCheckBody =
            serde_json::from_str(r#"{"enabled":true,"path":"/health"}"#).expect("a health check");
        let default = ActiveHealthCheck::default();

        assert_eq!(body.path, "/health");
        assert_eq!(body.interval_secs, default.interval_secs().get());
        assert_eq!(body.timeout_secs, default.timeout_secs().get());
        assert_eq!(body.healthy_threshold, default.healthy_threshold());
        assert_eq!(body.unhealthy_threshold, default.unhealthy_threshold());
        assert_eq!(
            body.panic_threshold_percent,
            default.panic_threshold_percent()
        );
    }

    /// An empty health check is the platform's default check.
    #[test]
    fn an_empty_health_check_is_the_platform_default() {
        let body: HealthCheckBody = serde_json::from_str("{}").expect("a health check");

        assert_eq!(
            HealthCheckPolicy::try_from(body).ok(),
            Some(HealthCheckPolicy::default())
        );
    }

    /// Switching the health check off takes only `enabled: false`.
    #[test]
    fn disabling_needs_no_other_field() {
        let body: HealthCheckBody =
            serde_json::from_str(r#"{"enabled":false}"#).expect("a health check");

        assert_eq!(
            HealthCheckPolicy::try_from(body).ok(),
            Some(HealthCheckPolicy::Disabled)
        );
    }

    /// Omitting the probe settings leaves them as they are; sending them
    /// replaces them. Answering with a default for the absent case would
    /// silently re-enable probing a tenant had turned off.
    #[test]
    fn omitting_the_health_check_changes_nothing_and_sending_one_replaces_it() {
        assert_eq!(health_check(None).ok(), Some(None));

        let disabled: HealthCheckBody =
            serde_json::from_str(r#"{"enabled":false}"#).expect("a health check");
        assert_eq!(
            health_check(Some(disabled)).ok(),
            Some(Some(HealthCheckPolicy::Disabled))
        );
    }
}
