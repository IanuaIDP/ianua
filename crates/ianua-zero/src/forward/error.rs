//! Why a request found no answer upstream, and why a service's pool could
//! not be built.
//!
//! The messages are for the gateway's own log and say what failed, never
//! with what: no header, credential or body is ever part of one. What a
//! client is told is the status, and the respond step keeps that generic.

use std::error::Error;

use http::StatusCode;
use http_body_util::LengthLimitError;
use ianua_domain::domains::proxy::pipeline::UpgradeRefusal;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::InvalidDnsNameError;

use super::screen;
use crate::connectors::{LinkError, link_error_in};

/// Why a request was not answered by a backend.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ForwardError {
    /// The service has no backends: none configured, or its name resolved
    /// to none. The route is refused rather than sent anywhere else.
    #[error("the service has no backends")]
    NoBackends,
    /// Every backend is set aside by its health check or its breaker.
    #[error("no backend of the service is taking traffic")]
    NoHealthyBackend,
    /// The backend is at an address the gateway may not reach.
    #[error("the backend is at an address the gateway may not reach")]
    AddressRefused,
    /// No request could be built for the backend and path.
    #[error("no request could be built for the backend")]
    InvalidAddress(#[source] http::Error),
    /// The backend did not start to answer within the service's timeout.
    #[error("the backend did not answer in time")]
    TimedOut,
    /// The backend could not be reached, or broke the exchange off.
    #[error("the backend could not be reached")]
    Unreachable(#[source] hyper_util::client::legacy::Error),
    /// The request body declared or streamed more than the pipeline takes.
    #[error("the request body is longer than the route takes")]
    RequestTooLarge,
    /// The answer declares a body longer than the pipeline inspects.
    #[error("the backend's answer is longer than the pipeline inspects")]
    ResponseTooLarge,
    /// The backend switched protocols on a request that did not ask to.
    #[error("the backend switched protocols unasked")]
    UnexpectedSwitch,
    /// The pipeline's rule refuses a protocol switch on this request.
    #[error("the request may not switch protocols here")]
    UpgradeRefused(UpgradeRefusal),
    /// The request asks to switch protocols on a connection that cannot.
    #[error("the connection cannot switch protocols")]
    UpgradeUnavailable,
    /// Every tunnel the gateway may hold is open.
    #[error("too many tunnels are open")]
    TunnelsExhausted,
    /// The service is reached through a tenant's connector, which holds no
    /// link to this gateway. It is never dialled from the gateway instead.
    #[error("the service's connector holds no link to this gateway")]
    ConnectorOffline,
    /// Every connection the connector's links may carry is in use.
    #[error("the service's connector carries as many connections as it may")]
    ConnectorBusy,
    /// The service has no pool: it is not active, or its pool could not be
    /// built.
    #[error("the service is not served")]
    NoPool,
}

impl ForwardError {
    /// The status a client is answered with.
    ///
    /// A switch refused because the pipeline inspects answers is one the
    /// route cannot offer, so it is `501`; refused because the caller is
    /// metered, `403`. A service whose connector holds no link here, or
    /// whose links are full, is `503`: the service is not there now, and
    /// may be again once the connector links.
    #[must_use]
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::NoBackends
            | Self::NoHealthyBackend
            | Self::TunnelsExhausted
            | Self::NoPool
            | Self::ConnectorOffline
            | Self::ConnectorBusy => StatusCode::SERVICE_UNAVAILABLE,
            Self::AddressRefused
            | Self::InvalidAddress(_)
            | Self::Unreachable(_)
            | Self::ResponseTooLarge
            | Self::UnexpectedSwitch => StatusCode::BAD_GATEWAY,
            Self::TimedOut => StatusCode::GATEWAY_TIMEOUT,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UpgradeRefused(UpgradeRefusal::InspectsResponses) => StatusCode::NOT_IMPLEMENTED,
            Self::UpgradeRefused(UpgradeRefusal::MeteredCaller) => StatusCode::FORBIDDEN,
            Self::UpgradeUnavailable => StatusCode::BAD_REQUEST,
        }
    }

    /// What a failed send means: a request body past its limit is the
    /// client's doing, a name that resolves only to refused addresses is
    /// the address rule's, a connector with no link or no room is its own,
    /// a backend outside a connector's scope is refused like an address,
    /// and anything else is the backend's.
    pub(super) fn of_send(error: hyper_util::client::legacy::Error) -> Self {
        if caused_by_body_limit(&error) {
            return Self::RequestTooLarge;
        }
        if let Some(linked) = link_error_in(&error).and_then(Self::of_link) {
            return linked;
        }
        if screen::refused_by_screen(&error) {
            return Self::AddressRefused;
        }
        Self::Unreachable(error)
    }

    /// What a connection that could not be opened down a link means, when
    /// it is not the backend's failure.
    fn of_link(error: &LinkError) -> Option<Self> {
        match error {
            LinkError::Offline | LinkError::Closed => Some(Self::ConnectorOffline),
            LinkError::Busy => Some(Self::ConnectorBusy),
            LinkError::OutsideScope | LinkError::Refused | LinkError::InvalidTarget => {
                Some(Self::AddressRefused)
            }
            LinkError::TimedOut => Some(Self::TimedOut),
            LinkError::Unreachable(_) | LinkError::Broken(_) | LinkError::Request(_) => None,
        }
    }
}

/// Whether a request body streaming past its cap caused `error`.
fn caused_by_body_limit(error: &(dyn Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(current) = cause {
        if current.is::<LengthLimitError>() {
            return true;
        }
        cause = current.source();
    }
    false
}

/// Why a service's pool could not be built. Its routes are refused until
/// it can be.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PoolError {
    /// The service presents a client certificate and its key was not
    /// handed in.
    #[error("the service's client certificate key is not available")]
    ClientKeyMissing,
    /// A certificate bundle holds no certificate.
    #[error("the certificate bundle holds no certificate")]
    NoCertificate,
    /// A key held no private key.
    #[error("the key holds no private key")]
    NoPrivateKey,
    /// A certificate or key could not be read.
    #[error("a certificate or key could not be read")]
    UnreadablePem(#[source] std::io::Error),
    /// The server name cannot be sent in a TLS handshake.
    #[error("the server name cannot be sent in a TLS handshake")]
    ServerName(#[source] InvalidDnsNameError),
    /// The TLS settings were refused.
    #[error("the TLS settings were refused")]
    Tls(#[source] rustls::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend that times out or cannot be reached is the backend's
    /// failure; a request the route refused is the client's.
    #[test]
    fn each_failure_answers_with_its_own_status() {
        assert_eq!(ForwardError::TimedOut.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            ForwardError::NoBackends.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ForwardError::RequestTooLarge.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            ForwardError::ResponseTooLarge.status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            ForwardError::ConnectorOffline.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn a_refused_switch_says_why_in_its_status() {
        assert_eq!(
            ForwardError::UpgradeRefused(UpgradeRefusal::InspectsResponses).status(),
            StatusCode::NOT_IMPLEMENTED
        );
        assert_eq!(
            ForwardError::UpgradeRefused(UpgradeRefusal::MeteredCaller).status(),
            StatusCode::FORBIDDEN
        );
    }

    /// A body past its cap is the client's doing, so it is told apart from
    /// a backend that failed.
    #[tokio::test]
    async fn a_body_past_its_cap_is_recognised() {
        let body = http_body_util::Full::new(hyper::body::Bytes::from_static(b"too long"));
        let limited = http_body_util::Limited::new(body, 1);
        let refused = http_body_util::BodyExt::collect(limited).await.unwrap_err();
        let cause: &(dyn Error + 'static) = &*refused;

        assert!(caused_by_body_limit(cause));
        assert!(!caused_by_body_limit(&std::io::Error::other("reset")));
    }
}
