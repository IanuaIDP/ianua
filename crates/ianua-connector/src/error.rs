//! Why the connector could not start or had to stop. None of it names the
//! enrollment code, the key or a certificate.

use ianua_boot::env::ConfigError;
use ianua_boot::logging::LoggingError;
use ianua_boot::shutdown::ShutdownError;
use ianua_domain::shared::errors::causes;

use crate::api::ClientError;
use crate::link::LinkError;
use crate::state::StateError;
use crate::tls::TlsError;

/// Why the connector could not start or had to stop.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    /// A setting was refused.
    #[error("the configuration was refused")]
    Config(#[from] ConfigError),
    /// The logs could not be set up.
    #[error("the logs could not be set up")]
    Logging(#[from] LoggingError),
    /// The stop signal could not be listened for, or relays outlasted the
    /// grace period.
    #[error("the connector did not stop cleanly")]
    Shutdown(#[from] ShutdownError),
    /// The state folder could not be used.
    #[error("the state folder could not be used")]
    State(#[from] StateError),
    /// The API client could not be built.
    #[error("the API client could not be built")]
    Client(#[from] ClientError),
    /// The kept certificate could not be used for TLS.
    #[error("the connector's certificate could not be used")]
    Tls(#[from] TlsError),
    /// The links could not be set up.
    #[error("the links to the gateway could not be set up")]
    Link(#[from] LinkError),
    /// The connector has not enrolled and was given no code to do so.
    #[error(
        "the connector has not enrolled yet: set CONNECTOR_ENROLLMENT_CODE or \
         CONNECTOR_ENROLLMENT_CODE_FILE to the code shown when the connector was created"
    )]
    NoCode,
    /// The API refused the enrollment code.
    #[error(
        "the API refused the enrollment (status {status}): the code is spent, has expired, or \
         its connector was revoked; create a new code in the dashboard"
    )]
    EnrollmentRefused {
        /// The status it answered.
        status: u16,
    },
    /// The API refused to renew the certificate.
    #[error(
        "the API refused to renew the connector's certificate (status {status}): the connector \
         was revoked or its key is no longer taken; create a new connector to enroll again"
    )]
    RenewalRefused {
        /// The status it answered.
        status: u16,
    },
    /// The connector was stopped before it enrolled.
    #[error("stopped before the connector enrolled")]
    StoppedBeforeEnrolling,
}

/// `error` with every cause under it, for the one line the binary prints
/// when it cannot start or had to stop.
#[must_use]
pub fn described(error: &ConnectorError) -> String {
    causes(error)
}
