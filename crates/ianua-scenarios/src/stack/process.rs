//! What the test process sets up once, before its first stack: the TLS
//! crypto provider and the logs, as the server's binary does at start.

use ianua_boot::logging::{self, LogFormat, LoggingConfig, LoggingError};

/// The variable a run may set to choose what the platform logs, as
/// `LOG_LEVEL` does for the server.
const LOG_LEVEL: &str = "IANUA_SCENARIO_LOG";

/// What is logged when the run names nothing: enough to read why a
/// scenario failed, which nextest shows only then.
const DEFAULT_LEVEL: &str = "info,sqlx=warn,async_nats=warn,hyper=warn";

/// Selects the `ring` crypto provider and sends the logs to standard
/// output, unless this process did either already.
pub(crate) fn set_up() {
    if tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::trace!("a TLS crypto provider was installed already");
    }
    let config = LoggingConfig {
        level: std::env::var(LOG_LEVEL).unwrap_or_else(|_| DEFAULT_LEVEL.to_owned()),
        format: LogFormat::Text,
    };
    match logging::init(&config) {
        Ok(()) | Err(LoggingError::Installed(_)) => {}
        Err(error) => eprintln!("the scenario logs could not be set up: {error}"),
    }
}
