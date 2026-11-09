//! Why the runner could not start or stop cleanly. None of it names a key,
//! a token or the SVID.

use ianua_boot::env::ConfigError;
use ianua_boot::logging::LoggingError;
use ianua_boot::shutdown::ShutdownError;
use ianua_domain::shared::errors::{DomainError, causes};

/// Why the runner could not start or stop cleanly.
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    /// A setting was refused.
    #[error("the configuration was refused")]
    Config(#[from] ConfigError),
    /// The logs could not be set up.
    #[error("the logs could not be set up")]
    Logging(#[from] LoggingError),
    /// The stop signal could not be listened for, or tasks outlasted the
    /// grace period.
    #[error("the runner did not stop cleanly")]
    Shutdown(#[from] ShutdownError),
    /// A part the runner is built from could not be built.
    #[error("{what} could not be built")]
    Build {
        /// The part.
        what: &'static str,
        /// Why.
        #[source]
        cause: DomainError,
    },
    /// The agent's listener could not be opened.
    #[error("the agent's listener could not be opened")]
    Listen(#[source] std::io::Error),
}

impl RunnerError {
    /// A refusal to build `what`, for a `map_err`.
    pub(crate) fn of(what: &'static str) -> impl FnOnce(DomainError) -> Self {
        move |cause| Self::Build { what, cause }
    }
}

/// `error` with every cause under it, for the one line the binary prints
/// when it cannot start.
#[must_use]
pub fn described(error: &RunnerError) -> String {
    causes(error)
}
