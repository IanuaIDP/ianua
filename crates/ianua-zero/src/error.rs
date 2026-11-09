//! Why the gateway did not start, or did not stop cleanly.

use std::net::SocketAddr;

use ianua_boot::env::ConfigError;
use ianua_boot::logging::LoggingError;
use ianua_boot::shutdown::ShutdownError;

use crate::runtime::RuntimeError;

/// A part of the gateway that could not be built, and why.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// One part failed: `part` names it.
    #[error("{part} could not be built")]
    Part {
        /// The part, such as "the bus".
        part: &'static str,
        /// What failed.
        #[source]
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A stop was asked for before the gateway was built.
    #[error("the stop came before the gateway was ready")]
    Stopped,
}

impl PlatformError {
    /// A mapper from an error of building `part`.
    pub fn of<E>(part: &'static str) -> impl FnOnce(E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        move |cause| Self::Part {
            part,
            cause: Box::new(cause),
        }
    }
}

/// Why the gateway did not start, or did not stop cleanly.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// A setting was refused.
    #[error("the configuration was refused")]
    Config(#[from] ConfigError),
    /// The logs could not be set up.
    #[error("the logs could not be set up")]
    Logging(#[from] LoggingError),
    /// The platform the gateway stands on could not be built.
    #[error("the gateway could not be built")]
    Platform(#[from] PlatformError),
    /// A listener could not be opened.
    #[error("the {listener} listener could not listen on {address}")]
    Listen {
        /// Which listener: `public`, `acme`, `runner` or `connector`.
        listener: &'static str,
        /// The address it was to listen on.
        address: SocketAddr,
        /// Why it could not.
        #[source]
        cause: std::io::Error,
    },
    /// The status listener could not be opened.
    #[error("the status listener could not be opened")]
    Status(#[from] RuntimeError),
    /// The stop did not go cleanly.
    #[error("the gateway did not stop cleanly")]
    Shutdown(#[from] ShutdownError),
}

pub use ianua_boot::logging::described;

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal is described with every cause under it.
    #[test]
    fn a_refusal_is_described_with_its_causes() {
        let error = GatewayError::Config(ConfigError::missing("GATEWAY_DATABASE_URL"));

        assert_eq!(
            described(&error),
            "the configuration was refused\n  caused by: GATEWAY_DATABASE_URL must be set"
        );
    }

    /// A part that could not be built is named, with what failed under it.
    #[test]
    fn a_part_that_could_not_be_built_is_named() {
        let cause = std::io::Error::other("refused");
        let error = GatewayError::Platform(PlatformError::of("the bus")(cause));

        assert_eq!(
            described(&error),
            "the gateway could not be built\n  caused by: the bus could not be built\n  caused by: refused"
        );
    }
}
