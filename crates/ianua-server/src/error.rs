//! Why the server did not start, or did not stop cleanly.

use ianua_boot::env::ConfigError;
use ianua_boot::logging::LoggingError;
use ianua_boot::shutdown::ShutdownError;

use crate::command::CommandError;
use crate::connector_pki::ConnectorPkiError;
use crate::demo::DemoError;
use crate::install::InstallError;
use crate::internal_pki::InternalPkiError;
use crate::link_pki::LinkPkiError;

/// A part of the platform that could not be built, and why.
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
    /// The audit log is not sealed from the app's role and the
    /// configuration requires it.
    #[error(
        "the app's role can change or remove audit records; run the migrate command with \
         MIGRATION_DATABASE_URL, or set AUDIT_REQUIRE_SEALED=false outside production"
    )]
    Unsealed,
    /// A stop was asked for before the platform was built.
    #[error("the stop came before the platform was ready")]
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

/// Why the server did not start, or did not stop cleanly.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The command line named nothing the binary does.
    #[error(transparent)]
    Command(#[from] CommandError),
    /// A setting was refused.
    #[error("the configuration was refused")]
    Config(#[from] ConfigError),
    /// The logs could not be set up.
    #[error("the logs could not be set up")]
    Logging(#[from] LoggingError),
    /// The platform could not be built.
    #[error("the platform could not be built")]
    Platform(#[from] PlatformError),
    /// A listener could not be opened.
    #[error("the {listener} listener could not listen on {address}")]
    Listen {
        /// Which listener: `public`, `internal`, `relay` or `network filter`.
        listener: &'static str,
        /// The address it was to listen on.
        address: std::net::SocketAddr,
        /// Why it could not.
        #[source]
        cause: std::io::Error,
    },
    /// The stop did not go cleanly.
    #[error("the server did not stop cleanly")]
    Shutdown(#[from] ShutdownError),
    /// A command that is not a one-off task on the platform was asked to
    /// run as one: serving never ends on its own, and migrating builds no
    /// platform.
    #[error("this command is not a one-off task on the platform")]
    NotOneOff,
    /// The installation's organization or the first operator could not be
    /// made.
    #[error("the installation could not be made")]
    Install(#[from] InstallError),
    /// The demonstration organization could not be seeded.
    #[error("the demo could not be seeded")]
    Demo(#[from] DemoError),
    /// The nameserver link's certificates were not written.
    #[error("the nameserver link's certificates were not written")]
    LinkPki(#[from] LinkPkiError),
    /// The connector authority's files were not written.
    #[error("the connector authority's files were not written")]
    ConnectorPki(#[from] ConnectorPkiError),
    /// The internal links' certificates were not written.
    #[error("the internal links' certificates were not written")]
    InternalPki(#[from] InternalPkiError),
    /// The relay listener's mutual TLS could not be set up from its files.
    #[error("the relay listener's mutual TLS could not be set up")]
    RelayTls(#[from] crate::mutual_listener::MutualTlsError),
    /// The sandbox gate could not listen on its socket.
    #[error("the sandbox gate could not listen on {socket}")]
    Gate {
        /// The socket it was to listen on.
        socket: std::path::PathBuf,
        /// Why it could not.
        #[source]
        cause: std::io::Error,
    },
}

pub use ianua_boot::logging::described;

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal is described with every cause under it.
    #[test]
    fn a_refusal_is_described_with_its_causes() {
        let error = ServerError::Config(ConfigError::missing("DATABASE_URL"));

        assert_eq!(
            described(&error),
            "the configuration was refused\n  caused by: DATABASE_URL must be set"
        );
    }
}
