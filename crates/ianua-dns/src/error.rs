//! Why the nameservers did not start, or did not stop cleanly.

use std::net::SocketAddr;

use ianua_boot::env::ConfigError;
use ianua_boot::logging::LoggingError;
use ianua_boot::shutdown::ShutdownError;

use crate::wire::Transport;

/// Why the nameservers did not start, or did not stop cleanly.
#[derive(Debug, thiserror::Error)]
pub enum NameserverError {
    /// A setting was missing or refused.
    #[error("the settings were refused")]
    Config(#[from] ConfigError),
    /// The logs could not be set up.
    #[error("the logs could not be set up")]
    Logging(#[from] LoggingError),
    /// A port could not be taken. A nameserver that cannot answer is
    /// absent, not degraded, so it does not start. On Ubuntu the usual
    /// cause is `systemd-resolved`, whose stub listener holds
    /// `127.0.0.53:53`.
    #[error("cannot listen for DNS over {transport} on {address}")]
    Bind {
        /// The transport whose port was refused.
        transport: Transport,
        /// The address asked for.
        address: SocketAddr,
        /// Why it was refused.
        #[source]
        cause: std::io::Error,
    },
    /// The stop signal could not be listened for, or tasks were still
    /// running when the grace period ended.
    #[error("the nameservers did not stop cleanly")]
    Shutdown(#[from] ShutdownError),
}
