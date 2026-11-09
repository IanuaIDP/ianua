//! A company's own databases, the systems Protected data steps reach behind
//! the gateway, each started in a container for one scenario on a port of
//! loopback and removed when dropped:
//!
//! - [`postgres`], [`mysql`], [`redis`] and [`mongodb`], each holding Acme's
//!   three orders (totals 40, 120 and 300) and a login made for workflows.
//! - [`vector_server`], a Qdrant-protocol server, and [`embedding_server`],
//!   Hugging Face's text-embeddings-inference, for the platform's memory.
//!
//! Each serves TLS or not as [`Serving`] says. Serving TLS, it holds a
//! certificate for the name given, from an authority made for that one
//! system, which the scenario names when it opens the route.

mod certificate;
mod container;
mod databases;

pub use certificate::SystemCertificate;
pub use container::Container;
pub(crate) use container::ContainerSpec;
pub use databases::{embedding_server, mongodb, mysql, postgres, redis, vector_server};

/// The password every system's workflow login has: words, not a key.
pub const LOGIN_PASSWORD: &str = "acme workflows password";

/// Whether a system serves TLS.
#[derive(Debug, Clone, Copy)]
pub enum Serving {
    /// None: the company's system speaks in the clear.
    Plain,
    /// TLS, with a certificate for this name.
    Tls(&'static str),
}

/// A company's system, running, with its workflow login.
#[derive(Debug)]
pub struct CompanySystem {
    container: Container,
    certificate: Option<SystemCertificate>,
    user: String,
}

impl CompanySystem {
    /// The loopback port it listens on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.container.port()
    }

    /// The user name of its workflow login.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The PEM of the authority its certificate is from, when it serves
    /// TLS.
    #[must_use]
    pub fn authority_pem(&self) -> Option<&str> {
        self.certificate
            .as_ref()
            .map(SystemCertificate::authority_pem)
    }
}
