//! Protected data: what a step reaching a system behind a stream route is
//! handed, such as a database a company runs on its own network.
//!
//! The platform opens each connection itself, through the gateway's
//! workflow listener, with a pass made for the one call: by the time a step
//! holds one, the gateway has named the run's person and the stream route's
//! access has let them in. The step only signs in over it with the login
//! the route keeps for workflows and asks its question in the system's own
//! protocol. What the login may do is decided by the system itself.
//!
//! The connection is the system's own, end to end: where the route's login
//! asks for TLS, it runs from the worker to the system, checked against the
//! system's certificate, so neither the network nor the gateway reads it.
//! A system starting TLS from its first byte (Redis, MongoDB) is wrapped
//! here, by [`Through::protected_connection`]; one starting it inside its
//! own protocol (Postgres, MySQL) is handed the check by [`Through::tls`]
//! and refuses to go on without it.

mod door;
mod tls;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use tokio::io::{AsyncRead, AsyncWrite};

pub use self::door::{Door, DoorKind};
pub use self::tls::{DataTls, TlsCheck, TlsClient};
use crate::arguments::{argument, required_count};

/// A connection to a system behind a stream route, already through the
/// gateway.
pub trait DataStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> DataStream for T {}

/// Opens connections through the gateway to one stream route, with the
/// pass made for the call.
#[async_trait]
pub trait Opener: Send + Sync {
    /// A new connection to the stream route's backend.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the gateway cannot be reached or
    /// refuses the connection.
    async fn open(&self) -> Result<Box<dyn DataStream>, DomainError>;
}

/// The login a stream route keeps for workflows, opened for one call. The
/// password never prints.
pub struct DataLogin {
    /// The user name it signs in as.
    pub user: String,
    /// Credential opened for this call's backend login, hidden from debug output.
    pub password: Secret,
}

impl fmt::Debug for DataLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataLogin")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// What a Protected data call goes through: connections to the stream
/// route, at most [`Through::MOST_CONNECTIONS`] for the call, the login to
/// sign in over them with, and how they are protected.
pub struct Through {
    opener: Box<dyn Opener>,
    opened: AtomicUsize,
    /// The login the route keeps for workflows.
    pub login: DataLogin,
    /// How the connection to the system is protected.
    pub tls: DataTls,
}

impl Through {
    /// The most connections one call opens: a client that opens a few of
    /// its own, such as MongoDB's, fits, and a step cannot fan out.
    pub const MOST_CONNECTIONS: usize = 8;

    /// Connections from `opener`, signed in over with `login`, protected as
    /// `tls` says.
    #[must_use]
    pub fn new(opener: Box<dyn Opener>, login: DataLogin, tls: DataTls) -> Self {
        Self {
            opener,
            opened: AtomicUsize::new(0),
            login,
            tls,
        }
    }

    /// A new connection to the system, as the gateway hands it over: for a
    /// system that starts TLS inside its own protocol with [`Through::tls`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the call has opened its most
    /// connections already, or the connection could not be opened.
    pub async fn connection(&self) -> Result<Box<dyn DataStream>, DomainError> {
        if self.opened.fetch_add(1, Ordering::SeqCst) >= Self::MOST_CONNECTIONS {
            return Err(DomainError::infra_msg(
                "the call opened the most connections it may",
            ));
        }
        self.opener.open().await
    }

    /// A new connection to the system, inside TLS from its first byte when
    /// the login asks for TLS, checked against the system's certificate.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] as [`Through::connection`] does, and when
    /// the system's certificate is not the one the login asks for.
    pub async fn protected_connection(&self) -> Result<Box<dyn DataStream>, DomainError> {
        let connection = self.connection().await?;
        let Some(client) = self.tls()? else {
            return Ok(connection);
        };
        client.wrapped(connection).await
    }

    /// The TLS a system starting it inside its own protocol must speak, or
    /// none when the login asks for none.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the login's authority or server name
    /// does not read.
    pub fn tls(&self) -> Result<Option<TlsClient>, DomainError> {
        match &self.tls {
            DataTls::Required(check) => TlsClient::checking(check).map(Some),
            DataTls::Off => Ok(None),
        }
    }

    /// A door on the worker's own loopback address, each connection to it
    /// carried to a new connection to the system as `kind` says: for a
    /// client that dials an address itself. It closes when dropped.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when no loopback port can be taken.
    pub async fn door(self: &Arc<Self>, kind: DoorKind) -> Result<Door, DomainError> {
        Door::open(Arc::clone(self), kind).await
    }
}

impl fmt::Debug for Through {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Through")
            .field("login", &self.login)
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

/// The most rows a query hands back: the step's `row_limit`, held to
/// `most`, or `most` when the step gives none.
///
/// # Errors
///
/// A failed outcome when the step's `row_limit` is not a count.
pub fn row_limit(arguments: &FlowData, most: u32) -> Result<u32, ActionOutcome> {
    if argument(arguments, "row_limit").is_none() {
        return Ok(most);
    }
    let asked = required_count(arguments, "row_limit")?;
    Ok(u32::try_from(asked).unwrap_or(most).clamp(1, most))
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    struct Pipes;

    #[async_trait]
    impl Opener for Pipes {
        async fn open(&self) -> Result<Box<dyn DataStream>, DomainError> {
            let (near, _far) = duplex(64);
            Ok(Box::new(near))
        }
    }

    fn through() -> Through {
        Through::new(
            Box::new(Pipes),
            DataLogin {
                user: "workflows_reader".to_owned(),
                password: Secret::new("reader password"),
            },
            DataTls::Off,
        )
    }

    /// A step asking for connection after connection is refused past the
    /// most, so one call cannot fan out across the gateway.
    #[tokio::test]
    async fn a_call_opens_at_most_its_connections() {
        let through = through();
        for _ in 0..Through::MOST_CONNECTIONS {
            through.connection().await.unwrap();
        }

        let past = through.connection().await;

        assert!(past.is_err());
    }

    /// The login's password never prints, wherever the call is logged.
    #[test]
    fn the_password_never_prints() {
        let printed = format!("{:?}", through());

        assert!(!printed.contains("reader password"), "{printed}");
    }
}
