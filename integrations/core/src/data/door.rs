//! A door on the worker's loopback address for a client library that dials
//! an address itself and takes no connection handed to it, such as MySQL's
//! or MongoDB's: each connection to the door is carried to a new connection
//! to the system, counted against the call's most.
//!
//! The door listens on 127.0.0.1 alone, on a port the system picks, for as
//! long as the call holds it. Dropping it stops taking connections and ends
//! every one it carries.

use std::net::SocketAddr;
use std::sync::Arc;

use ianua_domain::shared::errors::DomainError;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::data::Through;

/// What each connection to the door is carried to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoorKind {
    /// The connection as the gateway hands it over, for a client that
    /// starts TLS inside its own protocol with [`Through::tls`].
    AsHanded,
    /// The connection inside TLS from its first byte when the login asks
    /// for it, for a client that dials the door in the clear.
    Protected,
}

/// A loopback door to the system, open while held.
#[derive(Debug)]
pub struct Door {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Door {
    /// A door carrying each connection to `through` as `kind` says.
    pub(crate) async fn open(through: Arc<Through>, kind: DoorKind) -> Result<Self, DomainError> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(DomainError::infra)?;
        let address = listener.local_addr().map_err(DomainError::infra)?;
        let task = tokio::spawn(accept_connections(listener, through, kind));
        Ok(Self { address, task })
    }

    /// The loopback address to dial.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for Door {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Takes connections on `listener` and carries each to the system, until
/// the door is dropped, which ends every carried connection with it.
async fn accept_connections(listener: TcpListener, through: Arc<Through>, kind: DoorKind) {
    let mut carrying = JoinSet::new();
    while let Ok((client, _)) = listener.accept().await {
        carrying.spawn(carry(client, Arc::clone(&through), kind));
        while carrying.try_join_next().is_some() {}
    }
}

/// `client` spliced to a new connection to the system, closed when either
/// end closes or the system cannot be reached.
async fn carry(mut client: TcpStream, through: Arc<Through>, kind: DoorKind) {
    let opened = match kind {
        DoorKind::AsHanded => through.connection().await,
        DoorKind::Protected => through.protected_connection().await,
    };
    let Ok(mut system) = opened else {
        return;
    };
    drop(tokio::io::copy_bidirectional(&mut client, &mut system).await);
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::shared::security::secret::Secret;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

    use super::*;
    use crate::data::{DataLogin, DataStream, DataTls, Opener};

    /// A system that answers every connection with `hello`.
    struct Greeter;

    #[async_trait]
    impl Opener for Greeter {
        async fn open(&self) -> Result<Box<dyn DataStream>, DomainError> {
            let (near, mut far) = duplex(64);
            tokio::spawn(async move {
                drop(far.write_all(b"hello").await);
                let mut rest = Vec::new();
                drop(far.read_to_end(&mut rest).await);
            });
            Ok(Box::new(near))
        }
    }

    fn through() -> Arc<Through> {
        Arc::new(Through::new(
            Box::new(Greeter),
            DataLogin {
                user: "workflows_reader".to_owned(),
                password: Secret::new("reader password"),
            },
            DataTls::Off,
        ))
    }

    /// A client dialling the door is carried to the system: it reads what
    /// the system said.
    #[tokio::test]
    async fn a_connection_to_the_door_reaches_the_system() {
        let door = through().door(DoorKind::AsHanded).await.unwrap();

        let mut client = TcpStream::connect(door.address()).await.unwrap();
        let mut greeting = [0; 5];
        client.read_exact(&mut greeting).await.unwrap();

        assert_eq!(&greeting, b"hello");
        assert!(door.address().ip().is_loopback());
    }

    /// Once the call drops its door, nothing more is taken there.
    #[tokio::test]
    async fn a_dropped_door_takes_nothing() {
        let door = through().door(DoorKind::AsHanded).await.unwrap();
        let address = door.address();

        drop(door);
        tokio::task::yield_now().await;
        let mut client = TcpStream::connect(address).await;
        let read = match client.as_mut() {
            Ok(client) => client.read(&mut [0; 5]).await.unwrap_or(0),
            Err(_) => 0,
        };

        assert_eq!(read, 0);
    }
}
