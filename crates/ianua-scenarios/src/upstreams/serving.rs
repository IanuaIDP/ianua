//! What every app behind the gateway shares: a listener on a port of
//! loopback, its connections served until the app is dropped, and the
//! record of what arrived.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, PoisonError, RwLock};

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// A listener taking connections until it is dropped.
pub(super) struct Listening {
    address: SocketAddr,
    accepting: JoinHandle<()>,
}

impl Listening {
    /// A listener on a port of loopback, each connection given to `serve`
    /// as a task of its own.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub(super) async fn open<F, Fut>(serve: F) -> io::Result<Self>
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let accepting = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(serve(stream));
            }
        });
        Ok(Self { address, accepting })
    }

    /// Where it listens.
    pub(super) fn address(&self) -> SocketAddr {
        self.address
    }

    /// The address a service names to reach it, `http://127.0.0.1:<port>`.
    pub(super) fn url(&self) -> String {
        format!("http://{}", self.address)
    }
}

impl Drop for Listening {
    /// Stops taking connections.
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

/// What reached an app, in the order it arrived, shared with its
/// connections.
#[derive(Debug)]
pub(super) struct Record<T> {
    kept: Arc<RwLock<Vec<T>>>,
}

impl<T> Clone for Record<T> {
    fn clone(&self) -> Self {
        Self {
            kept: Arc::clone(&self.kept),
        }
    }
}

impl<T> Default for Record<T> {
    fn default() -> Self {
        Self {
            kept: Arc::default(),
        }
    }
}

impl<T: Clone> Record<T> {
    /// Keeps `arrived`.
    pub(super) fn keep(&self, arrived: T) {
        self.kept
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(arrived);
    }

    /// Everything kept, oldest first.
    pub(super) fn all(&self) -> Vec<T> {
        self.kept
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Forgets everything kept.
    pub(super) fn clear(&self) {
        self.kept
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}
