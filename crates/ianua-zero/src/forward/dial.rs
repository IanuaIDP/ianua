//! How a pooled client opens a connection to a backend: over TCP from the
//! gateway itself, or down a link of the tenant's connector, which dials
//! the backend from inside the tenant's network.
//!
//! Both answer a byte stream of one type, so a service reached through a
//! connector is pooled, probed, spoken TLS to and switched protocols on as
//! any other. A pool's client is built for one of the two and never moves
//! between them.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tower_service::Service;

use super::client::BoxError;
use super::screen::ScreenedResolver;
use crate::connectors::{LinkDialer, LinkedStream};

/// Where a pooled client's connections are opened.
#[derive(Clone)]
pub(super) enum Dial {
    /// From the gateway, over TCP, every address screened.
    Direct(HttpConnector<ScreenedResolver>),
    /// Down a link of the tenant's connector.
    Linked(LinkDialer),
}

impl Service<Uri> for Dial {
    type Response = Dialled;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Dialled, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Direct(connector) => connector.poll_ready(cx).map_err(Into::into),
            Self::Linked(_) => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        match self {
            Self::Direct(connector) => {
                let connecting = connector.call(destination);
                Box::pin(async move { connecting.await.map(Dialled::Direct).map_err(Into::into) })
            }
            Self::Linked(dialer) => {
                let dialer = dialer.clone();
                Box::pin(async move {
                    dialer
                        .dial(destination)
                        .await
                        .map(|stream| Dialled::Linked(Box::new(stream)))
                        .map_err(Into::into)
                })
            }
        }
    }
}

/// A connection to a backend, however it was opened.
pub(super) enum Dialled {
    /// Over TCP from the gateway.
    Direct(TokioIo<TcpStream>),
    /// Down a connector's link.
    Linked(Box<LinkedStream>),
}

impl Connection for Dialled {
    fn connected(&self) -> Connected {
        match self {
            Self::Direct(stream) => stream.connected(),
            Self::Linked(_) => Connected::new(),
        }
    }
}

impl Read for Dialled {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Linked(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl Write for Dialled {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Linked(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_flush(cx),
            Self::Linked(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Linked(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}
