//! TLS for a Postgres connection, started inside Postgres's own protocol
//! with the check the stream route's login names: the client asks for TLS
//! first, and a database answering that it has none is refused, never
//! spoken to in the clear.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use ianua_integration::data::{DataStream, TlsClient};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::config::SslMode;
use tokio_postgres::tls::{ChannelBinding, TlsConnect, TlsStream};
use tokio_rustls::{TlsConnector, client};

/// Starts TLS on a Postgres connection when the login asks for it,
/// checking the database's certificate as the login says.
pub(crate) struct PostgresTls(pub(crate) Option<TlsClient>);

impl PostgresTls {
    /// The mode the connection signs in with: TLS required where the login
    /// asks for it, so a database without it is refused rather than spoken
    /// to in the clear, and none asked where the login asks for none.
    pub(crate) fn ssl_mode(&self) -> SslMode {
        match self.0 {
            Some(_) => SslMode::Require,
            None => SslMode::Disable,
        }
    }
}

impl TlsConnect<Raw> for PostgresTls {
    type Stream = Encrypted;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Encrypted, io::Error>> + Send>>;

    fn connect(self, stream: Raw) -> Self::Future {
        let Some(client) = self.0 else {
            return Box::pin(async { Err(io::Error::other("the login asks for no TLS")) });
        };
        let connector = TlsConnector::from(client.config().clone());
        let name = client.server_name().clone();
        Box::pin(async move { connector.connect(name, stream).await.map(Encrypted) })
    }
}

/// A Postgres connection inside TLS.
pub(crate) struct Encrypted(client::TlsStream<Raw>);

/// A Postgres connection as the gateway handed it over, before any TLS.
pub(crate) struct Raw(pub(crate) Box<dyn DataStream>);

impl AsyncRead for Raw {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Raw {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl TlsStream for Encrypted {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

impl AsyncRead for Encrypted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Encrypted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
