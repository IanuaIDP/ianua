//! Opening a connection to a backend inside a tenant's network: an HTTP/2
//! `CONNECT` sent down one of its connector's links, which the connector
//! answers by dialling the backend from inside.
//!
//! What comes back is a plain byte stream, so whatever the gateway would
//! have sent over TCP goes over it unchanged: TLS to the backend, HTTP/1
//! or HTTP/2, a protocol switch. Before anything is sent the backend is
//! held to the connector's scope; the connector holds it to its own list
//! again. No link, no room on the link, a refusal or a link that breaks
//! each end the attempt with its own reason, and none of them is retried.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::{Request, StatusCode, Uri};
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::upgrade::Upgraded;
use ianua_domain::shared::validation::UrlHost;
use ianua_domain::types::{ConnectorId, HttpUrl, TenantId};
use tokio::sync::OwnedSemaphorePermit;

use super::links::{ConnectorLinks, Link};

/// Why no connection was opened down a link.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LinkError {
    /// The address is not one a connector is asked for.
    #[error("the backend's address cannot be sent to a connector")]
    InvalidTarget,
    /// The connector's scope does not name the backend.
    #[error("the connector may not be asked to dial this backend")]
    OutsideScope,
    /// The connector holds no live link to this gateway.
    #[error("the connector holds no link to this gateway")]
    Offline,
    /// Every stream the links may carry is in use.
    #[error("the connector's link carries as many connections as it may")]
    Busy,
    /// The connector refused to dial the backend.
    #[error("the connector refused to dial the backend")]
    Refused,
    /// The connector could not reach the backend.
    #[error("the connector could not reach the backend: {0}")]
    Unreachable(StatusCode),
    /// Opening the connection took longer than allowed.
    #[error("the connector did not open the connection in time")]
    TimedOut,
    /// The link broke while the connection was opened.
    #[error("the link broke while the connection was opened")]
    Broken(#[source] hyper::Error),
    /// The gateway closed the link while the connection was opened: its
    /// connector was revoked, removed or enrolled again with another key.
    #[error("the link was closed while the connection was opened")]
    Closed,
    /// No request could be built for the backend.
    #[error("no request could be built for the backend")]
    Request(#[source] http::Error),
}

/// Opens connections to the backends of one service reached through
/// `connector`, a connector of `tenant`.
#[derive(Clone)]
pub(crate) struct LinkDialer {
    links: Arc<ConnectorLinks>,
    tenant: TenantId,
    connector: ConnectorId,
    open: Duration,
}

impl LinkDialer {
    /// A dialer down the links of `tenant`'s `connector` in `links`, each
    /// connection opened within `open`.
    #[must_use]
    pub(crate) fn new(
        links: Arc<ConnectorLinks>,
        tenant: TenantId,
        connector: ConnectorId,
        open: Duration,
    ) -> Self {
        Self {
            links,
            tenant,
            connector,
            open,
        }
    }

    /// A connection to the backend `uri` names, opened down a live link.
    ///
    /// # Errors
    ///
    /// Any [`LinkError`].
    pub(crate) async fn dial(&self, uri: Uri) -> Result<LinkedStream, LinkError> {
        let target = HttpUrl::new(uri.to_string()).map_err(|_| LinkError::InvalidTarget)?;
        let link = self.admitted_link(&target)?;
        let permit = link
            .streams()
            .try_acquire_owned()
            .map_err(|_| LinkError::Busy)?;
        let authority = authority_of(&target);
        let closed = link.closed();
        let opening = tokio::time::timeout(self.open, opened(link.sender(), authority));
        let io = tokio::select! {
            opened = opening => opened.map_err(|_| LinkError::TimedOut)??,
            () = closed.cancelled() => return Err(LinkError::Closed),
        };
        Ok(LinkedStream {
            io,
            _permit: permit,
        })
    }

    /// Picks a live link only after the backend passes the connector's scope.
    fn admitted_link(&self, target: &HttpUrl) -> Result<Arc<Link>, LinkError> {
        if !self
            .links
            .may_dial(self.tenant, self.connector, target.host())
        {
            return Err(LinkError::OutsideScope);
        }
        let Some(link) = self.links.pick(self.tenant, self.connector) else {
            tracing::warn!(
                tenant = %self.tenant,
                connector = %self.connector,
                "a service's connector holds no link to this gateway"
            );
            return Err(LinkError::Offline);
        };
        Ok(link)
    }
}

/// The connection the connector opened for `authority`, once it answered
/// `200`.
async fn opened(
    mut sender: hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    authority: String,
) -> Result<Upgraded, LinkError> {
    sender.ready().await.map_err(LinkError::Broken)?;
    let request = Request::connect(authority)
        .body(Empty::new())
        .map_err(LinkError::Request)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(LinkError::Broken)?;
    match response.status() {
        StatusCode::OK => hyper::upgrade::on(response)
            .await
            .map_err(LinkError::Broken),
        StatusCode::FORBIDDEN => Err(LinkError::Refused),
        status => Err(LinkError::Unreachable(status)),
    }
}

/// The `host:port` a `CONNECT` names for `target`, an IPv6 address in
/// brackets.
fn authority_of(target: &HttpUrl) -> String {
    let port = target.port();
    match target.host() {
        UrlHost::Address(IpAddr::V6(address)) => format!("[{address}]:{port}"),
        UrlHost::Address(IpAddr::V4(address)) => format!("{address}:{port}"),
        UrlHost::Name(name) => format!("{name}:{port}"),
    }
}

/// A connection to a backend opened down a link. It holds one of the
/// link's streams for as long as it is open.
pub(crate) struct LinkedStream {
    io: Upgraded,
    _permit: OwnedSemaphorePermit,
}

impl Read for LinkedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl Write for LinkedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// The `LinkError` that `error`'s chain holds, when one does.
pub(crate) fn link_error_in<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a LinkError> {
    let mut cause = Some(error);
    while let Some(current) = cause {
        if let Some(found) = current.downcast_ref::<LinkError>() {
            return Some(found);
        }
        cause = current.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> HttpUrl {
        HttpUrl::new(text).unwrap()
    }

    /// A backend named by host, by address and by IPv6 address is asked
    /// for with its port, the scheme's when it names none.
    #[test]
    fn a_connect_names_the_host_and_port() {
        assert_eq!(
            authority_of(&url("https://wiki.corp.internal/")),
            "wiki.corp.internal:443"
        );
        assert_eq!(authority_of(&url("http://10.0.0.5:8080/")), "10.0.0.5:8080");
        assert_eq!(authority_of(&url("http://[fd00::5]:80/")), "[fd00::5]:80");
    }

    /// A link error deep in a chain is found, and a chain without one is
    /// not mistaken for it.
    #[test]
    fn a_link_error_is_found_in_a_chain() {
        let boxed: Box<dyn std::error::Error + Send + Sync> = Box::new(LinkError::Offline);

        assert!(matches!(link_error_in(&*boxed), Some(LinkError::Offline)));
        assert!(link_error_in(&io::Error::other("reset")).is_none());
    }
}
