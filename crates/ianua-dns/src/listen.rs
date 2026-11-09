//! The UDP and TCP listeners.
//!
//! Both are required. A resolver asks over UDP and comes back over TCP when
//! an answer does not fit, so a nameserver speaking only one of them fails
//! now and then on the larger answers.
//!
//! Both ports are taken before anything is served, and a port that cannot
//! be taken stops the start. Binding inside a serving task instead lets the
//! process look healthy while it answers nothing.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use crate::catalog::SharedCatalog;
use crate::error::NameserverError;
use crate::wire::{Transport, answer_query};

/// The largest UDP datagram read. A query never needs more, and a fixed
/// buffer keeps a sender from choosing what each packet costs us.
const MAX_UDP_REQUEST: usize = 4_096;

/// The largest DNS message accepted over TCP. TCP frames a message with a
/// two-byte length, and accepting the most it can say would let one
/// connection hold 64 KiB before sending anything.
const MAX_TCP_MESSAGE: usize = 8_192;

/// How long one TCP connection may take, end to end. A connection that
/// opens and sends nothing would otherwise hold one of the permits below
/// for ever.
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// How many TCP connections are served at once. TCP is the lesser path,
/// and the queue for it must not grow until memory runs out.
const MAX_TCP_CONNECTIONS: usize = 256;

/// The two ports a nameserver answers on, taken.
#[derive(Debug)]
pub struct Ports {
    /// The UDP socket.
    pub udp: UdpSocket,
    /// The TCP listener.
    pub tcp: TcpListener,
    /// Where both were taken, the port named even where any was asked for.
    pub address: SocketAddr,
}

impl Ports {
    /// Takes UDP and TCP at `address`, the TCP port the one UDP took when
    /// `address` asks for any.
    ///
    /// # Errors
    ///
    /// [`NameserverError::Bind`] naming the transport whose port was
    /// refused.
    pub async fn bind(address: SocketAddr) -> Result<Self, NameserverError> {
        let udp = UdpSocket::bind(address)
            .await
            .map_err(|cause| refused(Transport::Udp, address, cause))?;
        let taken = udp
            .local_addr()
            .map_err(|cause| refused(Transport::Udp, address, cause))?;
        let tcp = TcpListener::bind(taken)
            .await
            .map_err(|cause| refused(Transport::Tcp, taken, cause))?;
        tracing::info!(address = %taken, "dns listening on udp and tcp");
        Ok(Self {
            udp,
            tcp,
            address: taken,
        })
    }
}

/// A refusal of `transport`'s port at `address`.
fn refused(transport: Transport, address: SocketAddr, cause: std::io::Error) -> NameserverError {
    NameserverError::Bind {
        transport,
        address,
        cause,
    }
}

/// Answers DNS over UDP on `socket` from `catalog` until `stopping` is
/// done. A packet that is not a query gets no reply: answering one would
/// send traffic to whatever address its sender claimed.
pub(crate) async fn serve_udp(
    socket: UdpSocket,
    catalog: SharedCatalog,
    stopping: impl Future<Output = ()>,
) {
    let mut stopping = std::pin::pin!(stopping);
    let mut buffer = vec![0_u8; MAX_UDP_REQUEST];
    loop {
        let received = tokio::select! {
            () = &mut stopping => return,
            received = socket.recv_from(&mut buffer) => received,
        };
        let Ok((length, from)) = received else {
            continue;
        };
        let Some(request) = buffer.get(..length) else {
            continue;
        };
        let Some(response) = answer_query(&catalog.load(), request, Transport::Udp) else {
            continue;
        };
        if let Err(error) = socket.send_to(&response, from).await {
            tracing::debug!(%from, %error, "dns udp reply failed");
        }
    }
}

/// Answers DNS over TCP on `listener` from `catalog` until `stopping` is
/// done, each connection held to its own deadline and a bounded number
/// served at once.
pub(crate) async fn serve_tcp(
    listener: TcpListener,
    catalog: SharedCatalog,
    stopping: impl Future<Output = ()>,
) {
    let mut stopping = std::pin::pin!(stopping);
    let permits = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            () = &mut stopping => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, from)) = accepted else {
            continue;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            tracing::warn!(%from, "dns tcp connection refused: at capacity");
            continue;
        };
        let catalog = Arc::clone(&catalog);
        tokio::spawn(async move {
            let _permit = permit;
            let served = tokio::time::timeout(TCP_TIMEOUT, serve_connection(stream, &catalog));
            if served.await.is_err() {
                tracing::debug!(%from, "dns tcp connection timed out");
            }
        });
    }
}

/// Answers one TCP connection's queries, each framed by a two-byte length,
/// until it closes or sends what is not a query.
async fn serve_connection(mut stream: TcpStream, catalog: &SharedCatalog) {
    while let Some(request) = next_request(&mut stream).await {
        let Some(response) = answer_query(&catalog.load(), &request, Transport::Tcp) else {
            return;
        };
        let Ok(framed) = u16::try_from(response.len()) else {
            return;
        };
        let written = write_framed(&mut stream, framed, &response).await;
        if written.is_err() {
            return;
        }
    }
}

/// The next message on `stream`, or `None` when it closed or announced a
/// message of no size or past [`MAX_TCP_MESSAGE`].
async fn next_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).await.ok()?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > MAX_TCP_MESSAGE {
        return None;
    }
    let mut request = vec![0_u8; length];
    stream.read_exact(&mut request).await.ok()?;
    Some(request)
}

/// Writes `response` to `stream` behind its length `framed`.
async fn write_framed(stream: &mut TcpStream, framed: u16, response: &[u8]) -> std::io::Result<()> {
    stream.write_all(&framed.to_be_bytes()).await?;
    stream.write_all(response).await
}

#[cfg(test)]
mod tests {
    use arc_swap::ArcSwap;
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use ianua_domain::domains::tenant::custom_domains::dns_zone::{
        Authority, HeldZone, RecordName, RecordSet, RecordValue, Serial, Ttl, Zone, ZoneCatalog,
        ZoneStanding,
    };
    use ianua_domain::types::{DomainName, IpAddress, TenantId};

    use super::*;

    fn catalog() -> SharedCatalog {
        let authority = Authority::new(RecordName::new("hostmaster.ianua.test").unwrap());
        let set = RecordSet::new(
            RecordName::new("api.auth.acme.test").unwrap(),
            Ttl::standard(),
            vec![RecordValue::Address(
                IpAddress::new("198.51.100.1").unwrap(),
            )],
        )
        .unwrap();
        let zone = Zone::new(
            DomainName::new("auth.acme.test").unwrap(),
            Serial::at(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()),
            vec![set],
            vec![DomainName::new("abc123.ns1.ianua.test").unwrap()],
        )
        .unwrap();
        let held = HeldZone {
            zone,
            owner: TenantId::new(),
            standing: ZoneStanding::Proven,
        };
        Arc::new(ArcSwap::from_pointee(ZoneCatalog::new(
            vec![held],
            authority,
        )))
    }

    fn query(name: &str) -> Vec<u8> {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_utf8(format!("{name}.")).unwrap(),
            RecordType::A,
        ));
        message.to_vec().unwrap()
    }

    fn loopback() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    /// An occupied UDP port refuses listener setup with a UDP bind error.
    #[tokio::test]
    async fn a_taken_udp_port_refuses_the_start() {
        let held = UdpSocket::bind(loopback()).await.unwrap();

        let bound = Ports::bind(held.local_addr().unwrap()).await;

        assert!(matches!(
            bound,
            Err(NameserverError::Bind {
                transport: Transport::Udp,
                ..
            })
        ));
    }

    /// An occupied TCP port refuses listener setup even when UDP can bind.
    #[tokio::test]
    async fn a_taken_tcp_port_refuses_the_start() {
        let held = TcpListener::bind(loopback()).await.unwrap();

        let bound = Ports::bind(held.local_addr().unwrap()).await;

        assert!(matches!(
            bound,
            Err(NameserverError::Bind {
                transport: Transport::Tcp,
                ..
            })
        ));
    }

    /// Asking for any port takes the same port on both transports, where a
    /// resolver comes back over TCP.
    #[tokio::test]
    async fn any_port_is_the_same_port_on_both() {
        let ports = Ports::bind(loopback()).await.unwrap();

        assert_eq!(ports.udp.local_addr().unwrap(), ports.address);
        assert_eq!(ports.tcp.local_addr().unwrap(), ports.address);
    }

    /// Malformed UDP data receives no DNS reply during the observation window.
    #[tokio::test]
    async fn a_packet_that_is_not_a_query_gets_no_reply() {
        let ports = Ports::bind(loopback()).await.unwrap();
        let address = ports.address;
        let stop = Arc::new(tokio::sync::Notify::new());
        let stopping = Arc::clone(&stop);
        let server = tokio::spawn(serve_udp(ports.udp, catalog(), async move {
            stopping.notified().await;
        }));
        let client = UdpSocket::bind(loopback()).await.unwrap();

        client.send_to(b"not a dns packet", address).await.unwrap();
        let mut buffer = vec![0_u8; 4096];
        let answered =
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buffer)).await;

        assert!(answered.is_err(), "garbage draws no reply");
        stop.notify_one();
        let _ = server.await;
    }

    /// A name in a zone we hold is answered with authority over UDP, and a
    /// name in none is refused.
    #[tokio::test]
    async fn a_udp_query_is_answered_and_a_stranger_refused() {
        let ports = Ports::bind(loopback()).await.unwrap();
        let address = ports.address;
        let stop = Arc::new(tokio::sync::Notify::new());
        let stopping = Arc::clone(&stop);
        let server = tokio::spawn(serve_udp(ports.udp, catalog(), async move {
            stopping.notified().await;
        }));
        let client = UdpSocket::bind(loopback()).await.unwrap();
        let mut buffer = vec![0_u8; 4096];

        client
            .send_to(&query("api.auth.acme.test"), address)
            .await
            .unwrap();
        let (length, _) = client.recv_from(&mut buffer).await.unwrap();
        let held = Message::from_vec(&buffer[..length]).unwrap();
        client
            .send_to(&query("evil.example.com"), address)
            .await
            .unwrap();
        let (length, _) = client.recv_from(&mut buffer).await.unwrap();
        let stranger = Message::from_vec(&buffer[..length]).unwrap();

        assert!(held.metadata.authoritative);
        assert_eq!(held.answers.len(), 1);
        assert_eq!(stranger.metadata.response_code, ResponseCode::Refused);
        stop.notify_one();
        let _ = server.await;
    }
}
