//! The client's real address, from a PROXY protocol v2 header a trusted
//! ingress writes.
//!
//! An ingress that passes TLS through opens its own connection to the
//! gateway, so the socket peer is the ingress. PROXY protocol is how it
//! names the client: a short header before the client's first byte. For a
//! proxy that decides on identity and records every decision, the client's
//! address is the one field it cannot get wrong: every visitor would share
//! one address in the audit trail, the rate limits and the risk score.
//!
//! The header is unauthenticated, so it is read only from a peer the
//! deployment names as its ingress, and from that peer it is required. Any
//! other peer that opens with the header's signature is refused: reading
//! it would let any client choose the address recorded for it.
//!
//! Only version 2 is read. Version 1 is a text line, and telling a
//! truncated one from a client that starts with `PROXY ` means reading
//! until a newline that may never come; version 2 states its length in a
//! fixed 16-byte preamble. Every read here is bounded by a timeout.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ianua_domain::domains::proxy::request::forwarded::TrustedProxies;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::rewind::Rewind;

/// The 12 bytes every v2 header starts with, chosen by the specification
/// so that no other protocol begins with them.
const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// The signature, the version and command, the family, and the length.
const PREAMBLE: usize = 16;

/// The longest address block read. The specification allows metadata
/// after the addresses, none of which is needed, but it must be drained to
/// reach the client's first byte; a header claiming more is refused.
const MAX_ADDRESSES: usize = 536;

const IPV4_BLOCK: usize = 12;
const IPV6_BLOCK: usize = 36;
const TCP_OVER_IPV4: u8 = 0x11;
const TCP_OVER_IPV6: u8 = 0x21;

/// Whether a listener reads PROXY protocol headers, and from whom.
#[derive(Debug, Clone, Default)]
pub(crate) enum ProxyProtocol {
    /// No peer is trusted to send one: the socket peer is the client.
    #[default]
    Off,
    /// The peers in these ranges are the ingress, and each connection from
    /// one must open with a header naming the client. Every other peer is
    /// the client itself.
    FromIngress(TrustedProxies),
}

/// Why a connection was refused before it opened.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProxyHeaderError {
    /// A peer not trusted to send a header opened with one.
    #[error("a PROXY protocol header came from a peer not trusted to send one")]
    Untrusted,
    /// The ingress opened without a header.
    #[error("the ingress opened the connection without a PROXY protocol v2 header")]
    Missing,
    /// The header names a version, command or family not read here, or
    /// claims an implausible length.
    #[error("unsupported PROXY protocol header: {0}")]
    Unsupported(&'static str),
    /// The opening did not arrive within its timeout.
    #[error("the opening of the connection did not arrive in time")]
    TimedOut,
    /// The connection failed or ended mid-header.
    #[error("reading the opening of the connection failed")]
    Io(#[source] std::io::Error),
}

/// A connection whose opening was read: who the client is, and the stream
/// from its first byte.
#[derive(Debug)]
pub(crate) struct Opened<S> {
    /// The client: named by the ingress, or the socket peer.
    pub(crate) client: SocketAddr,
    /// The stream, from the client's first byte.
    pub(crate) stream: Rewind<S>,
}

/// Reads the opening of a connection from `peer` within `wait`.
///
/// # Errors
///
/// [`ProxyHeaderError`] when the opening is refused: a header from a peer
/// not trusted to send one, none or a malformed one from the ingress, or
/// nothing within `wait`.
pub(crate) async fn open<S>(
    stream: S,
    peer: SocketAddr,
    protocol: &ProxyProtocol,
    wait: Duration,
) -> Result<Opened<S>, ProxyHeaderError>
where
    S: AsyncRead + Unpin,
{
    tokio::time::timeout(wait, opening(stream, peer, protocol))
        .await
        .map_err(|_| ProxyHeaderError::TimedOut)?
}

async fn opening<S>(
    stream: S,
    peer: SocketAddr,
    protocol: &ProxyProtocol,
) -> Result<Opened<S>, ProxyHeaderError>
where
    S: AsyncRead + Unpin,
{
    match protocol {
        ProxyProtocol::FromIngress(ingress) if ingress.contains(peer.ip().to_canonical()) => {
            from_ingress(stream, peer).await
        }
        ProxyProtocol::FromIngress(_) | ProxyProtocol::Off => without_header(stream, peer).await,
    }
}

async fn from_ingress<S>(mut stream: S, peer: SocketAddr) -> Result<Opened<S>, ProxyHeaderError>
where
    S: AsyncRead + Unpin,
{
    let client = read_header(&mut stream).await?.unwrap_or(peer);
    Ok(Opened {
        client,
        stream: Rewind::new(Vec::new(), stream),
    })
}

async fn without_header<S>(mut stream: S, peer: SocketAddr) -> Result<Opened<S>, ProxyHeaderError>
where
    S: AsyncRead + Unpin,
{
    let opening = read_opening(&mut stream)
        .await
        .map_err(ProxyHeaderError::Io)?;
    if opening.as_slice() == SIGNATURE {
        return Err(ProxyHeaderError::Untrusted);
    }
    Ok(Opened {
        client: peer,
        stream: Rewind::new(opening, stream),
    })
}

/// The first bytes, read until they stop matching the signature or match
/// all of it. A TLS or HTTP client differs at its first byte, so this
/// usually reads once.
async fn read_opening<S>(stream: &mut S) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut opening = Vec::with_capacity(SIGNATURE.len());
    while SIGNATURE.starts_with(&opening) && opening.len() < SIGNATURE.len() {
        let mut chunk = [0_u8; SIGNATURE.len()];
        let wanted = SIGNATURE.len() - opening.len();
        let read = stream.read(&mut chunk[..wanted]).await?;
        if read == 0 {
            return Ok(opening);
        }
        opening.extend_from_slice(&chunk[..read]);
    }
    Ok(opening)
}

/// What the header says the connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    /// The ingress on its own behalf, such as a health check.
    Local,
    /// A client's connection, relayed.
    Proxy,
}

fn command_of(nibble: u8) -> Result<Command, ProxyHeaderError> {
    match nibble {
        0 => Ok(Command::Local),
        1 => Ok(Command::Proxy),
        _ => Err(ProxyHeaderError::Unsupported(
            "command is neither LOCAL nor PROXY",
        )),
    }
}

/// Reads the header and returns the client it names, or `None` for a
/// `LOCAL` header, which names none. Consumes exactly the header.
async fn read_header<S>(stream: &mut S) -> Result<Option<SocketAddr>, ProxyHeaderError>
where
    S: AsyncRead + Unpin,
{
    read_signature(stream).await?;
    let mut preamble = [0_u8; PREAMBLE - SIGNATURE.len()];
    stream
        .read_exact(&mut preamble)
        .await
        .map_err(ProxyHeaderError::Io)?;
    if preamble[0] >> 4 != 2 {
        return Err(ProxyHeaderError::Unsupported("version is not 2"));
    }
    let command = command_of(preamble[0] & 0x0F)?;
    let family = preamble[1];
    let length = usize::from(u16::from_be_bytes([preamble[2], preamble[3]]));
    if length > MAX_ADDRESSES {
        return Err(ProxyHeaderError::Unsupported("header is implausibly long"));
    }

    let mut addresses = vec![0_u8; length];
    stream
        .read_exact(&mut addresses)
        .await
        .map_err(ProxyHeaderError::Io)?;
    match command {
        Command::Local => Ok(None),
        Command::Proxy => source_of(family, &addresses).map(Some),
    }
}

/// Consumes the header's signature. A connection whose first bytes leave
/// the signature, however short it is, opened without a header; one that
/// ends while still on it ended mid-header.
async fn read_signature<S>(stream: &mut S) -> Result<(), ProxyHeaderError>
where
    S: AsyncRead + Unpin,
{
    let opening = read_opening(stream).await.map_err(ProxyHeaderError::Io)?;
    if !SIGNATURE.starts_with(&opening) {
        return Err(ProxyHeaderError::Missing);
    }
    if opening.len() < SIGNATURE.len() {
        return Err(ProxyHeaderError::Io(
            std::io::ErrorKind::UnexpectedEof.into(),
        ));
    }
    Ok(())
}

/// The source address in an address block: source and destination
/// addresses, then their ports.
fn source_of(family: u8, addresses: &[u8]) -> Result<SocketAddr, ProxyHeaderError> {
    match family {
        TCP_OVER_IPV4 => ipv4_source(addresses),
        TCP_OVER_IPV6 => ipv6_source(addresses),
        _ => Err(ProxyHeaderError::Unsupported(
            "address family is not TCP over IP",
        )),
    }
}

fn ipv4_source(addresses: &[u8]) -> Result<SocketAddr, ProxyHeaderError> {
    let block: [u8; IPV4_BLOCK] = addresses
        .get(..IPV4_BLOCK)
        .and_then(|block| block.try_into().ok())
        .ok_or(ProxyHeaderError::Unsupported("IPv4 block is too short"))?;
    let ip = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
    let port = u16::from_be_bytes([block[8], block[9]]);
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

fn ipv6_source(addresses: &[u8]) -> Result<SocketAddr, ProxyHeaderError> {
    let block: [u8; IPV6_BLOCK] = addresses
        .get(..IPV6_BLOCK)
        .and_then(|block| block.try_into().ok())
        .ok_or(ProxyHeaderError::Unsupported("IPv6 block is too short"))?;
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&block[..16]);
    let port = u16::from_be_bytes([block[32], block[33]]);
    Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    const WAIT: Duration = Duration::from_secs(1);
    const CLIENT_HELLO_START: &[u8] = b"\x16\x03\x01\x00\xf4\x01\x00\x00\xf0\x03\x03";

    fn header(command: u8, family: u8, addresses: &[u8]) -> Vec<u8> {
        let mut bytes = SIGNATURE.to_vec();
        bytes.push(0x20 | command);
        bytes.push(family);
        bytes.extend_from_slice(&u16::try_from(addresses.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(addresses);
        bytes
    }

    fn ipv4_block(source: [u8; 4], source_port: u16) -> Vec<u8> {
        let mut block = source.to_vec();
        block.extend_from_slice(&[10, 0, 0, 1]);
        block.extend_from_slice(&source_port.to_be_bytes());
        block.extend_from_slice(&443_u16.to_be_bytes());
        block
    }

    fn ingress() -> SocketAddr {
        "10.0.0.5:40000".parse().unwrap()
    }

    fn stranger() -> SocketAddr {
        "198.51.100.7:40000".parse().unwrap()
    }

    fn from_ingress_only() -> ProxyProtocol {
        ProxyProtocol::FromIngress(TrustedProxies::parse("10.0.0.0/24"))
    }

    async fn open_bytes(
        bytes: &[u8],
        peer: SocketAddr,
        protocol: &ProxyProtocol,
    ) -> Result<Opened<std::io::Cursor<Vec<u8>>>, ProxyHeaderError> {
        open(std::io::Cursor::new(bytes.to_vec()), peer, protocol, WAIT).await
    }

    async fn rest_of<S: AsyncRead + Unpin>(mut opened: Opened<S>) -> Vec<u8> {
        let mut rest = Vec::new();
        opened.stream.read_to_end(&mut rest).await.unwrap();
        rest
    }

    /// The ingress names the client, and the stream is left at the
    /// client's first byte.
    #[tokio::test]
    async fn the_ingress_names_the_client() {
        let mut bytes = header(1, TCP_OVER_IPV4, &ipv4_block([203, 0, 113, 9], 51_234));
        bytes.extend_from_slice(CLIENT_HELLO_START);

        let opened = open_bytes(&bytes, ingress(), &from_ingress_only())
            .await
            .unwrap();

        assert_eq!(opened.client, "203.0.113.9:51234".parse().unwrap());
        assert_eq!(rest_of(opened).await, CLIENT_HELLO_START);
    }

    /// An IPv6 client is read from its wider block.
    #[tokio::test]
    async fn an_ipv6_client_is_named() {
        let mut block = [0_u8; IPV6_BLOCK];
        block[..16].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        block[32..34].copy_from_slice(&51_234_u16.to_be_bytes());
        let bytes = header(1, TCP_OVER_IPV6, &block);

        let opened = open_bytes(&bytes, ingress(), &from_ingress_only())
            .await
            .unwrap();

        assert_eq!(opened.client, "[2001:db8::1]:51234".parse().unwrap());
    }

    /// A health check from the ingress names no client, so the peer is kept.
    #[tokio::test]
    async fn a_local_header_keeps_the_peer() {
        let bytes = header(0, 0x00, &[]);

        let opened = open_bytes(&bytes, ingress(), &from_ingress_only())
            .await
            .unwrap();

        assert_eq!(opened.client, ingress());
    }

    /// A peer outside the ingress ranges that opens with a header is
    /// refused: it would choose the address recorded for it.
    #[tokio::test]
    async fn a_header_from_an_untrusted_peer_is_refused() {
        let bytes = header(1, TCP_OVER_IPV4, &ipv4_block([203, 0, 113, 9], 443));

        let opened = open_bytes(&bytes, stranger(), &from_ingress_only()).await;

        assert!(matches!(opened, Err(ProxyHeaderError::Untrusted)));
    }

    /// With the protocol off no peer is trusted, and a header is refused
    /// all the same.
    #[tokio::test]
    async fn a_header_is_refused_when_the_protocol_is_off() {
        let bytes = header(1, TCP_OVER_IPV4, &ipv4_block([203, 0, 113, 9], 443));

        let opened = open_bytes(&bytes, ingress(), &ProxyProtocol::Off).await;

        assert!(matches!(opened, Err(ProxyHeaderError::Untrusted)));
    }

    /// A client that is not the ingress keeps its own address, and every
    /// byte it sent reaches the next reader.
    #[tokio::test]
    async fn a_direct_client_keeps_its_address_and_its_bytes() {
        let opened = open_bytes(CLIENT_HELLO_START, stranger(), &from_ingress_only())
            .await
            .unwrap();

        assert_eq!(opened.client, stranger());
        assert_eq!(rest_of(opened).await, CLIENT_HELLO_START);
    }

    /// The ingress must send a header; a connection from it without one is
    /// not attributed to the ingress.
    #[tokio::test]
    async fn the_ingress_without_a_header_is_refused() {
        let opened = open_bytes(CLIENT_HELLO_START, ingress(), &from_ingress_only()).await;

        assert!(matches!(opened, Err(ProxyHeaderError::Missing)));
    }

    /// A version 1 header in the binary preamble is refused.
    #[tokio::test]
    async fn a_malformed_version_is_refused() {
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0x11, TCP_OVER_IPV4, 0x00, 0x0C]);
        bytes.extend_from_slice(&ipv4_block([203, 0, 113, 9], 443));

        let opened = open_bytes(&bytes, ingress(), &from_ingress_only()).await;

        assert!(matches!(opened, Err(ProxyHeaderError::Unsupported(_))));
    }

    /// A length nobody sends is refused without waiting for its bytes.
    #[tokio::test]
    async fn an_implausible_length_is_refused() {
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0x21, TCP_OVER_IPV4, 0xFF, 0xFF]);

        let opened = open_bytes(&bytes, ingress(), &from_ingress_only()).await;

        assert!(matches!(opened, Err(ProxyHeaderError::Unsupported(_))));
    }

    /// A family other than TCP over IP is refused.
    #[tokio::test]
    async fn an_unknown_family_is_refused() {
        let bytes = header(1, 0x31, &[0_u8; 12]);

        let opened = open_bytes(&bytes, ingress(), &from_ingress_only()).await;

        assert!(matches!(opened, Err(ProxyHeaderError::Unsupported(_))));
    }

    /// An address block shorter than its family needs is refused.
    #[tokio::test]
    async fn a_short_address_block_is_refused() {
        let bytes = header(1, TCP_OVER_IPV6, &[0_u8; 12]);

        let opened = open_bytes(&bytes, ingress(), &from_ingress_only()).await;

        assert!(matches!(opened, Err(ProxyHeaderError::Unsupported(_))));
    }

    /// A header cut off mid-way is an error, never an address.
    #[tokio::test]
    async fn a_truncated_header_is_refused() {
        let bytes = header(1, TCP_OVER_IPV4, &ipv4_block([203, 0, 113, 9], 443));

        let cut_in_the_block = open_bytes(&bytes[..20], ingress(), &from_ingress_only()).await;
        let cut_in_the_preamble = open_bytes(&bytes[..8], ingress(), &from_ingress_only()).await;

        assert!(matches!(cut_in_the_block, Err(ProxyHeaderError::Io(_))));
        assert!(matches!(cut_in_the_preamble, Err(ProxyHeaderError::Io(_))));
    }

    /// A header that never arrives is given up on at the timeout.
    #[tokio::test]
    async fn a_header_that_never_arrives_times_out() {
        let (near, _far) = tokio::io::duplex(64);

        let opened = open(
            near,
            ingress(),
            &from_ingress_only(),
            Duration::from_millis(50),
        )
        .await;

        assert!(matches!(opened, Err(ProxyHeaderError::TimedOut)));
    }
}
