//! The network filter: the one way a run's code reaches the internet, and
//! only the hosts its ticket names.
//!
//! The code asks the filter to open a tunnel to a host's port 443, as any
//! HTTPS client does through a proxy, and shows its ticket as the proxy
//! password. The filter refuses anything else: no ticket, a forged or ended
//! one, a host it does not name, another port, or a name that leads to a
//! private, loopback, link-local or other address that is not public. It
//! looks the name up itself and connects to the address it checked, so a
//! name cannot change between the check and the connection. The tunnel
//! carries the encrypted bytes and nothing is read from them; it closes
//! when the ticket ends. The filter holds a fixed number of tunnels.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_domain::shared::security::ssrf::is_blocked_ip;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::sandbox::proxy::ticket::{MAX_TICKET, Ticket, TicketKey};

/// How long the code may take to ask for its tunnel.
const ASKED_WITHIN: Duration = Duration::from_secs(10);

/// How long looking a host up and connecting to it may take.
const CONNECTED_WITHIN: Duration = Duration::from_secs(10);

/// The most bytes of the ask, its line and its headers together.
const MAX_ASK: u64 = 16 * 1024;

/// The one port a run reaches.
const HTTPS_PORT: u16 = 443;

/// Where the filter reaches the hosts a ticket names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upstreams {
    /// Each host at the public addresses its name leads to, on port 443:
    /// every deployment. No setting chooses anything else.
    Public,
    /// Every host at one stand-in address, for tests on one machine.
    StandIn(SocketAddr),
}

/// How the filter is set up.
#[derive(Debug, Clone)]
pub struct ProxyServing {
    /// Where it listens, reachable from the sandboxes alone.
    pub listen: SocketAddr,
    /// The key tickets are signed with.
    pub key: TicketKey,
    /// The most tunnels it holds at once.
    pub most_at_once: usize,
    /// Where it reaches the hosts.
    pub upstreams: Upstreams,
}

/// The network filter, serving tunnels.
pub struct SandboxProxy {
    serving: ProxyServing,
    tunnels: Arc<Semaphore>,
}

/// Why a tunnel was refused, as the code is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// The ask was no tunnel to a host's port.
    NotATunnel,
    /// No ticket, or a forged or ended one.
    NoTicket,
    /// The ticket does not name the host, or the port is another.
    NotAllowed,
    /// The host leads nowhere public, or cannot be reached.
    Unreachable,
    /// Every tunnel the filter may hold is open.
    Busy,
}

impl Refusal {
    /// The answer that tells the code.
    fn answer(self) -> &'static [u8] {
        match self {
            Self::NotATunnel => b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n",
            Self::NoTicket => {
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"sandbox\"\r\nConnection: close\r\n\r\n"
            }
            Self::NotAllowed => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n",
            Self::Unreachable => b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
            Self::Busy => b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n",
        }
    }
}

/// A tunnel the ask names: its host and port, and the ticket shown.
#[derive(Debug, PartialEq, Eq)]
struct Asked {
    host: String,
    port: u16,
    ticket: Option<String>,
}

impl SandboxProxy {
    /// A filter set up as `serving` says.
    #[must_use]
    pub fn new(serving: ProxyServing) -> Self {
        let tunnels = Arc::new(Semaphore::new(serving.most_at_once.max(1)));
        Self { serving, tunnels }
    }

    /// Serves tunnels on its address until `stopping` resolves, then closes
    /// those open.
    ///
    /// # Errors
    ///
    /// When its address cannot be listened on.
    pub async fn serve(
        self: Arc<Self>,
        stopping: impl std::future::Future<Output = ()>,
    ) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.serving.listen).await?;
        self.serve_on(listener, stopping).await;
        Ok(())
    }

    /// Serves tunnels on `listener` until `stopping` resolves, then closes
    /// those open.
    pub async fn serve_on(
        self: Arc<Self>,
        listener: TcpListener,
        stopping: impl std::future::Future<Output = ()>,
    ) {
        let mut served = JoinSet::new();
        tokio::pin!(stopping);
        loop {
            while served.try_join_next().is_some() {}
            let accepted = tokio::select! {
                () = &mut stopping => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else {
                continue;
            };
            let proxy = Arc::clone(&self);
            served.spawn(async move { proxy.serve_connection(stream).await });
        }
        served.abort_all();
    }

    /// Answers the one tunnel `stream` asks for.
    async fn serve_connection(&self, mut stream: TcpStream) {
        let Ok(_tunnel) = Arc::clone(&self.tunnels).try_acquire_owned() else {
            refuse(&mut stream, Refusal::Busy).await;
            return;
        };
        let (upstream, ends_in) = match self.opened(&mut stream).await {
            Ok(opened) => opened,
            Err(refusal) => {
                tracing::info!(?refusal, "the network filter refused a tunnel");
                refuse(&mut stream, refusal).await;
                return;
            }
        };
        tunnel(stream, upstream, ends_in).await;
    }

    /// The connection the ask on `stream` is let through to, and how long
    /// until its ticket ends.
    async fn opened(&self, stream: &mut TcpStream) -> Result<(TcpStream, Duration), Refusal> {
        let asked = tokio::time::timeout(ASKED_WITHIN, read_ask(stream))
            .await
            .map_err(|_| Refusal::NotATunnel)??;
        let now = seconds_now();
        let token = asked.ticket.as_deref().ok_or(Refusal::NoTicket)?;
        let ticket = Ticket::verified(&self.serving.key, token, now).ok_or(Refusal::NoTicket)?;
        if asked.port != HTTPS_PORT || !ticket.allows(&asked.host) {
            return Err(Refusal::NotAllowed);
        }
        let upstream = tokio::time::timeout(CONNECTED_WITHIN, self.connected(&asked.host))
            .await
            .map_err(|_| Refusal::Unreachable)??;
        let ends_in = Duration::from_secs(ticket.ends_at.saturating_sub(now));
        Ok((upstream, ends_in))
    }

    /// A connection to `host`, at an address the filter may reach.
    async fn connected(&self, host: &str) -> Result<TcpStream, Refusal> {
        let addresses = match self.serving.upstreams {
            Upstreams::Public => public_addresses(host).await?,
            Upstreams::StandIn(address) => vec![address],
        };
        for address in addresses {
            if let Ok(stream) = TcpStream::connect(address).await {
                return Ok(stream);
            }
        }
        Err(Refusal::Unreachable)
    }
}

/// The addresses `host`'s name leads to on port 443, refused whole when any
/// is not public, so a name that leads somewhere private is never reached.
async fn public_addresses(host: &str) -> Result<Vec<SocketAddr>, Refusal> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, HTTPS_PORT))
        .await
        .map_err(|_| Refusal::Unreachable)?
        .collect();
    if addresses.is_empty() || addresses.iter().any(|address| is_blocked_ip(address.ip())) {
        return Err(Refusal::Unreachable);
    }
    Ok(addresses)
}

/// Reads the ask on `stream`: a `CONNECT host:port` line, then headers, the
/// ticket among them as the proxy password, up to the blank line.
async fn read_ask(stream: &mut TcpStream) -> Result<Asked, Refusal> {
    let mut reader = BufReader::new(stream.take(MAX_ASK));
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|_| Refusal::NotATunnel)?;
    let (host, port) = target_of(line.trim_end()).ok_or(Refusal::NotATunnel)?;
    let mut ticket = None;
    loop {
        let mut header = String::new();
        let read = reader
            .read_line(&mut header)
            .await
            .map_err(|_| Refusal::NotATunnel)?;
        let header = header.trim_end();
        if read == 0 {
            return Err(Refusal::NotATunnel);
        }
        if header.is_empty() {
            break;
        }
        if let Some(shown) = ticket_of(header) {
            ticket = Some(shown);
        }
    }
    Ok(Asked { host, port, ticket })
}

/// The host and port a `CONNECT host:port HTTP/1.1` line names.
fn target_of(line: &str) -> Option<(String, u16)> {
    let mut words = line.split(' ');
    let (method, target, version) = (words.next()?, words.next()?, words.next()?);
    if method != "CONNECT" || !version.starts_with("HTTP/1.") || words.next().is_some() {
        return None;
    }
    let (host, port) = target.rsplit_once(':')?;
    let named = !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    if !named {
        return None;
    }
    Some((host.to_ascii_lowercase(), port.parse().ok()?))
}

/// The ticket a `Proxy-Authorization: Basic` header shows as its password.
fn ticket_of(header: &str) -> Option<String> {
    let (name, value) = header.split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
        return None;
    }
    let encoded = value.trim().strip_prefix("Basic ")?;
    if encoded.len() > MAX_TICKET.saturating_mul(2) {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
    let (_, password) = decoded.split_once(':')?;
    Some(password.to_owned())
}

/// Tells the code its tunnel was refused, and closes.
async fn refuse(stream: &mut TcpStream, refusal: Refusal) {
    if let Err(error) = stream.write_all(refusal.answer()).await {
        tracing::debug!(%error, "a refused tunnel closed first");
    }
}

/// Carries bytes both ways between the code and the host until either
/// closes or the ticket ends in `ends_in`.
async fn tunnel(mut code: TcpStream, mut upstream: TcpStream, ends_in: Duration) {
    if code
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let carried = tokio::time::timeout(
        ends_in,
        tokio::io::copy_bidirectional(&mut code, &mut upstream),
    );
    if carried.await.is_err() {
        tracing::info!("a tunnel closed as its ticket ended");
    }
}

/// Seconds since the Unix epoch.
fn seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tunnel is asked for by `CONNECT` to a host's port; anything else,
    /// a host holding odd characters or words added, is no tunnel.
    #[test]
    fn only_a_connect_line_names_a_tunnel() {
        assert_eq!(
            target_of("CONNECT API.github.com:443 HTTP/1.1"),
            Some(("api.github.com".to_owned(), 443))
        );
        assert_eq!(target_of("GET http://api.github.com/ HTTP/1.1"), None);
        assert_eq!(target_of("CONNECT api.github.com HTTP/1.1"), None);
        assert_eq!(target_of("CONNECT a@b.com:443 HTTP/1.1"), None);
        assert_eq!(target_of("CONNECT api.github.com:443 HTTP/1.1 extra"), None);
    }

    /// The ticket is read as the proxy password of a basic header, the
    /// header named in any case.
    #[test]
    fn the_ticket_is_the_proxy_password() {
        let shown = format!(
            "proxy-authorization: Basic {}",
            STANDARD.encode("run:the.ticket")
        );

        assert_eq!(ticket_of(&shown).as_deref(), Some("the.ticket"));
        assert_eq!(ticket_of("Authorization: Basic cnVuOng="), None);
        assert_eq!(ticket_of("Proxy-Authorization: Bearer x"), None);
    }

    /// Resolving localhost as a public upstream returns an unreachable refusal.
    #[tokio::test]
    async fn a_name_leading_somewhere_private_is_refused() {
        let refused = public_addresses("localhost").await;

        assert_eq!(refused, Err(Refusal::Unreachable));
    }
}
