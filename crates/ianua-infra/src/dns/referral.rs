//! Asking the servers of the zone above a name, without recursion, which
//! name servers that zone delegates the name to.
//!
//! A recursive resolver answers that question from the delegated zone
//! itself, and for a name delegated to us that zone is ours. Only the zone
//! above says what its operator wrote, so it is asked directly: one server
//! after another, over UDP and again over TCP when the answer was cut
//! short, each try held to its own bound.
//!
//! An answer is believed only from the address it was asked of and only
//! with the question's own id, so a packet sent from elsewhere proves
//! nothing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_resolver::proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, Record, RecordType};
use ianua_domain::shared::errors::DomainError;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};

/// The port every authoritative name server answers on.
pub(super) const DNS_PORT: u16 = 53;

/// The largest answer read over UDP. A server sends at most 512 bytes to a
/// question that offers no more.
const MAX_UDP_ANSWER: usize = 4_096;

/// Asks the servers of a zone, without recursion, for a name's `NS`
/// records.
#[derive(Debug, Clone, Copy)]
pub(super) struct ReferralAsker {
    port: u16,
    per_try: Duration,
}

impl ReferralAsker {
    /// An asker reaching each server on `port`, each try held to `per_try`.
    pub(super) fn new(port: u16, per_try: Duration) -> Self {
        Self { port, per_try }
    }

    /// The `NS` records the first of `servers` to answer gives for `name`,
    /// from its answer and its referral alike: none when it says the name
    /// does not exist. A server that refuses, fails or stays silent is
    /// passed over for the next.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when no server answers.
    pub(super) async fn delegation(
        &self,
        name: &Name,
        servers: &[IpAddr],
    ) -> Result<Vec<Record>, DomainError> {
        for server in servers {
            let address = SocketAddr::new(*server, self.port);
            let Some(records) = self.asked(name, address).await else {
                continue;
            };
            return Ok(records);
        }
        Err(DomainError::infra_msg(
            "no server of the zone above the name answered for it",
        ))
    }

    /// What the server at `address` answers for `name`, or `None` when it
    /// gave no answer to read.
    async fn asked(&self, name: &Name, address: SocketAddr) -> Option<Vec<Record>> {
        let request = question_for(name);
        let bytes = request.to_vec().ok()?;
        let id = request.metadata.id;
        let answered = match self.over_udp(&bytes, address, id).await {
            Ok(answer) if answer.metadata.truncation => self.over_tcp(&bytes, address, id).await,
            other => other,
        };
        let answer = answered
            .inspect_err(
                |error| tracing::debug!(%address, %error, "a server above the name did not answer"),
            )
            .ok()?;
        delegation_in(answer, name)
    }

    /// The answer to `bytes` from `address` over UDP, read only from that
    /// address and only with the question's `id`.
    async fn over_udp(
        &self,
        bytes: &[u8],
        address: SocketAddr,
        id: u16,
    ) -> Result<Message, DomainError> {
        let socket = UdpSocket::bind(unbound_like(address))
            .await
            .map_err(DomainError::infra)?;
        socket.connect(address).await.map_err(DomainError::infra)?;
        socket.send(bytes).await.map_err(DomainError::infra)?;
        tokio::time::timeout(self.per_try, answer_on(&socket, id))
            .await
            .map_err(DomainError::infra)?
    }

    /// The answer to `bytes` from `address` over TCP, each message framed
    /// by its two-byte length.
    async fn over_tcp(
        &self,
        bytes: &[u8],
        address: SocketAddr,
        id: u16,
    ) -> Result<Message, DomainError> {
        tokio::time::timeout(self.per_try, exchanged_over_tcp(bytes, address))
            .await
            .map_err(DomainError::infra)??
            .filter(|answer| answers_question(answer, id))
            .ok_or_else(|| DomainError::infra_msg("the server's answer is not to our question"))
    }
}

/// A question for `name`'s `NS` records that asks for no recursion.
fn question_for(name: &Name) -> Message {
    let mut question = Message::query();
    question.metadata.recursion_desired = false;
    question.add_query(Query::query(name.clone(), RecordType::NS));
    question
}

/// The first message read on `socket` that answers the question `id`.
async fn answer_on(socket: &UdpSocket, id: u16) -> Result<Message, DomainError> {
    let mut buffer = vec![0_u8; MAX_UDP_ANSWER];
    loop {
        let read = socket.recv(&mut buffer).await.map_err(DomainError::infra)?;
        let Some(answer) = buffer
            .get(..read)
            .and_then(|bytes| Message::from_vec(bytes).ok())
        else {
            continue;
        };
        if answers_question(&answer, id) {
            return Ok(answer);
        }
    }
}

/// The message `address` answers `bytes` with over TCP, or `None` when what
/// it sent does not read as one.
async fn exchanged_over_tcp(
    bytes: &[u8],
    address: SocketAddr,
) -> Result<Option<Message>, DomainError> {
    let length = u16::try_from(bytes.len()).map_err(DomainError::infra)?;
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(DomainError::infra)?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(DomainError::infra)?;
    stream.write_all(bytes).await.map_err(DomainError::infra)?;
    let mut framed = [0_u8; 2];
    stream
        .read_exact(&mut framed)
        .await
        .map_err(DomainError::infra)?;
    let mut answer = vec![0_u8; usize::from(u16::from_be_bytes(framed))];
    stream
        .read_exact(&mut answer)
        .await
        .map_err(DomainError::infra)?;
    Ok(Message::from_vec(&answer).ok())
}

/// Whether `message` is an answer to the question `id`.
fn answers_question(message: &Message, id: u16) -> bool {
    message.metadata.id == id && message.metadata.message_type == MessageType::Response
}

/// The `NS` records for `name` in `answer`, from its answer and its
/// authority sections, none when the name does not exist, or `None` when
/// the server refused or failed.
fn delegation_in(answer: Message, name: &Name) -> Option<Vec<Record>> {
    let code = answer.metadata.response_code;
    if code == ResponseCode::NXDomain {
        return Some(Vec::new());
    }
    if code != ResponseCode::NoError {
        return None;
    }
    Some(
        answer
            .answers
            .into_iter()
            .chain(answer.authorities)
            .filter(|record| record.record_type() == RecordType::NS && record.name == *name)
            .collect(),
    )
}

/// Any local address of the family `address` is in, for a socket to reach
/// it from.
fn unbound_like(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}
