//! Asking a nameserver real questions over UDP and TCP, shared by the
//! integration tests.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// How long an answer may take before the test gives up on it.
const PATIENCE: Duration = Duration::from_secs(5);

fn question(name: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.add_query(Query::query(
        Name::from_ascii(format!("{name}.")).unwrap(),
        RecordType::A,
    ));
    message.to_vec().unwrap()
}

/// The answer the nameserver at `address` gives for `name`'s address
/// over UDP.
pub(super) async fn over_udp(address: SocketAddr, name: &str) -> Message {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&question(name), address).await.unwrap();
    let mut buffer = vec![0_u8; 4096];
    let (read, _) = tokio::time::timeout(PATIENCE, client.recv_from(&mut buffer))
        .await
        .expect("the nameserver answered over UDP")
        .unwrap();
    Message::from_vec(&buffer[..read]).unwrap()
}

/// The answer the nameserver at `address` gives for `name`'s address
/// over TCP.
pub(super) async fn over_tcp(address: SocketAddr, name: &str) -> Message {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = question(name);
    let length = u16::try_from(request.len()).unwrap();
    stream.write_all(&length.to_be_bytes()).await.unwrap();
    stream.write_all(&request).await.unwrap();
    let mut framed = [0_u8; 2];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut framed))
        .await
        .expect("the nameserver answered over TCP")
        .unwrap();
    let mut answer = vec![0_u8; usize::from(u16::from_be_bytes(framed))];
    stream.read_exact(&mut answer).await.unwrap();
    Message::from_vec(&answer).unwrap()
}

/// The addresses an answer holds.
pub(super) fn addresses(answer: &Message) -> Vec<String> {
    answer
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(address) => Some(address.0.to_string()),
            _ => None,
        })
        .collect()
}

/// The first answer for `name` over UDP that is not a refusal, asked
/// again every tenth of a second for at most `within`; `None` when every
/// one was refused.
pub(super) async fn answered_within(
    address: SocketAddr,
    name: &str,
    within: Duration,
) -> Option<Message> {
    let started = Instant::now();
    while started.elapsed() < within {
        let answer = over_udp(address, name).await;
        if answer.metadata.response_code != ResponseCode::Refused {
            return Some(answer);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}
