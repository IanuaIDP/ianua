//! The stack's name server: the recursive resolver the platform asks for a
//! domain proof (`DNS_RESOLVERS`), standing in for the public DNS a
//! customer writes their records in. A scenario writes a `TXT` record here
//! as a customer writes one at their DNS provider, and the platform's real
//! resolver reads it over UDP.
//!
//! It answers only `TXT` and `A` questions for names a scenario wrote, and
//! says no such name for anything else, so a proof that was never written
//! fails as it would on the internet. An `A` record lets a scenario's own
//! server stand at a public-looking name the platform looks up here.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, TXT};
use hickory_proto::rr::{RData, Record, RecordType};
use ianua_boot::shutdown::Shutdown;
use tokio::net::UdpSocket;

/// The largest question the name server reads.
const LARGEST_QUESTION: usize = 4096;

/// How long a resolver may keep an answer: nothing, so a record written
/// later is read at once.
const TTL: u32 = 0;

/// The records the scenarios wrote, by name.
type Written = Arc<RwLock<HashMap<String, Records>>>;

/// The records written at one name.
#[derive(Debug, Clone, Default)]
struct Records {
    /// Its `TXT` values.
    txt: Vec<String>,
    /// IPv4 destinations returned when a resolver asks for this name.
    addresses: Vec<Ipv4Addr>,
}

/// The stack's name server, answering over UDP on loopback.
#[derive(Clone)]
pub struct NameServer {
    address: SocketAddr,
    written: Written,
}

impl std::fmt::Debug for NameServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NameServer")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl NameServer {
    /// A name server on a port of loopback, answering until `shutdown`
    /// stops it.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub(crate) async fn open(shutdown: &Shutdown) -> io::Result<Self> {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let address = socket.local_addr()?;
        let written = Written::default();
        shutdown.spawn_until_stopped(answering(socket, Arc::clone(&written)));
        Ok(Self { address, written })
    }

    /// Where it answers.
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Writes a `TXT` record of `value` at `name`, beside any already there,
    /// as a customer does at their DNS provider.
    pub fn write_txt(&self, name: &str, value: &str) {
        let mut written = self.written.write().unwrap_or_else(PoisonError::into_inner);
        written
            .entry(canonical(name))
            .or_default()
            .txt
            .push(value.to_owned());
    }

    /// Writes an `A` record pointing `name` at `address`, as the owner of a
    /// public name does for the server answering at it.
    pub fn write_a(&self, name: &str, address: Ipv4Addr) {
        let mut written = self.written.write().unwrap_or_else(PoisonError::into_inner);
        written
            .entry(canonical(name))
            .or_default()
            .addresses
            .push(address);
    }
}

/// `name` as the server keys it: lowercase, with no final dot.
fn canonical(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Answers every question that arrives on `socket` from `written`.
async fn answering(socket: UdpSocket, written: Written) {
    let mut buffer = vec![0_u8; LARGEST_QUESTION];
    loop {
        let Ok((length, from)) = socket.recv_from(&mut buffer).await else {
            continue;
        };
        let Some(answer) = answer(&buffer[..length], &written) else {
            continue;
        };
        if let Err(error) = socket.send_to(&answer, from).await {
            tracing::debug!(%error, "the stack's name server could not answer");
        }
    }
}

/// The answer to the question in `bytes`, or none for one that does not
/// read.
fn answer(bytes: &[u8], written: &Written) -> Option<Vec<u8>> {
    let question = Message::from_vec(bytes).ok()?;
    let query = question.queries.first()?.clone();
    let mut response = Message::new(0, MessageType::Response, OpCode::Query);
    response.metadata = Metadata::response_from_request(&question.metadata);
    response.metadata.authoritative = true;
    response.add_query(query.clone());
    let records = written
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&canonical(&query.name().to_string()))
        .cloned();
    let name = query.name().clone();
    match (records, query.query_type()) {
        (Some(records), RecordType::TXT) => {
            response.add_answers(records.txt.into_iter().map(|value| {
                Record::from_rdata(name.clone(), TTL, RData::TXT(TXT::new(vec![value])))
            }));
        }
        (Some(records), RecordType::A) => {
            response.add_answers(
                records
                    .addresses
                    .into_iter()
                    .map(|address| Record::from_rdata(name.clone(), TTL, RData::A(A(address)))),
            );
        }
        (Some(_), _) => {}
        (None, _) => response.metadata.response_code = ResponseCode::NXDomain,
    }
    response.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;

    use super::*;

    fn asked(name: &str, kind: RecordType) -> Vec<u8> {
        let mut question = Message::new(7, MessageType::Query, OpCode::Query);
        question.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
        question.to_vec().unwrap()
    }

    fn txt_of(answer: &[u8]) -> Vec<String> {
        Message::from_vec(answer)
            .unwrap()
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt.to_string()),
                _ => None,
            })
            .collect()
    }

    /// A written record is answered, whatever the question's letter case.
    #[test]
    fn a_written_record_is_answered() {
        let written = Written::default();
        written.write().unwrap().insert(
            "_proof.shop.s1.example".to_owned(),
            Records {
                txt: vec!["token-1".to_owned()],
                addresses: Vec::new(),
            },
        );

        let answer = answer(&asked("_Proof.Shop.s1.example.", RecordType::TXT), &written).unwrap();

        assert_eq!(txt_of(&answer), ["token-1"]);
    }

    /// A written address is answered to an `A` question.
    #[test]
    fn a_written_address_is_answered() {
        let written = Written::default();
        written.write().unwrap().insert(
            "idp.s1.example".to_owned(),
            Records {
                txt: Vec::new(),
                addresses: vec![Ipv4Addr::LOCALHOST],
            },
        );

        let answer = answer(&asked("idp.s1.example.", RecordType::A), &written).unwrap();

        let addresses: Vec<Ipv4Addr> = Message::from_vec(&answer)
            .unwrap()
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(address) => Some(address.0),
                _ => None,
            })
            .collect();
        assert_eq!(addresses, [Ipv4Addr::LOCALHOST]);
    }

    /// A name nobody wrote is no such name.
    #[test]
    fn a_name_nobody_wrote_is_no_such_name() {
        let answer = answer(
            &asked("_proof.elsewhere.example.", RecordType::TXT),
            &Written::default(),
        )
        .unwrap();

        let message = Message::from_vec(&answer).unwrap();
        assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
        assert!(message.answers.is_empty());
    }
}
