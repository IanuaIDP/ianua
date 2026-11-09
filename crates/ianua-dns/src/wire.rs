//! Bytes in, bytes out. The only module that knows the DNS packet format.
//!
//! Everything about *what* to answer lives in the domain; this translates a
//! parsed question into the domain's vocabulary and the domain's answer back
//! into records. Keeping the split sharp is what lets the hard decisions be
//! tested without a socket.
//!
//! It refuses three things on purpose. It never recurses: answering for
//! names we do not hold would make us an open resolver. It never transfers
//! a zone, which would hand anyone every hostname every tenant delegated.
//! And it never answers `ANY`, the one small query that asks for a large
//! answer, which is what amplification attacks are built from.

use hickory_proto::op::{Message, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CAA, CNAME, MX, NS, SOA, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    Answer, AnswerValue, CaaProperty, CaaTag, QueryKind, RecordKind, RecordName, RecordValue,
    Resolution, ZoneCatalog,
};

/// The largest response we will put in a UDP packet without being asked to.
///
/// 512 bytes is what a resolver must accept without EDNS. Anything longer is
/// truncated with `TC` set, which tells the resolver to ask again over TCP —
/// the mechanism that stops a small query producing a large reply, and with
/// it the amplification that would otherwise make these servers useful to
/// somebody attacking a third party.
pub const MAX_UDP_RESPONSE: usize = 512;

/// The largest EDNS payload we will honour.
///
/// Senders may advertise more; ignoring the excess costs one extra TCP round
/// trip on a large answer and removes a large amplification factor. 1232 is
/// the figure the DNS Flag Day 2020 consensus settled on as the biggest
/// packet that reliably survives a path without fragmenting.
const MAX_EDNS_RESPONSE: usize = 1232;

/// How a query reached us, which decides how large the answer may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// A UDP datagram: the answer is capped and truncated past the cap.
    Udp,
    /// A TCP stream: the answer may be any size.
    Tcp,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
        })
    }
}

/// Answers one DNS message, returning the bytes to send back.
///
/// A packet we cannot parse gets no reply. There is nowhere to put an error
/// code in a message that is not a message, and answering anyway would mean
/// sending a packet to whatever address the sender claimed to be — which is
/// the whole of a reflection attack.
/// A packet that panics the parser is treated the same way, because from the
/// sender's side it is the same thing: input we could not read. `hickory-proto`
/// has arithmetic in its record parsers that is only checked where debug
/// assertions are on, so a crafted packet can unwind out of
/// [`Message::from_vec`] instead of returning an error. Letting that reach the
/// serving loop would end the task and take the nameserver with it, which is a
/// worse answer to a malformed packet than silence.
#[must_use]
pub fn answer_query(
    catalog: &ZoneCatalog,
    request: &[u8],
    transport: Transport,
) -> Option<Vec<u8>> {
    // SAFETY (unwind): `answer` borrows the catalog immutably and builds its
    // reply in locals, so an unwind out of it leaves nothing half-written for a
    // later request to observe.
    let answered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        answer(catalog, request, transport)
    }));

    answered.unwrap_or_else(|_| {
        tracing::warn!(
            bytes = request.len(),
            "dns request panicked the parser; dropped"
        );
        None
    })
}

fn answer(catalog: &ZoneCatalog, request: &[u8], transport: Transport) -> Option<Vec<u8>> {
    let request = Message::from_vec(request).ok()?;

    let mut response = Message::new(0, hickory_proto::op::MessageType::Response, OpCode::Query);
    response.metadata = Metadata::response_from_request(&request.metadata);

    let Some(query) = request.queries.first().cloned() else {
        response.metadata.response_code = ResponseCode::FormErr;
        return response.to_vec().ok();
    };

    response.add_query(query.clone());

    if request.metadata.op_code != OpCode::Query {
        response.metadata.response_code = ResponseCode::NotImp;
        return response.to_vec().ok();
    }

    apply(catalog, &query, &mut response);

    let limit = match transport {
        Transport::Tcp => usize::MAX,
        Transport::Udp => {
            (request.max_payload() as usize).clamp(MAX_UDP_RESPONSE, MAX_EDNS_RESPONSE)
        }
    };

    Some(encode(&response, limit))
}

/// Resolves one question into the response message.
fn apply(catalog: &ZoneCatalog, query: &Query, response: &mut Message) {
    let Some(name) = record_name(query.name()) else {
        response.metadata.response_code = ResponseCode::FormErr;
        return;
    };

    match catalog.answer(&name, query_kind(query.query_type())) {
        Resolution::Refused => response.metadata.response_code = ResponseCode::Refused,
        Resolution::NotImplemented => response.metadata.response_code = ResponseCode::NotImp,
        Resolution::Found { answers, authority } => {
            response.metadata.authoritative = true;
            response.add_answers(answers.iter().filter_map(record));
            response.add_authorities(authority.iter().filter_map(record));
        }
        Resolution::NoData { soa } => {
            response.metadata.authoritative = true;
            response.add_authorities(record(&soa));
        }
        Resolution::NameError { soa } => {
            response.metadata.authoritative = true;
            response.metadata.response_code = ResponseCode::NXDomain;
            response.add_authorities(record(&soa));
        }
    }
}

/// Encodes the response, truncating rather than overflowing `limit`.
///
/// A truncated answer keeps its question and its header and drops its
/// records, with `TC` set. That is not a failure: it is the protocol's own
/// instruction to the resolver to come back over TCP, where the whole answer
/// fits.
fn encode(response: &Message, limit: usize) -> Vec<u8> {
    let encoded = response.to_vec().unwrap_or_default();

    if encoded.len() <= limit {
        return encoded;
    }

    response.truncate().to_vec().unwrap_or_default()
}

/// The domain's name for a question's owner name.
///
/// A name that will not parse is one no zone of ours could hold, so the
/// question is malformed rather than merely unanswerable.
fn record_name(name: &Name) -> Option<RecordName> {
    RecordName::new(name.to_string().trim_end_matches('.')).ok()
}

/// The domain's kind for a query type.
///
/// Everything we do not serve collapses to [`QueryKind::Unsupported`], which
/// the resolver answers as `NOTIMP`. Naming each unsupported type here would
/// be a list to keep in step with a registry that grows without us.
fn query_kind(query_type: RecordType) -> QueryKind {
    match query_type {
        RecordType::A => QueryKind::Record(RecordKind::A),
        RecordType::AAAA => QueryKind::Record(RecordKind::Aaaa),
        RecordType::CNAME => QueryKind::Record(RecordKind::Cname),
        RecordType::TXT => QueryKind::Record(RecordKind::Txt),
        RecordType::MX => QueryKind::Record(RecordKind::Mx),
        RecordType::SRV => QueryKind::Record(RecordKind::Srv),
        RecordType::CAA => QueryKind::Record(RecordKind::Caa),
        RecordType::SOA => QueryKind::StartOfAuthority,
        RecordType::NS => QueryKind::Nameservers,
        RecordType::ANY => QueryKind::Any,
        _ => QueryKind::Unsupported,
    }
}

/// One answer as a wire record.
///
/// `None` when the value cannot be expressed — a malformed address that
/// somehow reached storage, or a name too long for the wire. Dropping the one
/// record is better than dropping the whole answer, and a zone that produced
/// it is wrong in a way no response code communicates.
fn record(answer: &Answer) -> Option<Record> {
    let name = wire_name(answer.name.as_str())?;
    let rdata = rdata(&answer.value)?;

    Some(Record::from_rdata(name, answer.ttl.as_seconds(), rdata))
}

/// A domain name as the wire spells it.
fn wire_name(text: &str) -> Option<Name> {
    Name::from_utf8(format!("{text}.")).ok()
}

/// One answer's value as wire rdata.
fn rdata(value: &AnswerValue) -> Option<RData> {
    match value {
        AnswerValue::Record(record) => record_rdata(record),
        AnswerValue::Nameserver(host) => Some(RData::NS(NS(wire_name(host.as_str())?))),
        AnswerValue::StartOfAuthority(soa) => Some(RData::SOA(SOA::new(
            wire_name(soa.primary().as_str())?,
            wire_name(soa.hostmaster().as_str())?,
            soa.serial().as_u32(),
            i32::try_from(soa.timers().refresh()).ok()?,
            i32::try_from(soa.timers().retry()).ok()?,
            i32::try_from(soa.timers().expire()).ok()?,
            soa.timers().minimum(),
        ))),
    }
}

/// One tenant record as wire rdata.
fn record_rdata(value: &RecordValue) -> Option<RData> {
    match value {
        RecordValue::Address(address) => match address.as_str().parse().ok()? {
            std::net::IpAddr::V4(v4) => Some(RData::A(A(v4))),
            std::net::IpAddr::V6(v6) => Some(RData::AAAA(AAAA(v6))),
        },
        RecordValue::Alias(target) => Some(RData::CNAME(CNAME(wire_name(target.as_str())?))),
        RecordValue::Text(text) => Some(RData::TXT(TXT::new(vec![text.as_str().to_owned()]))),
        RecordValue::Mail(mail) => Some(RData::MX(MX::new(
            mail.priority(),
            wire_name(mail.host().as_str())?,
        ))),
        RecordValue::Service(service) => Some(RData::SRV(SRV::new(
            service.priority(),
            service.weight(),
            service.port(),
            wire_name(service.host().as_str())?,
        ))),
        RecordValue::Authority(caa) => caa_rdata(caa),
    }
}

/// One certificate authorisation as wire rdata.
fn caa_rdata(caa: &CaaProperty) -> Option<RData> {
    let value = caa.value().as_str();

    let record = match caa.tag() {
        CaaTag::Issue => CAA::new_issue(
            caa.is_critical(),
            Some(Name::from_utf8(value).ok()?),
            Vec::new(),
        ),
        CaaTag::IssueWild => CAA::new_issuewild(
            caa.is_critical(),
            Some(Name::from_utf8(value).ok()?),
            Vec::new(),
        ),
        CaaTag::Iodef => CAA::new_iodef(caa.is_critical(), value.parse().ok()?),
    };

    Some(RData::CAA(record))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::dns_zone::Authority;

    use super::*;

    fn catalog() -> ZoneCatalog {
        let hostmaster = RecordName::new("hostmaster.ianua.test").expect("a valid record name");
        ZoneCatalog::empty(Authority::new(hostmaster))
    }

    /// Regression, found by the `dns_answer_query` fuzz target.
    ///
    /// These 43 bytes reach an unchecked subtraction in the TSIG record parser
    /// of `hickory-proto`, which panics wherever overflow checks are on. The
    /// contract on [`answer_query`] is that a packet we cannot parse gets no
    /// reply; a panic is not no reply, it is the serving task gone.
    #[test]
    fn a_packet_that_panics_the_parser_gets_no_reply() {
        let request = [
            0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 6, 0, 0, 0, 250, 254, 255, 255, 255, 0, 243, 0, 6, 0,
            255, 0, 1, 0, 0, 0, 0, 0, 1, 236, 6, 0, 243, 11, 0, 6, 4, 4, 255,
        ];

        assert_eq!(answer_query(&catalog(), &request, Transport::Udp), None);
        assert_eq!(answer_query(&catalog(), &request, Transport::Tcp), None);
    }

    #[test]
    fn garbage_gets_no_reply() {
        assert_eq!(answer_query(&catalog(), &[], Transport::Udp), None);
        assert_eq!(
            answer_query(&catalog(), b"not a dns packet", Transport::Udp),
            None
        );
    }
}
