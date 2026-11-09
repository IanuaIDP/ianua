//! Reading the server name out of a TLS `ClientHello`.
//!
//! Passthrough does not finish the handshake, so the only thing the gateway
//! learns about a connection is the name the client asked for, in the
//! clear, in the first flight. This reads that name and nothing else.
//!
//! Every function here is total. The input is the first bytes an
//! unauthenticated client sent, so a parser that panics on a truncated
//! length is a remote crash. Nothing here indexes; every step is a checked
//! slice, and anything unexpected is `None`, which the caller treats as a
//! connection that named nothing: one only an unrestricted route takes.

/// The most of a `ClientHello` worth reading.
///
/// TLS caps a handshake record at 16 KiB, and the server name is in the
/// first flight.
pub(super) const MAX_CLIENT_HELLO: usize = 16 * 1024 + 5;

/// The fewest bytes that could carry a record header and a handshake
/// header.
pub(super) const MIN_CLIENT_HELLO: usize = 9;

/// The record type of a TLS handshake.
const HANDSHAKE_RECORD: u8 = 0x16;

/// The handshake type of a `ClientHello`.
const CLIENT_HELLO: u8 = 0x01;

/// The extension type of `server_name`.
const SERVER_NAME_EXTENSION: u16 = 0x0000;

/// The name type of a `host_name` entry.
const HOST_NAME: u8 = 0;

/// A cursor that cannot run off the end.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        let pair: [u8; 2] = self.take(2)?.try_into().ok()?;
        Some(u16::from_be_bytes(pair))
    }

    /// The vector whose length is written in the next byte.
    fn u8_vec(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    /// The vector whose length is written in the next two bytes.
    fn u16_vec(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
}

/// The server name the bytes a client opened with ask for.
///
/// `None` when the bytes are not a whole TLS `ClientHello`, carry no
/// server name, or carry one that is not a plain host name. The whole
/// record must have arrived: a header that claims more than was sent names
/// nothing, so a client cannot have a name honoured for a record no server
/// would accept.
pub(super) fn server_name(bytes: &[u8]) -> Option<String> {
    let mut record = Reader::new(bytes);
    if record.u8()? != HANDSHAKE_RECORD {
        return None;
    }
    record.take(2)?;
    let mut hello = Reader::new(record.u16_vec()?);
    if hello.u8()? != CLIENT_HELLO {
        return None;
    }
    hello.take(3)?;
    hello.take(2 + 32)?;
    hello.u8_vec()?;
    hello.u16_vec()?;
    hello.u8_vec()?;
    server_name_in_extensions(hello.u16_vec()?)
}

/// The host name in the `server_name` extension of `extensions`.
fn server_name_in_extensions(extensions: &[u8]) -> Option<String> {
    let mut r = Reader::new(extensions);
    loop {
        let kind = r.u16()?;
        let body = r.u16_vec()?;
        if kind == SERVER_NAME_EXTENSION {
            return first_host_name(body);
        }
    }
}

/// The first `host_name` entry of a `server_name` extension.
///
/// Clients send exactly one. Taking the first and ignoring the rest matches
/// what every server does; taking the last would let a client show the
/// gateway one name and the backend another.
fn first_host_name(body: &[u8]) -> Option<String> {
    let mut list = Reader::new(Reader::new(body).u16_vec()?);
    loop {
        let kind = list.u8()?;
        let value = list.u16_vec()?;
        if kind == HOST_NAME {
            return plain_host_name(value);
        }
    }
}

/// `value` as a host name, when it is one: printable ASCII and not empty,
/// so a name with a newline never reaches a log or a comparison.
fn plain_host_name(value: &[u8]) -> Option<String> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    String::from_utf8(value.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn with_u16_len(body: &[u8]) -> Vec<u8> {
        let len = u16::try_from(body.len()).expect("a short test body");
        let mut out = len.to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    /// A `ClientHello` carrying `name`, or no SNI extension when `name` is
    /// empty.
    fn client_hello(name: &str) -> Vec<u8> {
        let mut extensions = Vec::new();
        if !name.is_empty() {
            let mut entry = vec![HOST_NAME];
            entry.extend_from_slice(&with_u16_len(name.as_bytes()));
            extensions.extend_from_slice(&SERVER_NAME_EXTENSION.to_be_bytes());
            extensions.extend_from_slice(&with_u16_len(&with_u16_len(&entry)));
        }

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&with_u16_len(&[0x13, 0x01]));
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&with_u16_len(&extensions));

        let len = u32::try_from(body.len()).expect("a short test body");
        let mut handshake = vec![CLIENT_HELLO];
        handshake.extend_from_slice(&len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![HANDSHAKE_RECORD, 0x03, 0x01];
        record.extend_from_slice(&with_u16_len(&handshake));
        record
    }

    #[test]
    fn reads_the_server_name() {
        let hello = client_hello("db.acme.com");

        assert_eq!(server_name(&hello).as_deref(), Some("db.acme.com"));
    }

    #[test]
    fn a_hello_without_sni_names_nothing() {
        assert_eq!(server_name(&client_hello("")), None);
    }

    #[test]
    fn every_truncation_of_a_hello_names_nothing() {
        let hello = client_hello("db.acme.com");

        for n in 0..hello.len() {
            assert_eq!(server_name(&hello[..n]), None);
        }
    }

    #[test]
    fn garbage_names_nothing() {
        assert_eq!(server_name(&[]), None);
        assert_eq!(server_name(&[HANDSHAKE_RECORD]), None);
        assert_eq!(server_name(&[0xff; 64]), None);
        assert_eq!(server_name(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn a_record_claiming_more_than_was_sent_names_nothing() {
        let mut hello = client_hello("db.acme.com");
        hello[3] = 0xff;
        hello[4] = 0xff;

        assert_eq!(server_name(&hello), None);
    }

    #[test]
    fn a_name_with_a_control_character_names_nothing() {
        assert_eq!(server_name(&client_hello("db.acme.com\nHost: x")), None);
    }

    proptest! {
        #[test]
        fn any_bytes_are_read_without_panicking(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = server_name(&bytes);
        }

        #[test]
        fn any_plain_name_reads_back(name in "[a-z0-9]{1,20}(\\.[a-z0-9]{1,20}){0,3}") {
            prop_assert_eq!(server_name(&client_hello(&name)), Some(name));
        }
    }
}
