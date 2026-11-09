//! The TLS ClientHello, read off the connection before the handshake so
//! its fingerprint can be taken.
//!
//! rustls reads the ClientHello too, but shows only part of it: the JA4
//! fingerprint needs every extension in the order sent. So the records
//! holding the ClientHello are read here first, bounded in size, parsed for
//! what the fingerprint needs, and then given back to rustls unchanged.
//! The handshake is still rustls's: nothing read here decides whether it
//! succeeds, except that a connection that does not open with a
//! well-formed ClientHello is refused.

use tokio::io::{AsyncRead, AsyncReadExt};

/// The largest ClientHello read. Real ones are a few hundred bytes, or a
/// couple of kilobytes with post-quantum key shares.
pub(crate) const MAX_HELLO_BYTES: usize = 32_768;

const RECORD_HEADER: usize = 5;
const MAX_RECORD: usize = 16_384;
const HANDSHAKE_RECORD: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const HANDSHAKE_HEADER: usize = 4;
const RANDOM_BYTES: usize = 32;

/// The extension naming the server, by its code point.
pub(crate) const SERVER_NAME: u16 = 0x0000;
/// The extension listing application protocols (ALPN).
pub(crate) const ALPN: u16 = 0x0010;
const SIGNATURE_ALGORITHMS: u16 = 0x000d;
const SUPPORTED_VERSIONS: u16 = 0x002b;

/// Why a connection's opening is not a ClientHello that can be read.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HelloError {
    /// The connection opened with something other than a ClientHello.
    #[error("the connection did not open with a TLS ClientHello")]
    NotAHello,
    /// The ClientHello is longer than [`MAX_HELLO_BYTES`].
    #[error("the ClientHello is longer than {MAX_HELLO_BYTES} bytes")]
    TooLong,
    /// The ClientHello does not parse.
    #[error("the ClientHello is malformed")]
    Malformed,
    /// The connection failed or ended mid-hello.
    #[error("reading the ClientHello failed")]
    Io(#[source] std::io::Error),
}

/// What a ClientHello offers, as far as its fingerprint needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientHello {
    legacy_version: u16,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    first_protocol: Option<Vec<u8>>,
    signature_algorithms: Vec<u16>,
    supported_versions: Vec<u16>,
}

/// A ClientHello, and the records it came in, to be given back.
#[derive(Debug)]
pub(crate) struct RecordedHello {
    records: Vec<u8>,
    hello: ClientHello,
}

impl RecordedHello {
    /// What the ClientHello offers.
    pub(crate) fn hello(&self) -> &ClientHello {
        &self.hello
    }

    /// The bytes read off the connection, to be read again by the handshake.
    pub(crate) fn into_records(self) -> Vec<u8> {
        self.records
    }
}

/// Reads the records holding the ClientHello off `stream`.
///
/// # Errors
///
/// [`HelloError`] when the connection does not open with a handshake
/// record holding a ClientHello, the ClientHello is too long or malformed,
/// or the connection fails before it is whole.
pub(crate) async fn read_client_hello<S>(stream: &mut S) -> Result<RecordedHello, HelloError>
where
    S: AsyncRead + Unpin,
{
    let mut records = Vec::new();
    let mut message = Vec::new();
    loop {
        if records.len() > MAX_HELLO_BYTES {
            return Err(HelloError::TooLong);
        }
        let (header, fragment) = read_record(stream).await?;
        records.extend_from_slice(&header);
        records.extend_from_slice(&fragment);
        message.extend_from_slice(&fragment);
        if let Some(body) = whole_hello(&message)? {
            let hello = ClientHello::parse(body)?;
            return Ok(RecordedHello { records, hello });
        }
    }
}

/// One handshake record: its header and its fragment.
async fn read_record<S>(stream: &mut S) -> Result<([u8; RECORD_HEADER], Vec<u8>), HelloError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; RECORD_HEADER];
    stream
        .read_exact(&mut header)
        .await
        .map_err(HelloError::Io)?;
    if header[0] != HANDSHAKE_RECORD {
        return Err(HelloError::NotAHello);
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length == 0 || length > MAX_RECORD {
        return Err(HelloError::Malformed);
    }
    let mut fragment = vec![0_u8; length];
    stream
        .read_exact(&mut fragment)
        .await
        .map_err(HelloError::Io)?;
    Ok((header, fragment))
}

/// The ClientHello's body once `message` holds all of it.
fn whole_hello(message: &[u8]) -> Result<Option<&[u8]>, HelloError> {
    let Some(header) = message.get(..HANDSHAKE_HEADER) else {
        return Ok(None);
    };
    if header[0] != CLIENT_HELLO {
        return Err(HelloError::NotAHello);
    }
    let length =
        (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
    if length > MAX_HELLO_BYTES {
        return Err(HelloError::TooLong);
    }
    Ok(message.get(HANDSHAKE_HEADER..HANDSHAKE_HEADER + length))
}

impl ClientHello {
    /// Parses a ClientHello's body, after its handshake header.
    ///
    /// # Errors
    ///
    /// [`HelloError::Malformed`] when a length runs past the bytes there
    /// are, or bytes are left over.
    pub(crate) fn parse(body: &[u8]) -> Result<Self, HelloError> {
        let mut reader = Reader::new(body);
        let legacy_version = reader.u16()?;
        let _random = reader.take(RANDOM_BYTES)?;
        let _session_id = reader.vec8()?;
        let cipher_suites = Reader::new(reader.vec16()?).u16s()?;
        let _compression_methods = reader.vec8()?;
        let mut hello = Self {
            legacy_version,
            cipher_suites,
            extensions: Vec::new(),
            first_protocol: None,
            signature_algorithms: Vec::new(),
            supported_versions: Vec::new(),
        };
        if reader.is_empty() {
            return Ok(hello);
        }
        let mut extensions = Reader::new(reader.vec16()?);
        reader.ensure_empty()?;
        while !extensions.is_empty() {
            let kind = extensions.u16()?;
            let data = extensions.vec16()?;
            hello.note_extension(kind, data)?;
        }
        Ok(hello)
    }

    fn note_extension(&mut self, kind: u16, data: &[u8]) -> Result<(), HelloError> {
        self.extensions.push(kind);
        match kind {
            ALPN => self.first_protocol = first_protocol(data)?,
            SIGNATURE_ALGORITHMS => {
                self.signature_algorithms = Reader::new(Reader::new(data).vec16()?).u16s()?;
            }
            SUPPORTED_VERSIONS => {
                self.supported_versions = Reader::new(Reader::new(data).vec8()?).u16s()?;
            }
            _ => {}
        }
        Ok(())
    }

    /// The version in the ClientHello's own header.
    pub(crate) fn legacy_version(&self) -> u16 {
        self.legacy_version
    }

    /// The cipher suites offered, in the order sent.
    pub(crate) fn cipher_suites(&self) -> &[u16] {
        &self.cipher_suites
    }

    /// The extensions' code points, in the order sent.
    pub(crate) fn extensions(&self) -> &[u16] {
        &self.extensions
    }

    /// The first application protocol offered, if any was.
    pub(crate) fn first_protocol(&self) -> Option<&[u8]> {
        self.first_protocol.as_deref()
    }

    /// The signature algorithms offered, in the order sent.
    pub(crate) fn signature_algorithms(&self) -> &[u16] {
        &self.signature_algorithms
    }

    /// The versions the `supported_versions` extension lists.
    pub(crate) fn supported_versions(&self) -> &[u16] {
        &self.supported_versions
    }
}

/// The first protocol an ALPN extension lists, or `None` for an empty list.
fn first_protocol(data: &[u8]) -> Result<Option<Vec<u8>>, HelloError> {
    let mut protocols = Reader::new(Reader::new(data).vec16()?);
    if protocols.is_empty() {
        return Ok(None);
    }
    Ok(Some(protocols.vec8()?.to_vec()))
}

/// Reads big-endian fields off a byte slice, refusing any that run past it.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn ensure_empty(&self) -> Result<(), HelloError> {
        if !self.bytes.is_empty() {
            return Err(HelloError::Malformed);
        }
        Ok(())
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], HelloError> {
        let (head, rest) = self
            .bytes
            .split_at_checked(count)
            .ok_or(HelloError::Malformed)?;
        self.bytes = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, HelloError> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u16(&mut self) -> Result<u16, HelloError> {
        self.take(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn vec8(&mut self) -> Result<&'a [u8], HelloError> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    fn vec16(&mut self) -> Result<&'a [u8], HelloError> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }

    /// Reads complete big-endian pairs, refusing an unmatched trailing byte.
    fn u16s(self) -> Result<Vec<u16>, HelloError> {
        let (pairs, remainder) = self.bytes.as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(HelloError::Malformed);
        }
        Ok(pairs.iter().copied().map(u16::from_be_bytes).collect())
    }
}

/// ClientHellos written byte by byte for tests.
#[cfg(test)]
pub(crate) mod samples {
    /// A ClientHello offering `cipher_suites` and `extensions` (code point
    /// and data), wrapped in one handshake record.
    pub(crate) fn record(cipher_suites: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0_u8; 32]);
        body.push(32);
        body.extend_from_slice(&[7_u8; 32]);
        body.extend_from_slice(&with_u16_length(&u16s(cipher_suites)));
        body.extend_from_slice(&[1, 0]);
        let block: Vec<u8> = extensions
            .iter()
            .flat_map(|(kind, data)| {
                let mut extension = kind.to_be_bytes().to_vec();
                extension.extend_from_slice(&with_u16_length(data));
                extension
            })
            .collect();
        body.extend_from_slice(&with_u16_length(&block));

        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        let mut message = vec![1, length[1], length[2], length[3]];
        message.extend_from_slice(&body);

        let mut record = vec![22, 0x03, 0x01];
        record.extend_from_slice(&with_u16_length(&message));
        record
    }

    /// The example the JA4 specification publishes, with GREASE values
    /// scattered through it and the lists out of order: fifteen cipher
    /// suites, sixteen extensions, `h2` first, TLS 1.3 offered.
    pub(crate) fn published_example() -> Vec<u8> {
        let ciphers = [
            0x2a2a, 0xc02c, 0x1301, 0x002f, 0xcca9, 0x1303, 0xc013, 0x009c, 0xc030, 0x0035, 0x1302,
            0xc02b, 0x009d, 0xcca8, 0xc014, 0xc02f,
        ];
        record(&ciphers, &published_extensions())
    }

    /// The published JA4 example's extension order and encoded extension data.
    fn published_extensions() -> Vec<(u16, Vec<u8>)> {
        let empty = |kind: u16| (kind, Vec::new());
        vec![
            empty(0x0a0a),
            (0x0000, server_name("example.com")),
            empty(0x0017),
            empty(0xff01),
            empty(0x000a),
            empty(0x000b),
            empty(0x0023),
            (0x0010, alpn(&[b"h2", b"http/1.1"])),
            empty(0x0005),
            (
                0x000d,
                with_u16_length(&u16s(&[
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                ])),
            ),
            empty(0x0012),
            empty(0x0033),
            empty(0x002d),
            (0x002b, with_u8_length(&u16s(&[0x3a3a, 0x0304, 0x0303]))),
            empty(0x001b),
            empty(0x0015),
            empty(0x4469),
            (0x1a1a, vec![0]),
        ]
    }

    fn server_name(name: &str) -> Vec<u8> {
        let mut entry = vec![0];
        entry.extend_from_slice(&with_u16_length(name.as_bytes()));
        with_u16_length(&entry)
    }

    /// An ALPN extension's data listing `protocols`.
    pub(crate) fn alpn(protocols: &[&[u8]]) -> Vec<u8> {
        let list: Vec<u8> = protocols
            .iter()
            .flat_map(|protocol| with_u8_length(protocol))
            .collect();
        with_u16_length(&list)
    }

    fn u16s(values: &[u16]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_be_bytes())
            .collect()
    }

    fn with_u8_length(bytes: &[u8]) -> Vec<u8> {
        let mut prefixed = vec![u8::try_from(bytes.len()).unwrap()];
        prefixed.extend_from_slice(bytes);
        prefixed
    }

    fn with_u16_length(bytes: &[u8]) -> Vec<u8> {
        let mut prefixed = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        prefixed.extend_from_slice(bytes);
        prefixed
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    async fn read_bytes(bytes: Vec<u8>) -> Result<RecordedHello, HelloError> {
        read_client_hello(&mut std::io::Cursor::new(bytes)).await
    }

    /// Everything the fingerprint needs is read, in the order sent.
    #[tokio::test]
    async fn the_offer_is_read_in_the_order_sent() {
        let recorded = read_bytes(samples::published_example()).await.unwrap();
        let hello = recorded.hello();

        assert_eq!(hello.legacy_version(), 0x0303);
        assert_eq!(hello.cipher_suites().len(), 16);
        assert_eq!(hello.extensions()[..3], [0x0a0a, 0x0000, 0x0017]);
        assert_eq!(hello.first_protocol(), Some(&b"h2"[..]));
        assert_eq!(hello.signature_algorithms()[0], 0x0403);
        assert_eq!(hello.supported_versions(), [0x3a3a, 0x0304, 0x0303]);
    }

    /// The records come back exactly as read, and nothing after them is
    /// taken off the connection.
    #[tokio::test]
    async fn the_records_come_back_whole_and_nothing_more_is_read() {
        let record = samples::published_example();
        let mut bytes = record.clone();
        bytes.extend_from_slice(b"after");
        let mut stream = std::io::Cursor::new(bytes);

        let recorded = read_client_hello(&mut stream).await.unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();

        assert_eq!(recorded.into_records(), record);
        assert_eq!(rest, b"after");
    }

    /// A ClientHello split over two records is joined.
    #[tokio::test]
    async fn a_hello_split_over_two_records_is_joined() {
        let record = samples::published_example();
        let message = &record[RECORD_HEADER..];
        let (first, second) = message.split_at(40);
        let mut bytes = Vec::new();
        for fragment in [first, second] {
            bytes.extend_from_slice(&[22, 0x03, 0x01]);
            bytes.extend_from_slice(&u16::try_from(fragment.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(fragment);
        }

        let recorded = read_bytes(bytes).await.unwrap();

        assert_eq!(recorded.hello().cipher_suites().len(), 16);
    }

    /// A plain HTTP request on the TLS port is not a ClientHello.
    #[tokio::test]
    async fn plain_http_is_not_a_hello() {
        let read = read_bytes(b"GET / HTTP/1.1\r\n\r\n".to_vec()).await;

        assert!(matches!(read, Err(HelloError::NotAHello)));
    }

    /// A handshake message that is not a ClientHello is refused.
    #[tokio::test]
    async fn another_handshake_message_is_not_a_hello() {
        let mut record = samples::published_example();
        record[RECORD_HEADER] = 2;

        let read = read_bytes(record).await;

        assert!(matches!(read, Err(HelloError::NotAHello)));
    }

    /// A length that runs past the bytes there are is refused.
    #[tokio::test]
    async fn a_length_running_past_the_hello_is_malformed() {
        let mut record = samples::published_example();
        let session_id_length = RECORD_HEADER + HANDSHAKE_HEADER + 2 + RANDOM_BYTES;
        record[session_id_length] = 0xff;

        let read = read_bytes(record).await;

        assert!(matches!(read, Err(HelloError::Malformed)));
    }

    /// A ClientHello claiming more than the bound is refused before it is
    /// read.
    #[tokio::test]
    async fn an_oversized_hello_is_refused() {
        let bytes = vec![22, 0x03, 0x01, 0x00, 0x04, 1, 0xff, 0xff, 0xff];

        let read = read_bytes(bytes).await;

        assert!(matches!(read, Err(HelloError::TooLong)));
    }

    /// A connection that ends mid-hello is an error.
    #[tokio::test]
    async fn a_truncated_hello_is_an_error() {
        let record = samples::published_example();

        let read = read_bytes(record[..30].to_vec()).await;

        assert!(matches!(read, Err(HelloError::Io(_))));
    }
}
