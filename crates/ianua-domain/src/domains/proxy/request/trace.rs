//! W3C Trace Context: where the proxy sits in somebody else's trace.
//!
//! A request usually arrives already inside a trace. A browser, a mobile app
//! or an upstream service started one and passed it along in `traceparent`.
//! A gateway that ignores it leaves a gap in every trace that crosses it. The
//! caller's span ends, the backend's span begins, and the hop that decided
//! whether the request was allowed is missing.
//!
//! This module holds the whole format. It parses what arrived, or starts a
//! trace when nothing did, and builds the header the upstream should see.
//!
//! <https://www.w3.org/TR/trace-context/>

use std::fmt;

/// The only version of the header this understands.
///
/// The spec requires a later version to stay readable. So a higher version
/// number is parsed on the assumption that its first four fields mean what
/// they mean in version 00. `ff` is reserved and never valid.
const SUPPORTED_VERSION: u8 = 0;

/// The bit that says the caller is recording this trace.
const SAMPLED_FLAG: u8 = 0x01;

/// A trace identifier: 16 bytes, never all zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId([u8; 16]);

/// A span identifier: 8 bytes, never all zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpanId([u8; 8]);

impl TraceId {
    /// The identifier these bytes name, or `None` if they are all zero.
    #[must_use]
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        (bytes != [0; 16]).then_some(Self(bytes))
    }

    /// The identifier this hex names.
    #[must_use]
    pub fn parse(hex: &str) -> Option<Self> {
        Self::new(decode_hex::<16>(hex)?)
    }

    /// The bytes, as an exporter wants them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl SpanId {
    /// The identifier these bytes name, or `None` if they are all zero.
    #[must_use]
    pub fn new(bytes: [u8; 8]) -> Option<Self> {
        (bytes != [0; 8]).then_some(Self(bytes))
    }

    /// The identifier this hex names.
    #[must_use]
    pub fn parse(hex: &str) -> Option<Self> {
        Self::new(decode_hex::<8>(hex)?)
    }

    /// The bytes, as an exporter wants them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// Whether a trace's spans are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sampling {
    /// The trace is recorded.
    Sampled,
    /// The trace is passed on but not recorded.
    NotSampled,
}

impl Sampling {
    /// What the sampled bit of a header's trace flags says.
    fn from_flags(flags: u8) -> Self {
        if flags & SAMPLED_FLAG == 0 {
            return Self::NotSampled;
        }
        Self::Sampled
    }

    /// The trace flags a header carries for this choice.
    fn flags(self) -> u8 {
        match self {
            Self::Sampled => SAMPLED_FLAG,
            Self::NotSampled => 0,
        }
    }
}

/// Where this request sits in a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    trace_id: TraceId,
    span_id: SpanId,
    sampling: Sampling,
}

impl TraceContext {
    /// Builds a context from its parts.
    #[must_use]
    pub fn new(trace_id: TraceId, span_id: SpanId, sampling: Sampling) -> Self {
        Self {
            trace_id,
            span_id,
            sampling,
        }
    }

    /// The trace this request belongs to.
    #[must_use]
    pub fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// The span this context names.
    #[must_use]
    pub fn span_id(&self) -> SpanId {
        self.span_id
    }

    /// Whether the trace is being recorded.
    ///
    /// A gateway keeps what the caller decided instead of sampling again.
    /// Half a trace is worse than none, and only the caller knows whether the
    /// rest of it is being kept.
    #[must_use]
    pub fn sampling(&self) -> Sampling {
        self.sampling
    }

    /// Whether the trace is being recorded. See [`Self::sampling`].
    #[must_use]
    pub fn is_sampled(&self) -> bool {
        self.sampling == Sampling::Sampled
    }

    /// Reads a `traceparent` header value.
    ///
    /// `None` for anything that is not a usable context, and the caller then
    /// starts a trace. Version 00 is exactly four fields. A later version may
    /// add more, and the spec says to read the ones we know and ignore the
    /// rest.
    #[must_use]
    pub fn parse(traceparent: &str) -> Option<Self> {
        let mut fields = traceparent.trim().split('-');
        let version = decode_hex::<1>(fields.next()?)?[0];
        if version == 0xff {
            return None;
        }

        let trace_id = TraceId::parse(fields.next()?)?;
        let span_id = SpanId::parse(fields.next()?)?;
        let flags = decode_hex::<1>(fields.next()?)?[0];

        if version == SUPPORTED_VERSION && fields.next().is_some() {
            return None;
        }

        Some(Self {
            trace_id,
            span_id,
            sampling: Sampling::from_flags(flags),
        })
    }

    /// The context the proxy passes on, naming `span_id` as the parent.
    ///
    /// The upstream's parent is the proxy's own span, not the caller's. That
    /// puts the gateway hop in the middle of the trace instead of hiding it.
    #[must_use]
    pub fn child(&self, span_id: SpanId) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id,
            sampling: self.sampling,
        }
    }

    /// The `traceparent` header value for this context.
    #[must_use]
    pub fn to_header(&self) -> String {
        let flags = self.sampling.flags();
        format!(
            "{:02x}-{}-{}-{flags:02x}",
            SUPPORTED_VERSION, self.trace_id, self.span_id
        )
    }
}

/// Decodes exactly `N` bytes of lowercase hex.
///
/// The spec says the header is lowercase. Accepting uppercase would give the
/// same id two spellings, and the store that receives them would split the
/// trace in two.
fn decode_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if Some(hex.len()) != N.checked_mul(2)
        || !hex
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }

    let mut bytes = [0u8; N];
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(bytes)
}

/// Writes bytes as lowercase hex.
fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const SPAN: &str = "00f067aa0ba902b7";

    fn sampled_header() -> String {
        format!("00-{TRACE}-{SPAN}-01")
    }

    /// A sampled `traceparent` from a browser is read back with its own trace
    /// id, span id and sampled flag, so the proxy joins that trace.
    #[test]
    fn a_caller_already_tracing_is_joined_rather_than_restarted() {
        let context = TraceContext::parse(&sampled_header()).expect("a usable context");

        assert_eq!(context.trace_id().to_string(), TRACE);
        assert_eq!(context.span_id().to_string(), SPAN);
        assert!(context.is_sampled());
    }

    /// A caller sends a trace with the sampled flag off. The context and the
    /// child the proxy passes on both stay unsampled, so no half trace is
    /// recorded.
    #[test]
    fn an_unsampled_trace_stays_unsampled() {
        let context = TraceContext::parse(&format!("00-{TRACE}-{SPAN}-00")).expect("usable");

        assert!(!context.is_sampled());
        assert!(!context.child(SpanId::parse(SPAN).unwrap()).is_sampled());
    }

    /// The header sent upstream keeps the caller's trace id but names the
    /// proxy's span as the parent. The gateway hop then shows in the trace.
    #[test]
    fn the_upstream_is_told_the_proxys_span_is_its_parent() {
        let inbound = TraceContext::parse(&sampled_header()).expect("usable");
        let proxy_span = SpanId::parse("a1b2c3d4e5f60718").expect("valid span id");

        let outbound = inbound.child(proxy_span);

        assert_eq!(outbound.trace_id(), inbound.trace_id());
        assert_eq!(outbound.span_id(), proxy_span);
        assert_eq!(
            outbound.to_header(),
            format!("00-{TRACE}-a1b2c3d4e5f60718-01")
        );
    }

    /// A parsed header written back out is the same text that arrived.
    #[test]
    fn a_header_survives_the_round_trip() {
        let context = TraceContext::parse(&sampled_header()).expect("usable");

        assert_eq!(context.to_header(), sampled_header());
    }

    /// An empty header, the reserved version `ff`, an all-zero id, a field of
    /// the wrong length and a missing field are all refused. The proxy then
    /// starts its own trace instead of joining one somebody made up.
    #[test]
    fn a_header_that_is_not_a_trace_context_is_refused() {
        for invalid in [
            "",
            "not-a-header",
            &format!("ff-{TRACE}-{SPAN}-01"),
            &format!("00-{}-{SPAN}-01", "0".repeat(32)),
            &format!("00-{TRACE}-{}-01", "0".repeat(16)),
            &format!("00-{}-{SPAN}-01", &TRACE[..30]),
            &format!("00-{TRACE}-{}-01", &SPAN[..14]),
            &format!("00-{TRACE}-{SPAN}"),
        ] {
            assert!(
                TraceContext::parse(invalid).is_none(),
                "accepted {invalid:?} as a trace context"
            );
        }
    }

    /// A trace id in uppercase is refused. The spec says lowercase, and two
    /// spellings of one id would split the trace in the store.
    #[test]
    fn an_uppercase_identifier_is_refused() {
        let shouting = format!("00-{}-{SPAN}-01", TRACE.to_uppercase());

        assert!(TraceContext::parse(&shouting).is_none());
    }

    /// A version 00 header with a fifth field is refused. Version 00 has
    /// exactly four, so the sender used a version it did not declare.
    #[test]
    fn a_version_00_header_with_extra_fields_is_refused() {
        assert!(TraceContext::parse(&format!("00-{TRACE}-{SPAN}-01-extra")).is_none());
    }

    /// A version 01 header with extra fields is read by its first four. The
    /// spec asks for this, so tracing keeps working after a client upgrade.
    #[test]
    fn a_later_version_is_read_rather_than_refused() {
        let future = format!("01-{TRACE}-{SPAN}-01-something-new");

        let context = TraceContext::parse(&future).expect("a later version is still readable");

        assert_eq!(context.trace_id().to_string(), TRACE);
        assert!(context.is_sampled());
    }

    /// A header with spaces before and after it is still read.
    #[test]
    fn surrounding_whitespace_does_not_stop_a_header_being_read() {
        assert!(TraceContext::parse(&format!("  {}  ", sampled_header())).is_some());
    }

    /// All-zero bytes make no trace id and no span id. Any other bytes do.
    #[test]
    fn an_all_zero_identifier_names_nothing() {
        assert!(TraceId::new([0; 16]).is_none());
        assert!(SpanId::new([0; 8]).is_none());
        assert!(TraceId::new([1; 16]).is_some());
        assert!(SpanId::new([1; 8]).is_some());
    }

    /// A trace id and span id parsed from hex give back exactly those bytes
    /// to an exporter. Other bytes would file the span under a trace that
    /// does not exist.
    #[test]
    fn an_identifier_hands_an_exporter_the_bytes_it_was_parsed_from() {
        let trace = TraceId::parse("4bf92f3577b34da6a3ce929d0e0e4736").expect("a trace id");
        let span = SpanId::parse("00f067aa0ba902b7").expect("a span id");

        assert_eq!(
            trace.as_bytes(),
            &[
                0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
                0x47, 0x36
            ]
        );
        assert_eq!(
            span.as_bytes(),
            &[0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]
        );
        assert_eq!(trace.to_string(), "4bf92f3577b34da6a3ce929d0e0e4736");
    }
}
