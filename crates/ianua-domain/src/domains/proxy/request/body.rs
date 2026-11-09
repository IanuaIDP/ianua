//! What the proxy read of a request or response body before deciding on it.
//!
//! A stage that looks at a body sees at most a capped prefix of it. So every
//! decision that depends on the body must know whether that prefix is all
//! there is. A stage that did not see the body in full cannot know what the
//! rest holds.
//!
//! How much of a request body the proxy reads before deciding is a question
//! of the pipeline: [`BodyNeed`] answers it, from the stages that read a body
//! and the caps the operator set for each, [`BodyReadSettings`].

use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;

/// A number of bytes a body, or the part of it read, is held to.
///
/// Never zero. A cap of nothing would refuse every body, or read none while
/// a stage waits to see one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteCap(u64);

impl ByteCap {
    /// The smallest cap there is, one byte.
    ///
    /// What a cap that could not be read is taken as: it lets the least
    /// through.
    pub const SMALLEST: Self = Self(1);

    /// A cap of `bytes`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `bytes` is zero.
    pub fn new(bytes: u64) -> Result<Self, DomainError> {
        validate_range("bytes", bytes, 1..=u64::MAX)?;
        Ok(Self(bytes))
    }

    /// The number of bytes.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// What reads a request body before the proxy decides on it.
///
/// Each one needs a prefix of the body, of the size the operator set for
/// it. The rest of the stages decide on the request line and headers alone,
/// so the body streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodyReader {
    /// The WAF stage, scanning the body for attack patterns.
    Waf,
    /// The request signing stage, which signs the body it forwards.
    RequestSign,
    /// The MCP stage, which reads the JSON-RPC envelope to see the tool
    /// called. A call it cannot read whole is refused, so its cap must hold
    /// an envelope.
    Mcp,
    /// The GraphQL stage, which reads the query from the body.
    GraphQl,
    /// The route's parameter rules, which check every body field for an
    /// address no rule covers and refuse a body they could not read.
    ParameterRules,
}

/// How many bytes of a request body each reader reads, and the largest body
/// a pipeline takes when none of its stages sets one.
///
/// The operator's settings for the gateway, read once at start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyReadSettings {
    /// The largest request body taken on a route whose pipeline sets none.
    pub default_limit: ByteCap,
    /// How much of the body the WAF stage scans.
    pub waf: ByteCap,
    /// How much of the body the request signing stage signs.
    pub request_sign: ByteCap,
    /// How much of the body the MCP stage reads.
    pub mcp: ByteCap,
    /// How much of the body the GraphQL stage reads.
    pub graphql: ByteCap,
    /// How much of the body the route's parameter rules read.
    pub parameter_rules: ByteCap,
}

impl BodyReadSettings {
    /// How much of the body `reader` reads.
    #[must_use]
    pub fn cap_for(&self, reader: BodyReader) -> ByteCap {
        match reader {
            BodyReader::Waf => self.waf,
            BodyReader::RequestSign => self.request_sign,
            BodyReader::Mcp => self.mcp,
            BodyReader::GraphQl => self.graphql,
            BodyReader::ParameterRules => self.parameter_rules,
        }
    }
}

/// How much of a request body the proxy reads before it decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyNeed {
    /// Nothing reads the body. It is not read ahead, and streams.
    Nothing,
    /// Up to this many bytes are read once and shared by every reader.
    Prefix(ByteCap),
}

/// Whether the bytes read are the whole body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyExtent {
    /// The body ended before the read cap: the bytes are all of it.
    Whole,
    /// The read stopped at the cap: more of the body followed.
    Prefix,
}

impl BodyExtent {
    /// Whether the bytes read are the whole body.
    #[must_use]
    pub fn is_whole(self) -> bool {
        matches!(self, Self::Whole)
    }
}

/// The part of a body the proxy read, and whether it is all of it.
#[derive(Debug, Clone, Copy)]
pub struct CapturedBody<'a> {
    /// The bytes read, up to the configured cap.
    pub bytes: &'a [u8],
    /// Whether those bytes are the whole body.
    pub extent: BodyExtent,
}

impl<'a> CapturedBody<'a> {
    /// The bytes read and how much of the body they are.
    #[must_use]
    pub fn new(bytes: &'a [u8], extent: BodyExtent) -> Self {
        Self { bytes, extent }
    }

    /// Whether the bytes read are the whole body.
    #[must_use]
    pub fn is_whole(&self) -> bool {
        self.extent.is_whole()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body `{}` read to its end is whole. A body cut off after `{` at the
    /// cap is only a prefix, so no stage may treat it as the full body.
    #[test]
    fn only_a_body_read_to_its_end_is_whole() {
        assert!(CapturedBody::new(b"{}", BodyExtent::Whole).is_whole());
        assert!(!CapturedBody::new(b"{", BodyExtent::Prefix).is_whole());
    }

    /// A cap of 1024 bytes is kept. A cap of zero is refused, since it would
    /// read nothing while a stage waits for the body.
    #[test]
    fn a_byte_cap_is_never_zero() {
        assert_eq!(ByteCap::new(1024).unwrap().get(), 1024);
        assert!(matches!(ByteCap::new(0), Err(DomainError::Validation(_))));
    }

    /// Each reader is given the cap set for it, and none another's.
    #[test]
    fn each_reader_reads_its_own_cap() {
        let cap = |bytes| ByteCap::new(bytes).unwrap();
        let settings = BodyReadSettings {
            default_limit: cap(10),
            waf: cap(1),
            request_sign: cap(2),
            mcp: cap(3),
            graphql: cap(4),
            parameter_rules: cap(5),
        };

        let caps: Vec<u64> = [
            BodyReader::Waf,
            BodyReader::RequestSign,
            BodyReader::Mcp,
            BodyReader::GraphQl,
            BodyReader::ParameterRules,
        ]
        .into_iter()
        .map(|reader| settings.cap_for(reader).get())
        .collect();

        assert_eq!(caps, [1, 2, 3, 4, 5]);
    }
}
