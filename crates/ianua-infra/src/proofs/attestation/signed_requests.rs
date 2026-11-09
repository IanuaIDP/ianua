//! The parts of a SigV4-signed request the AWS attestor reads before it
//! sends it: the `Authorization` header's scope and signed headers, and
//! the `x-amz-date`.
//!
//! Nothing here checks the signature itself. Only AWS can, holding the
//! role's secret key; these parts decide whether the request is one worth
//! sending.

use std::ops::Range;
use std::str::FromStr;

use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

/// The parts of a SigV4 `Authorization` header the attestor checks.
pub(crate) struct Authorization<'a> {
    /// The day of the credential scope, as `20261026`.
    pub(crate) day: &'a str,
    /// The region the request was signed for.
    pub(crate) region: &'a str,
    /// The service the request was signed for.
    pub(crate) service: &'a str,
    signed_headers: Vec<&'a str>,
}

impl<'a> Authorization<'a> {
    /// The parts of `value`, a SigV4 `Authorization` header, or `None` for
    /// any other scheme or a header missing a part or naming one twice.
    pub(crate) fn read(value: &'a str) -> Option<Self> {
        let fields = value.strip_prefix("AWS4-HMAC-SHA256 ")?;
        let parts: Vec<(&str, &str)> = fields
            .split(',')
            .map(|part| part.trim().split_once('='))
            .collect::<Option<_>>()?;
        let credential = only(&parts, "Credential")?;
        let signed = only(&parts, "SignedHeaders")?;
        let signature = only(&parts, "Signature")?;
        if parts.len() != 3 || signature.is_empty() {
            return None;
        }
        let mut scope = credential.split('/');
        let (Some(_), Some(day), Some(region), Some(service), Some("aws4_request"), None) = (
            scope.next(),
            scope.next(),
            scope.next(),
            scope.next(),
            scope.next(),
            scope.next(),
        ) else {
            return None;
        };
        Some(Self {
            day,
            region,
            service,
            signed_headers: signed.split(';').collect(),
        })
    }

    /// Whether the signature covers the header `name`.
    pub(crate) fn signs(&self, name: &str) -> bool {
        self.signed_headers.contains(&name)
    }
}

/// The one value `parts` give `name`, or `None` when they give none or
/// several.
fn only<'a>(parts: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    let mut found = parts
        .iter()
        .filter(|(part, _)| *part == name)
        .map(|(_, value)| *value);
    let (Some(value), None) = (found.next(), found.next()) else {
        return None;
    };
    Some(value)
}

/// The moment `text`, an `x-amz-date` such as `20261026T101500Z`, names.
pub(crate) fn signed_at(text: &str) -> Option<OffsetDateTime> {
    let (day, rest) = text.split_once('T')?;
    let clock = rest.strip_suffix('Z')?;
    let digits = |part: &str, length: usize| {
        part.len() == length && part.bytes().all(|b| b.is_ascii_digit())
    };
    if !(digits(day, 8) && digits(clock, 6)) {
        return None;
    }
    let month = Month::try_from(number::<u8>(day, 4..6)?).ok()?;
    let date = Date::from_calendar_date(number(day, 0..4)?, month, number(day, 6..8)?).ok()?;
    let time = Time::from_hms(
        number(clock, 0..2)?,
        number(clock, 2..4)?,
        number(clock, 4..6)?,
    )
    .ok()?;
    Some(PrimitiveDateTime::new(date, time).assume_utc())
}

/// The number the digits of `text` in `range` write.
fn number<T: FromStr>(text: &str, range: Range<usize>) -> Option<T> {
    text.get(range)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED: &str = "AWS4-HMAC-SHA256 \
         Credential=ASIAEXAMPLE/20261026/eu-central-1/sts/aws4_request, \
         SignedHeaders=host;x-amz-date;x-ianua-attestation-binding, \
         Signature=0123456789abcdef";

    /// A SigV4 header reads back its scope and the headers it signs.
    #[test]
    fn a_sigv4_header_reads_its_scope_and_signed_headers() {
        let authorization = Authorization::read(SIGNED).unwrap();

        assert_eq!(authorization.day, "20261026");
        assert_eq!(authorization.region, "eu-central-1");
        assert_eq!(authorization.service, "sts");
        assert!(authorization.signs("x-ianua-attestation-binding"));
        assert!(!authorization.signs("x-amz-security-token"));
    }

    /// Unsupported schemes, missing or duplicate parts, malformed scopes and empty signatures
    /// cannot be parsed as SigV4 authorization.
    #[test]
    fn a_header_that_is_not_sigv4_is_not_read() {
        for value in [
            "AWS4-HMAC-SHA512 Credential=A/20261026/eu-central-1/sts/aws4_request, SignedHeaders=host, Signature=ab",
            "AWS4-HMAC-SHA256 Credential=A/20261026/eu-central-1/sts/aws4_request, SignedHeaders=host",
            "AWS4-HMAC-SHA256 Credential=A/20261026/eu-central-1/sts/aws4_request, SignedHeaders=host, SignedHeaders=x, Signature=ab",
            "AWS4-HMAC-SHA256 Credential=A/20261026/eu-central-1/sts, SignedHeaders=host, Signature=ab",
            "AWS4-HMAC-SHA256 Credential=A/20261026/eu-central-1/sts/aws4_request/x, SignedHeaders=host, Signature=ab",
            "AWS4-HMAC-SHA256 Credential=A/20261026/eu-central-1/sts/aws4_request, SignedHeaders=host, Signature=",
        ] {
            assert!(Authorization::read(value).is_none(), "{value}");
        }
    }

    /// An `x-amz-date` reads as the moment it names, in UTC.
    #[test]
    fn an_amz_date_reads_as_its_moment() {
        let moment = signed_at("20261026T101500Z").unwrap();

        assert_eq!(moment.unix_timestamp(), 1_793_009_700);
    }

    /// Incorrect date syntax and impossible calendar dates yield no signing time.
    #[test]
    fn a_malformed_amz_date_is_not_read() {
        for text in [
            "2026-10-26T10:15:00Z",
            "20261026T101500",
            "20261326T101500Z",
            "20261026T251500Z",
            "+0261026T101500Z",
            "",
        ] {
            assert!(signed_at(text).is_none(), "{text}");
        }
    }
}
