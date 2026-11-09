//! AWS Signature Version 4, the one signer every call to an AWS-style API
//! is made with: AWS itself (STS, EC2, RDS, SES), and every S3-compatible
//! store.
//!
//! A request is written out in one canonical form (its method, its path,
//! its query sorted, its signed headers in name order, and a hash of its
//! body), hashed, and signed with a key derived from the secret for one
//! day, one region and one service. A signature made for one of them is
//! good for nothing else, and the secret itself never leaves this file.
//!
//! The signature goes into headers, the `Authorization` value and the
//! date beside it ([`Signing::headers`]). A body that is not at hand to
//! hash is signed as [`Payload::Unsigned`]. The headers that carry a
//! credential are marked sensitive, so the client never prints them.
//!
//! A path is written as S3 writes it: each segment decoded and escaped
//! once. Every other service the platform signs for is called on a plain
//! path, where S3's rule and theirs give the same text.

use std::fmt;

use data_encoding::HEXLOWER;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac as _};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, UtcOffset};
use zeroize::Zeroizing;

/// The algorithm every signature here is made with.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The last part of every credential scope.
const TERMINATOR: &str = "aws4_request";

/// What the body hash says when the body is not signed.
pub(crate) const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// What AWS leaves unescaped: letters, digits and `-_.~`.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// A key that could not be used for an HMAC, which never happens: HMAC
/// takes a key of any length.
#[derive(Debug, thiserror::Error)]
#[error("a request signing key could not be used")]
struct UnusableKey;

/// The key a request is signed with: the access key's id, its secret,
/// and the session token a short-lived key comes with.
pub(crate) struct AccessKey<'a> {
    /// The access key's id, which is not secret.
    pub id: &'a str,
    /// The secret access key.
    pub secret: &'a str,
    /// The session token of a short-lived key, sent with each request.
    pub token: Option<&'a str>,
}

/// Shows the id, never the secret or the token.
impl fmt::Debug for AccessKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessKey")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .field("token", &self.token.map(|_| "<redacted>"))
            .finish()
    }
}

/// Where a signature holds: one region and one service.
#[derive(Debug, Clone, Copy)]
pub struct Scope<'a> {
    /// The region, such as `eu-central-1`, or `auto` for a store that has
    /// none.
    pub region: &'a str,
    /// The service, such as `s3` or `sts`.
    pub service: &'a str,
}

/// The body a signature covers.
#[derive(Debug, Clone, Copy)]
pub enum Payload<'a> {
    /// These bytes, hashed into the signature.
    Bytes(&'a [u8]),
    /// A body left out of the signature, such as one streamed while it is
    /// sent.
    Unsigned,
}

impl Payload<'_> {
    /// The body's hash as the canonical request and the
    /// `x-amz-content-sha256` header write it.
    pub fn hash(self) -> String {
        match self {
            Self::Bytes(bytes) => hex_sha256(bytes),
            Self::Unsigned => UNSIGNED_PAYLOAD.to_owned(),
        }
    }
}

/// The parts of a request a signature covers.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The method, such as `PUT`.
    pub method: &'a str,
    /// The URL, whose path and query are covered.
    pub url: &'a url::Url,
    /// The headers signed besides those the signer adds itself, each sent
    /// by the caller with the same value.
    pub headers: &'a [(&'a str, &'a str)],
    /// The body.
    pub payload: Payload<'a>,
}

/// One signing: whose key, for which region and service, and when.
#[derive(Debug)]
pub(crate) struct Signing<'a> {
    /// The key signed with.
    pub key: &'a AccessKey<'a>,
    /// The region and service the signature holds for.
    pub scope: Scope<'a>,
    /// When the request is signed, which the store holds it to.
    pub at: OffsetDateTime,
}

impl Signing<'_> {
    /// The `Authorization` value that signs `request` as it stands: every
    /// header it lists is signed, `host` and the date among them, and
    /// nothing is added.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a key cannot be used,
    /// which never happens for HMAC.
    pub(crate) fn authorization(&self, request: &Request<'_>) -> Result<String, DomainError> {
        let canonical = Canonical::of(request);
        let signature = self.signature(&canonical.text)?;
        Ok(format!(
            "{ALGORITHM} Credential={}/{}, SignedHeaders={}, Signature={signature}",
            self.key.id,
            self.credential_scope(),
            canonical.signed_headers
        ))
    }

    /// The headers that sign `request`: `x-amz-date`,
    /// `x-amz-content-sha256`, the session token when the key has one,
    /// and `Authorization`, the last two marked sensitive. `host` and the
    /// request's own headers are signed too; the client sends those.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the URL names no host, and
    /// `DomainError::Infrastructure` when a value cannot be a header.
    pub(crate) fn headers(&self, request: &Request<'_>) -> Result<HeaderMap, DomainError> {
        let host = host_of(request.url)?;
        let date = amz_date(self.at);
        let content = request.payload.hash();
        let mut signed: Vec<(&str, &str)> = request.headers.to_vec();
        signed.extend([
            ("host", host.as_str()),
            ("x-amz-date", date.as_str()),
            ("x-amz-content-sha256", content.as_str()),
        ]);
        signed.extend(self.key.token.map(|token| ("x-amz-security-token", token)));
        let authorization = self.authorization(&Request {
            headers: &signed,
            ..*request
        })?;
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-date", plain(&date)?);
        headers.insert("x-amz-content-sha256", plain(&content)?);
        if let Some(token) = self.key.token {
            headers.insert("x-amz-security-token", sensitive(token)?);
        }
        headers.insert(AUTHORIZATION, sensitive(&authorization)?);
        Ok(headers)
    }

    /// The day, region and service the signature holds for, as the
    /// credential names them.
    fn credential_scope(&self) -> String {
        [
            day(self.at).as_str(),
            self.scope.region,
            self.scope.service,
            TERMINATOR,
        ]
        .join("/")
    }

    /// The signature over `canonical`, a request in its canonical form.
    fn signature(&self, canonical: &str) -> Result<String, DomainError> {
        let to_sign = [
            ALGORITHM,
            amz_date(self.at).as_str(),
            self.credential_scope().as_str(),
            hex_sha256(canonical.as_bytes()).as_str(),
        ]
        .join("\n");
        let key = signing_key(self.key.secret, &day(self.at), self.scope)?;
        Ok(HEXLOWER.encode(&mac(&key, to_sign.as_bytes())?))
    }
}

/// A request in its canonical form, and the names of its signed headers.
struct Canonical {
    text: String,
    signed_headers: String,
}

impl Canonical {
    /// The canonical form of `request`.
    fn of(request: &Request<'_>) -> Self {
        let mut headers: Vec<(String, String)> = request
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), collapsed(value)))
            .collect();
        headers.sort();
        let listed: String = headers
            .iter()
            .map(|(name, value)| format!("{name}:{value}\n"))
            .collect();
        let signed_headers = headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let text = [
            request.method,
            canonical_path(request.url).as_str(),
            canonical_query(request.url).as_str(),
            listed.as_str(),
            signed_headers.as_str(),
            request.payload.hash().as_str(),
        ]
        .join("\n");
        Self {
            text,
            signed_headers,
        }
    }
}

/// `value` trimmed, each run of spaces inside it made one.
fn collapsed(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The path of `url`, each segment decoded and escaped once, as S3 signs
/// it.
fn canonical_path(url: &url::Url) -> String {
    url.path()
        .split('/')
        .map(|segment| escaped(&percent_decode_str(segment).decode_utf8_lossy()))
        .collect::<Vec<_>>()
        .join("/")
}

/// The query of `url`, each name and value escaped as AWS escapes them,
/// sorted. A name with no value is written with an empty one.
fn canonical_query(url: &url::Url) -> String {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| (escaped(&name), escaped(&value)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// `text` escaped as AWS escapes a path segment, a query name or a value:
/// everything but letters, digits and `-_.~`.
pub fn escaped(text: &str) -> String {
    utf8_percent_encode(text, UNRESERVED).to_string()
}

/// `at` as `x-amz-date` writes it, in UTC: `20150830T123600Z`.
pub(crate) fn amz_date(at: OffsetDateTime) -> String {
    let utc = at.to_offset(UtcOffset::UTC);
    format!(
        "{}T{:02}{:02}{:02}Z",
        day(utc),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// The day of `at` in UTC, as a credential scope names it: `20150830`.
fn day(at: OffsetDateTime) -> String {
    let utc = at.to_offset(UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}",
        utc.year(),
        u8::from(utc.month()),
        utc.day()
    )
}

/// The `host` header the client sends for `url`: the host, and the port
/// when it is not the scheme's own.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the URL names no host.
pub fn host_of(url: &url::Url) -> Result<String, DomainError> {
    let Some(host) = url.host_str() else {
        return Err(DomainError::invalid(message!(
            "infra-the-address-names-no-host",
            "the address names no host"
        )));
    };
    let Some(port) = url.port() else {
        return Ok(host.to_owned());
    };
    Ok(format!("{host}:{port}"))
}

/// The lower-case hex SHA-256 of `data`.
pub(crate) fn hex_sha256(data: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(data))
}

/// The key derived from `secret` for `day` and `scope`.
fn signing_key(
    secret: &str,
    day: &str,
    scope: Scope<'_>,
) -> Result<Zeroizing<Vec<u8>>, DomainError> {
    let opened = Zeroizing::new(["AWS4", secret].concat());
    let dated = Zeroizing::new(mac(opened.as_bytes(), day.as_bytes())?);
    let regional = Zeroizing::new(mac(&dated, scope.region.as_bytes())?);
    let service = Zeroizing::new(mac(&regional, scope.service.as_bytes())?);
    Ok(Zeroizing::new(mac(&service, TERMINATOR.as_bytes())?))
}

/// The HMAC-SHA256 of `data` under `key`.
fn mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, DomainError> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|_| DomainError::infra(UnusableKey))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// `value` as a plain header value.
fn plain(value: &str) -> Result<HeaderValue, DomainError> {
    HeaderValue::from_str(value).map_err(DomainError::infra)
}

/// `value` as a header value marked sensitive, so the client never prints
/// it.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be a header value.
/// The refusal never repeats it.
pub fn sensitive(value: &str) -> Result<HeaderValue, DomainError> {
    let mut header = HeaderValue::from_str(value)
        .map_err(|_| DomainError::infra_msg("a credential cannot be sent as a header"))?;
    header.set_sensitive(true);
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example secret of AWS's signature test suite and IAM's example.
    const SUITE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    /// The example secret of S3's own signing examples.
    const S3_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    /// The hash of an empty body.
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn suite_key() -> AccessKey<'static> {
        AccessKey {
            id: "AKIDEXAMPLE",
            secret: SUITE_SECRET,
            token: None,
        }
    }

    fn s3_key() -> AccessKey<'static> {
        AccessKey {
            id: "AKIAIOSFODNN7EXAMPLE",
            secret: S3_SECRET,
            token: None,
        }
    }

    /// 30 August 2015 at 12:36 UTC, when the test suite signs.
    fn suite_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_440_938_160).unwrap()
    }

    /// 24 May 2013 at midnight UTC, when S3's examples sign.
    fn s3_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_369_353_600).unwrap()
    }

    fn suite_signing<'a>(key: &'a AccessKey<'a>, service: &'a str) -> Signing<'a> {
        Signing {
            key,
            scope: Scope {
                region: "us-east-1",
                service,
            },
            at: suite_time(),
        }
    }

    fn s3_signing<'a>(key: &'a AccessKey<'a>) -> Signing<'a> {
        Signing {
            key,
            scope: Scope {
                region: "us-east-1",
                service: "s3",
            },
            at: s3_time(),
        }
    }

    fn url(text: &str) -> url::Url {
        url::Url::parse(text).unwrap()
    }

    fn suite_get(url: &url::Url) -> String {
        let key = suite_key();
        let headers = [
            ("host", "example.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ];
        suite_signing(&key, "service")
            .authorization(&Request {
                method: "GET",
                url,
                headers: &headers,
                payload: Payload::Bytes(b""),
            })
            .unwrap()
    }

    fn signature_of(authorization: &str) -> &str {
        authorization.rsplit("Signature=").next().unwrap()
    }

    fn s3_authorization(headers: &HeaderMap) -> String {
        headers
            .get(AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    /// The signing key AWS derives in its documented example, for IAM in
    /// `us-east-1` on 15 February 2012, comes out the same.
    #[test]
    fn the_signing_key_matches_the_documented_example() {
        let scope = Scope {
            region: "us-east-1",
            service: "iam",
        };

        let key = signing_key(SUITE_SECRET, "20120215", scope).unwrap();

        assert_eq!(
            HEXLOWER.encode(&key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    /// The test suite's plain GET signs to the signature it publishes.
    #[test]
    fn a_plain_get_signs_as_the_test_suite_says() {
        let header = suite_get(&url("https://example.amazonaws.com/"));

        assert_eq!(
            header,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    /// The test suite's GET with its query out of order signs as it
    /// publishes, so the query is sorted before it is signed.
    #[test]
    fn a_query_is_sorted_as_the_test_suite_says() {
        let header = suite_get(&url(
            "https://example.amazonaws.com/?Param2=value2&Param1=value1",
        ));

        assert_eq!(
            signature_of(&header),
            "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        );
    }

    /// The test suite's headers with spaces around and inside their values
    /// sign as it publishes, so values are trimmed and their runs of
    /// spaces made one.
    #[test]
    fn header_values_are_trimmed_as_the_test_suite_says() {
        let key = suite_key();
        let url = url("https://example.amazonaws.com/");
        let headers = [
            ("host", "example.amazonaws.com"),
            ("My-Header1", " value1"),
            ("My-Header2", " \"a   b   c\""),
            ("x-amz-date", "20150830T123600Z"),
        ];

        let header = suite_signing(&key, "service")
            .authorization(&Request {
                method: "GET",
                url: &url,
                headers: &headers,
                payload: Payload::Bytes(b""),
            })
            .unwrap();

        assert!(header.contains("SignedHeaders=host;my-header1;my-header2;x-amz-date,"));
        assert_eq!(
            signature_of(&header),
            "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736"
        );
    }

    /// IAM's worked example, `ListUsers`, has the canonical request and the
    /// signature AWS publishes for it, its headers given in any order and
    /// case.
    #[test]
    fn the_iam_example_signs_as_aws_publishes() {
        let key = suite_key();
        let url = url("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08");
        let headers = [
            ("Host", "iam.amazonaws.com"),
            (
                "Content-Type",
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
            ("X-Amz-Date", "20150830T123600Z"),
        ];
        let request = Request {
            method: "GET",
            url: &url,
            headers: &headers,
            payload: Payload::Bytes(b""),
        };

        let canonical = Canonical::of(&request);
        let header = suite_signing(&key, "iam").authorization(&request).unwrap();

        assert_eq!(
            hex_sha256(canonical.text.as_bytes()),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        assert_eq!(
            header,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    /// S3's example GET of part of an object signs as S3 publishes, the
    /// date, the body hash and the host added by the signer.
    #[test]
    fn s3s_get_object_example_signs_as_published() {
        let key = s3_key();
        let url = url("https://examplebucket.s3.amazonaws.com/test.txt");

        let headers = s3_signing(&key)
            .headers(&Request {
                method: "GET",
                url: &url,
                headers: &[("range", "bytes=0-9")],
                payload: Payload::Bytes(b""),
            })
            .unwrap();

        assert_eq!(headers.get("x-amz-date").unwrap(), "20130524T000000Z");
        assert_eq!(headers.get("x-amz-content-sha256").unwrap(), EMPTY);
        assert_eq!(
            s3_authorization(&headers),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// S3's example PUT signs as S3 publishes, its body hashed and the `$`
    /// in its key escaped in the canonical path.
    #[test]
    fn s3s_put_object_example_signs_as_published() {
        let key = s3_key();
        let url = url("https://examplebucket.s3.amazonaws.com/test$file.text");

        let headers = s3_signing(&key)
            .headers(&Request {
                method: "PUT",
                url: &url,
                headers: &[
                    ("date", "Fri, 24 May 2013 00:00:00 GMT"),
                    ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                ],
                payload: Payload::Bytes(b"Welcome to Amazon S3."),
            })
            .unwrap();

        assert_eq!(
            headers.get("x-amz-content-sha256").unwrap(),
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        assert_eq!(
            signature_of(&s3_authorization(&headers)),
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    /// S3's example of a query name with no value, `?lifecycle`, signs as
    /// S3 publishes.
    #[test]
    fn a_query_name_without_a_value_signs_as_published() {
        let key = s3_key();
        let url = url("https://examplebucket.s3.amazonaws.com/?lifecycle");

        let headers = s3_signing(&key)
            .headers(&Request {
                method: "GET",
                url: &url,
                headers: &[],
                payload: Payload::Bytes(b""),
            })
            .unwrap();

        assert_eq!(
            signature_of(&s3_authorization(&headers)),
            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
    }

    /// S3's example listing, `?max-keys=2&prefix=J`, signs as S3
    /// publishes.
    #[test]
    fn s3s_listing_example_signs_as_published() {
        let key = s3_key();
        let url = url("https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J");

        let headers = s3_signing(&key)
            .headers(&Request {
                method: "GET",
                url: &url,
                headers: &[],
                payload: Payload::Bytes(b""),
            })
            .unwrap();

        assert_eq!(
            signature_of(&s3_authorization(&headers)),
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }

    /// A body left unsigned is named so in its hash header and in the
    /// canonical request.
    #[test]
    fn an_unsigned_body_is_named_so() {
        let key = s3_key();
        let url = url("https://examplebucket.s3.amazonaws.com/big.bin");

        let headers = s3_signing(&key)
            .headers(&Request {
                method: "PUT",
                url: &url,
                headers: &[],
                payload: Payload::Unsigned,
            })
            .unwrap();

        assert_eq!(
            headers.get("x-amz-content-sha256").unwrap(),
            UNSIGNED_PAYLOAD
        );
    }

    /// Authorization and session-token headers are marked sensitive, the token header
    /// is covered by the signature, and no header contains the signing secret.
    #[test]
    fn credentials_are_sensitive_and_the_secret_is_never_sent() {
        let key = AccessKey {
            id: "ASIASESSION",
            secret: S3_SECRET,
            token: Some("session-token"),
        };
        let url = url("https://examplebucket.s3.amazonaws.com/test.txt");

        let headers = s3_signing(&key)
            .headers(&Request {
                method: "GET",
                url: &url,
                headers: &[],
                payload: Payload::Bytes(b""),
            })
            .unwrap();

        assert!(headers.get(AUTHORIZATION).unwrap().is_sensitive());
        assert!(headers.get("x-amz-security-token").unwrap().is_sensitive());
        assert!(s3_authorization(&headers).contains("x-amz-security-token"));
        for value in headers.values() {
            assert!(!value.to_str().unwrap().contains(S3_SECRET));
        }
    }

    /// An access key's debug output includes its ID while omitting its secret and session token.
    #[test]
    fn a_key_shows_only_its_id() {
        let key = AccessKey {
            id: "AKIDEXAMPLE",
            secret: SUITE_SECRET,
            token: Some("session-token"),
        };

        let shown = format!("{key:?}");

        assert!(shown.contains("AKIDEXAMPLE"));
        assert!(!shown.contains(SUITE_SECRET));
        assert!(!shown.contains("session-token"));
    }

    /// A moment in another offset is written as the date and day in UTC.
    #[test]
    fn a_moment_is_written_in_utc() {
        let at = suite_time().to_offset(UtcOffset::from_hms(2, 0, 0).unwrap());

        assert_eq!(amz_date(at), "20150830T123600Z");
        assert_eq!(day(at), "20150830");
    }

    /// A value is escaped as AWS escapes it: a space as `%20`, a slash and
    /// a plus too, and `-_.~` left as they are.
    #[test]
    fn values_are_escaped_as_aws_escapes_them() {
        assert_eq!(escaped("a b/c+d-_.~"), "a%20b%2Fc%2Bd-_.~");
    }

    /// A port that is not the scheme's own is part of the host, as the
    /// client sends it.
    #[test]
    fn a_port_is_part_of_the_host() {
        assert_eq!(
            host_of(&url("http://127.0.0.1:9000/")).unwrap(),
            "127.0.0.1:9000"
        );
        assert_eq!(
            host_of(&url("https://s3.amazonaws.com:443/")).unwrap(),
            "s3.amazonaws.com"
        );
    }
}
