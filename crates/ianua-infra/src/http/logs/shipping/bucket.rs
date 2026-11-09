//! Writing one batch as one object into an S3-compatible bucket: a
//! path-style `PUT`, signed with AWS Signature Version 4.
//!
//! The credential the tenant gave is the access key's id and its secret,
//! joined by a colon. The body's hash is part of what is signed, so a body
//! changed on the way is refused by the store. The request is signed for
//! the region the tenant named with the destination, never one guessed
//! from the endpoint's host, since only AWS writes its region there.

use ianua_domain::domains::proxy::log_shipping::{BucketName, BucketRegion};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use reqwest::header::HeaderMap;
use time::OffsetDateTime;

use crate::crypto::sigv4::{AccessKey, Payload, Request, Scope, Signing};

/// The service every S3-compatible store signs requests for.
const SERVICE: &str = "s3";

/// The access key `credential` holds, written `ACCESS_KEY_ID:SECRET`.
///
/// # Errors
///
/// Returns `DomainError::Validation` when it is not two parts joined by a
/// colon. The refusal never repeats the credential.
pub(super) fn access_key(credential: &Secret) -> Result<AccessKey<'_>, DomainError> {
    let refused = || {
        DomainError::invalid(message!(
            "infra-a-bucket-credential-is-the-access",
            "a bucket credential is the access key id and its secret, joined by a colon"
        ))
    };
    let (id, secret) = credential.expose().split_once(':').ok_or_else(refused)?;
    if id.is_empty() || secret.is_empty() {
        return Err(refused());
    }
    Ok(AccessKey {
        id,
        secret,
        token: None,
    })
}

/// One object to write: where, what, and when it is signed.
pub(super) struct Upload<'a> {
    /// The object's address, the bucket and key in its path.
    pub(super) url: &'a url::Url,
    /// The region the bucket is signed for.
    pub(super) region: &'a BucketRegion,
    /// The type the body is sent as, which is signed too.
    pub(super) content_type: &'a str,
    /// The object's body.
    pub(super) body: &'a [u8],
    /// When the request is signed.
    pub(super) at: OffsetDateTime,
}

/// The address of a new object in `bucket` at `endpoint`, its key under
/// `ianua/<year>/<month>/<day>/` with a fresh id and `extension`.
pub(super) fn object_url(
    endpoint: &url::Url,
    bucket: &BucketName,
    at: OffsetDateTime,
    extension: &str,
) -> url::Url {
    let mut url = endpoint.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.set_path(&format!(
        "/{}/ianua/{:04}/{:02}/{:02}/{}.{extension}",
        bucket.as_str(),
        at.year(),
        u8::from(at.month()),
        at.day(),
        uuid::Uuid::now_v7().simple()
    ));
    url
}

/// The headers that sign `upload` with `key`: the date, the body's hash
/// and the authorization, the last marked sensitive.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the address names no host, and
/// `DomainError::Infrastructure` when a signature cannot be made.
pub(super) fn signed_headers(
    upload: &Upload<'_>,
    key: &AccessKey<'_>,
) -> Result<HeaderMap, DomainError> {
    let signing = Signing {
        key,
        scope: Scope {
            region: upload.region.as_str(),
            service: SERVICE,
        },
        at: upload.at,
    };
    signing.headers(&Request {
        method: "PUT",
        url: upload.url,
        headers: &[("content-type", upload.content_type)],
        payload: Payload::Bytes(upload.body),
    })
}

#[cfg(test)]
mod tests {
    use reqwest::header::AUTHORIZATION;

    use super::*;
    use crate::crypto::sigv4::hex_sha256;

    /// A bucket credential without a colon returns a validation error that
    /// does not repeat the access key ID.
    #[test]
    fn a_credential_without_a_colon_is_refused_unrepeated() {
        let credential = Secret::new("AKIAONLYTHEID");

        let refused = access_key(&credential).unwrap_err();

        assert!(matches!(refused, DomainError::Validation(_)));
        assert!(!format!("{refused:?} {refused}").contains("AKIAONLYTHEID"));
    }

    /// An object goes under the bucket and the day it was written, with
    /// the format's extension.
    #[test]
    fn an_object_is_keyed_by_bucket_and_day() {
        let endpoint = url::Url::parse("https://s3.eu-central-1.amazonaws.com/?x=1").unwrap();
        let at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

        let url = object_url(
            &endpoint,
            &BucketName::new("acme-logs").unwrap(),
            at,
            "jsonl",
        );

        assert!(url.path().starts_with("/acme-logs/ianua/2023/11/14/"));
        assert!(url.path().ends_with(".jsonl"));
        assert_eq!(url.query(), None);
    }

    /// The signature covers the body's hash and names the key id and the
    /// day's scope, never the secret.
    #[test]
    fn the_signature_names_the_key_and_scope_but_not_the_secret() {
        let credential = Secret::new("AKIDEXAMPLE:topsecret");
        let key = access_key(&credential).unwrap();
        let url =
            url::Url::parse("https://s3.eu-central-1.amazonaws.com/acme-logs/a.jsonl").unwrap();
        let region = BucketRegion::new("eu-central-1").unwrap();
        let upload = Upload {
            url: &url,
            region: &region,
            content_type: "application/x-ndjson",
            body: b"{}\n",
            at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        };

        let headers = signed_headers(&upload, &key).unwrap();

        let authorization = headers.get(AUTHORIZATION).unwrap().to_str().unwrap();
        assert_eq!(headers.get("x-amz-date").unwrap(), "20231114T221320Z");
        assert_eq!(
            headers.get("x-amz-content-sha256").unwrap(),
            hex_sha256(b"{}\n").as_str()
        );
        assert!(authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20231114/eu-central-1/s3/aws4_request"
        ));
        assert!(!authorization.contains("topsecret"));
    }

    /// A Cloudflare bucket request uses the configured `auto` region in its
    /// signature scope.
    #[test]
    fn the_region_is_the_one_the_destination_names() {
        let credential = Secret::new("AKIDEXAMPLE:topsecret");
        let key = access_key(&credential).unwrap();
        let url =
            url::Url::parse("https://acct.r2.cloudflarestorage.com/acme-logs/a.jsonl").unwrap();
        let region = BucketRegion::new("auto").unwrap();
        let upload = Upload {
            url: &url,
            region: &region,
            content_type: "application/x-ndjson",
            body: b"{}\n",
            at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        };

        let headers = signed_headers(&upload, &key).unwrap();

        let authorization = headers.get(AUTHORIZATION).unwrap().to_str().unwrap();
        assert!(authorization.contains("/20231114/auto/s3/aws4_request"));
    }
}
