//! One signed call to the object store, and how its answer is read.
//!
//! Every call goes through the fixed client, is signed with the shared
//! signer for the configured region, and waits at most [`CALL_TIMEOUT`]
//! for its answer. A download's body may then take up to
//! [`DOWNLOAD_TIMEOUT`], since a person's export streams at the pace of
//! whoever downloads it. A failure names the status and the store's error
//! code, never the body, the address's query or the key.

use std::time::Duration;

use bytes::Bytes;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use reqwest::header::HeaderMap;
use reqwest::{Method, Response, Url};

use crate::crypto::sigv4::{AccessKey, Payload, Request, Scope, Signing};
use crate::files::objects::documents::error_code;
use crate::files::objects::settings::ObjectStoreSettings;
use crate::http::client::{body_within, fixed};
use crate::reading::xml::plain_word;

/// The longest one call may wait for its answer.
pub(super) const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest a download's body may take to read, once it has begun.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// The service every S3-compatible store signs requests for.
const SERVICE: &str = "s3";

/// The most bytes of an answer read: a page of a listing, a store's
/// error, or the result of a batch.
pub(super) const MOST_ANSWER: usize = 4_194_304;

/// The most bytes of a failure's body read for its code.
const MOST_FAILURE: usize = 16_384;

/// How long a call's body may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reading {
    /// The whole call, body and all, within [`CALL_TIMEOUT`].
    Whole,
    /// A download, whose body may take up to [`DOWNLOAD_TIMEOUT`].
    Streamed,
}

/// One call: its method, the object or the bucket, its query, the
/// headers it signs and sends, and its body.
pub(super) struct Call<'a> {
    /// The method, such as `PUT`.
    pub(super) method: Method,
    /// The object's key, or empty for the bucket itself.
    pub(super) key: &'a str,
    /// The query, each pair escaped when it is written.
    pub(super) query: &'a [(&'a str, &'a str)],
    /// Headers sent and signed besides those the signer adds.
    pub(super) headers: &'a [(&'a str, &'a str)],
    /// The body, hashed into the signature.
    pub(super) body: Bytes,
    /// How long its body may take.
    pub(super) reading: Reading,
}

impl<'a> Call<'a> {
    /// A call of `method` to `key` with `query`, no body and no headers of
    /// its own, read whole.
    pub(super) fn to(method: Method, key: &'a str, query: &'a [(&'a str, &'a str)]) -> Self {
        Self {
            method,
            key,
            query,
            headers: &[],
            body: Bytes::new(),
            reading: Reading::Whole,
        }
    }
}

/// A store's refusal of a call: its status and its error code.
#[derive(Debug, thiserror::Error)]
#[error("the object store answered with status {status} and code {code}")]
pub(super) struct Refused {
    /// The status it answered with.
    pub(super) status: u16,
    /// Its error code when it is a plain word, or `unknown`.
    pub(super) code: String,
}

/// The bucket the files are kept in, and the client it is reached with.
pub(super) struct Bucket {
    http: reqwest::Client,
    settings: ObjectStoreSettings,
}

impl Bucket {
    /// The bucket `settings` names, reached through the fixed client.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub(super) fn new(settings: ObjectStoreSettings) -> Result<Self, DomainError> {
        Ok(Self {
            http: fixed(CALL_TIMEOUT)?,
            settings,
        })
    }

    /// The store's answer to `call`, whatever its status.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the call cannot be signed
    /// or sent, or no answer comes within [`CALL_TIMEOUT`].
    pub(super) async fn send(&self, call: Call<'_>) -> Result<Response, DomainError> {
        let url = self.settings.url_of(call.key, call.query)?;
        let signed = self.signed_headers(&call, &url)?;
        let mut request = self.http.request(call.method, url).headers(signed);
        for (name, value) in call.headers {
            request = request.header(*name, *value);
        }
        if call.reading == Reading::Streamed {
            request = request.timeout(DOWNLOAD_TIMEOUT);
        }
        tokio::time::timeout(CALL_TIMEOUT, request.body(call.body).send())
            .await
            .map_err(|_| DomainError::infra_msg("the object store did not answer in time"))?
            .map_err(|error| DomainError::infra(error.without_url()))
    }

    /// Signs this call's URL, headers and body under the bucket's region and key.
    fn signed_headers(&self, call: &Call<'_>, url: &Url) -> Result<HeaderMap, DomainError> {
        let key = AccessKey {
            id: &self.settings.access_key_id,
            secret: self.settings.secret_access_key.expose(),
            token: None,
        };
        let signing = Signing {
            key: &key,
            scope: Scope {
                region: &self.settings.region,
                service: SERVICE,
            },
            at: clock::now(),
        };
        signing.headers(&Request {
            method: call.method.as_str(),
            url,
            headers: call.headers,
            payload: Payload::Bytes(&call.body),
        })
    }

    /// The store's answer to `call` when it is a success.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the call fails or the
    /// store answers with anything but a success.
    pub(super) async fn succeeded(&self, call: Call<'_>) -> Result<Response, DomainError> {
        let response = self.send(call).await?;
        if response.status().is_success() {
            return Ok(response);
        }
        Err(DomainError::infra(refusal(response).await))
    }
}

impl Refused {
    /// Whether the store refused because what was named is not there, as
    /// `code` says, rather than for any other reason, such as a bucket
    /// that is missing.
    pub(super) fn is_gone(&self, code: &str) -> bool {
        self.status == 404 && self.code == code
    }
}

/// The refusal `response` is, named by its status and the error code its
/// body gives. Nothing else of the body is kept.
pub(super) async fn refusal(response: Response) -> Refused {
    let status = response.status().as_u16();
    let code = body_within(response, MOST_FAILURE)
        .await
        .ok()
        .and_then(|body| String::from_utf8(body).ok())
        .and_then(|text| error_code(&text))
        .unwrap_or_default();
    refused(status, &code)
}

/// The refusal of a call answered with `status` and `code`, the code kept
/// only when it is a plain word.
pub(super) fn refused(status: u16, code: &str) -> Refused {
    Refused {
        status,
        code: plain_word(code).to_owned(),
    }
}

/// Success when `response` is one, or a refusal saying what was named is
/// already gone, as `code` says.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for any other answer.
pub(super) async fn unless_gone(response: Response, code: &str) -> Result<(), DomainError> {
    if response.status().is_success() {
        return Ok(());
    }
    let refused = refusal(response).await;
    if refused.is_gone(code) {
        return Ok(());
    }
    Err(DomainError::infra(refused))
}

/// The body of a successful `response` as text, at most [`MOST_ANSWER`]
/// bytes.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it is longer, cannot be
/// read, or is not text.
pub(super) async fn text_of(response: Response) -> Result<String, DomainError> {
    let body = body_within(response, MOST_ANSWER).await?;
    String::from_utf8(body).map_err(DomainError::infra)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store's code is kept when it is a plain word, and anything else,
    /// which may echo what was sent, is not.
    #[test]
    fn only_a_plain_code_is_kept() {
        assert_eq!(plain_word("NoSuchBucket"), "NoSuchBucket");
        assert_eq!(
            plain_word("Access denied for AKIDEXAMPLE:secret"),
            "unknown"
        );
        assert_eq!(plain_word(""), "unknown");
    }
}
