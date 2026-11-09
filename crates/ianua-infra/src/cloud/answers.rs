//! How a call to a cloud is made and its answer read, the same way for
//! every cloud: each call held to [`CALL`], each whole check to
//! [`OPERATION`], each answer read up to [`MOST`] bytes, and the answer
//! sorted into the customer's refusal or our own failure.
//!
//! An error names the status a cloud answered with, never its body, and a
//! failed send loses its URL, so nothing a cloud echoes and no address
//! reaches an error. An access token is a [`Secret`] from the moment it is
//! read to the sensitive header it is sent in, and the body it came in is
//! wiped.

use std::future::Future;
use std::time::Duration;

use ianua_domain::domains::organization::cloud::account::CloudIdentity;
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudNetwork, DeploymentRegion, NetworkHandle,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Label;
use reqwest::header::HeaderValue;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::crypto::sigv4::sensitive;
use crate::http::client::body_within;

/// The longest name of a network shown to the customer.
const MOST_NAME: usize = 300;

/// The longest one call to a cloud may take.
pub(crate) const CALL: Duration = Duration::from_secs(10);

/// The longest one whole check may take, every call in it together.
pub(crate) const OPERATION: Duration = Duration::from_secs(25);

/// The most pages one listing reads. A cloud that has more is refused
/// rather than listed in part, so a network is never missing without a
/// word; every page together is still held to [`OPERATION`].
pub(crate) const MOST_PAGES: usize = 20;

/// The most bytes of one answer that are read.
pub(crate) const MOST: usize = 2_097_152;

/// The statuses that mean a cloud refused the customer's credential when it
/// is used on an API.
pub(crate) const CREDENTIAL_REFUSED: &[u16] = &[401, 403];

/// The statuses that mean a sign-in endpoint refused the customer's grant:
/// a token endpoint answers a revoked key or a wrong secret with 400.
pub(crate) const GRANT_REFUSED: &[u16] = &[400, 401, 403];

/// What a cloud answered: its status and its body.
pub(crate) struct Reply {
    /// The status code.
    pub(crate) status: u16,
    /// The body, at most [`MOST`] bytes.
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// Whether the cloud answered with a success.
    pub(crate) fn succeeded(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body of a success.
    ///
    /// # Errors
    ///
    /// - `DomainError::Forbidden` with `refusal` when the status is one of
    ///   `refused`.
    /// - `DomainError::Infrastructure` for any other failure.
    pub(crate) fn checked(self, refused: &[u16], refusal: &str) -> Result<Vec<u8>, DomainError> {
        if self.succeeded() {
            return Ok(self.body);
        }
        if refused.contains(&self.status) {
            return Err(DomainError::forbidden(refusal));
        }
        Err(DomainError::infra_msg(format!(
            "the cloud answered with status {}",
            self.status
        )))
    }

    /// The JSON body of a success, read as `T`.
    ///
    /// # Errors
    ///
    /// As [`Self::checked`], and `DomainError::Infrastructure` when the body
    /// is not the JSON expected.
    pub(crate) fn json<T: DeserializeOwned>(
        self,
        refused: &[u16],
        refusal: &str,
    ) -> Result<T, DomainError> {
        let body = self.checked(refused, refusal)?;
        serde_json::from_slice(&body).map_err(DomainError::infra)
    }

    /// The access token a token endpoint's success hands out, held as a
    /// [`Secret`] from the moment it is read; the body it came in is wiped.
    ///
    /// A body that does not read is refused without the parser's error,
    /// which can quote the text it stopped at, and so the token.
    ///
    /// # Errors
    ///
    /// As [`Self::checked`], and `DomainError::Infrastructure` when the body
    /// holds no access token.
    pub(crate) fn access_token(
        self,
        refused: &[u16],
        refusal: &str,
    ) -> Result<Secret, DomainError> {
        let body = Zeroizing::new(self.checked(refused, refusal)?);
        let answer: TokenAnswer = serde_json::from_slice(&body).map_err(|_| {
            DomainError::infra_msg("the token endpoint answered with no access token")
        })?;
        Ok(Secret::new(answer.access_token))
    }
}

/// A token endpoint's answer, read only for its access token.
#[derive(Deserialize)]
struct TokenAnswer {
    access_token: String,
}

/// The `Authorization` header sending `token`, as a [`Secret`] or a
/// customer's cloud secret exposes it, as a bearer: marked sensitive, so the HTTP
/// stack never prints it, and built from text wiped once the header holds
/// it.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure`, naming no part of the token, when
/// the token holds a character a header cannot carry.
pub(crate) fn bearer(token: &str) -> Result<HeaderValue, DomainError> {
    let written = Zeroizing::new(format!("Bearer {token}"));
    sensitive(&written)
}

/// Sends `request` and reads what came back.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the cloud could not be
/// reached, did not answer in time, or answered with a body too long.
pub(crate) async fn reply(request: reqwest::RequestBuilder) -> Result<Reply, DomainError> {
    let response = request.send().await.map_err(unsent)?;
    let status = response.status().as_u16();
    let body = body_within(response, MOST).await?;
    Ok(Reply { status, body })
}

/// The error of a request that got no answer, without its URL.
pub(crate) fn unsent(error: reqwest::Error) -> DomainError {
    if error.is_timeout() {
        return DomainError::infra_msg("the cloud did not answer in time");
    }
    DomainError::infra(error.without_url())
}

/// `work`, given up once [`OPERATION`] has passed.
///
/// # Errors
///
/// Returns what `work` returns, or `DomainError::Infrastructure` when it
/// ran out of time.
pub(crate) async fn within<T>(
    work: impl Future<Output = Result<T, DomainError>>,
) -> Result<T, DomainError> {
    within_time(OPERATION, work).await
}

/// `work`, given up once `limit` has passed.
async fn within_time<T>(
    limit: Duration,
    work: impl Future<Output = Result<T, DomainError>>,
) -> Result<T, DomainError> {
    tokio::time::timeout(limit, work)
        .await
        .map_err(|_| DomainError::infra_msg("the cloud did not answer in time"))?
}

/// A network a cloud reported, under `handle`, named `name`, in `region`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the cloud reported a handle
/// or a name no network can carry.
pub(crate) fn found_network(
    handle: &str,
    name: &str,
    region: DeploymentRegion,
) -> Result<CloudNetwork, DomainError> {
    let handle = NetworkHandle::new(handle).map_err(DomainError::infra)?;
    let name = Label::with_max_length("network", name, MOST_NAME).map_err(DomainError::infra)?;
    Ok(CloudNetwork::new(handle, name, region))
}

/// The identity a cloud reported for the account a credential opened.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it is no identity.
pub(crate) fn found_identity(identity: &str) -> Result<CloudIdentity, DomainError> {
    CloudIdentity::new(identity).map_err(DomainError::infra)
}

/// The refusal of a listing of `cloud` that runs past [`MOST_PAGES`].
pub(crate) fn too_many_pages(cloud: &str) -> DomainError {
    DomainError::infra_msg(format!(
        "{cloud} lists more networks than one look reads; narrow what the credential sees"
    ))
}

/// The refusal of a credential of another cloud, handed to the adapter of
/// `cloud`: a mistake in the wiring, never anything the customer did.
pub(crate) fn another_cloud(cloud: &str) -> DomainError {
    DomainError::invalid(message!(
        "infra-the-adapter-was-handed-a-credential",
        format!("the {cloud} adapter was handed a credential for another cloud")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answered(status: u16, body: &str) -> Reply {
        Reply {
            status,
            body: body.as_bytes().to_vec(),
        }
    }

    /// An HTTP 200 response passes its payload bytes through the credential check.
    #[test]
    fn a_success_hands_back_its_body() {
        let body = answered(200, "{}")
            .checked(CREDENTIAL_REFUSED, "refused")
            .unwrap();

        assert_eq!(body, b"{}");
    }

    /// A 403 is the customer's credential refused, with the reason given.
    #[test]
    fn a_refused_status_is_forbidden() {
        let result = answered(403, "denied").checked(CREDENTIAL_REFUSED, "fix the role");

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A cloud HTTP 500 remains an infrastructure failure rather than a credential rejection.
    #[test]
    fn a_server_failure_is_ours() {
        let result = answered(500, "oops").checked(CREDENTIAL_REFUSED, "fix the role");

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Failure text includes the HTTP status while omitting the response body and its token.
    #[test]
    fn a_failure_names_the_status_and_not_the_body() {
        let error = answered(502, "token=abc123")
            .checked(CREDENTIAL_REFUSED, "fix the role")
            .unwrap_err();

        assert!(!format!("{error:?} {error}").contains("abc123"));
    }

    /// A parsed access token retains its value but has a redacted debug representation.
    #[test]
    fn an_access_token_is_read_as_a_secret() {
        let token = answered(
            200,
            r#"{"access_token": "ya29.live-token", "expires_in": 3599}"#,
        )
        .access_token(GRANT_REFUSED, "fix the key")
        .unwrap();

        assert_eq!(token.expose(), "ya29.live-token");
        assert!(!format!("{token:?}").contains("ya29"));
    }

    /// Malformed token responses produce errors that omit the token-bearing body.
    #[test]
    fn an_unreadable_token_answer_names_no_token() {
        for body in [
            r#"{"access_token": "ya29.live-token""#,
            r#"{"access_token": 7, "id_token": "ya29.live-token"}"#,
            r#"{"token": "ya29.live-token"}"#,
        ] {
            let error = answered(200, body)
                .access_token(GRANT_REFUSED, "fix the key")
                .unwrap_err();

            assert!(matches!(error, DomainError::Infrastructure(_)), "{body}");
            assert!(!format!("{error:?} {error}").contains("ya29"), "{body}");
        }
    }

    /// The bearer header carries the token but marks it sensitive and hides it in debug output.
    #[test]
    fn the_bearer_header_is_sensitive() {
        let header = bearer("ya29.live-token").unwrap();

        assert!(header.is_sensitive());
        assert_eq!(header.as_bytes(), b"Bearer ya29.live-token");
        assert!(!format!("{header:?}").contains("ya29"));
    }

    /// A token containing a line break cannot form a header and is omitted from the error.
    #[test]
    fn a_token_no_header_can_carry_is_refused_without_it() {
        let error = bearer("ya29.live\r\nX-Forged: 1").unwrap_err();

        assert!(!format!("{error:?} {error}").contains("ya29"));
    }

    /// A check that runs out of time is our failure.
    #[tokio::test]
    async fn a_check_past_its_time_is_ours() {
        let result: Result<(), DomainError> = within_time(Duration::from_millis(20), async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(())
        })
        .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }
}
