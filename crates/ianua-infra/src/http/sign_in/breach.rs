//! Whether a password appears in known data breaches, asked of the Have I
//! Been Pwned range service without telling it the password.
//!
//! The password is hashed with SHA-1 here. Only the first five hex
//! characters of the hash are sent; the service answers with every hash
//! suffix it knows under that prefix, padded with made-up ones, and the
//! match is found here. So neither the password nor its full hash leaves
//! the process, and the size of the answer says nothing about it either.
//!
//! The service is the platform's choice, not a tenant's, so it is called
//! through the [`fixed`] client. It is asked at every sign-in and every new
//! password, so a lookup that takes more than two seconds is given up as
//! unavailable, as the port says.

use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::CredentialBreachChecker;
use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use sha1::{Digest as _, Sha1};

use crate::http::calls::succeeded;
use crate::http::client::{body_within, fixed};

/// Where the range service listens.
pub const PWNED_PASSWORDS: &str = "https://api.pwnedpasswords.com";

/// How long one lookup may take before it is given up.
const LOOKUP_TIME: Duration = Duration::from_secs(2);

/// The most an answer may hold. A real one is a few dozen kilobytes, with
/// its padding.
const MOST_ANSWER_BYTES: usize = 1024 * 1024;

/// How many hex characters of the hash leave the process.
const PREFIX_CHARS: usize = 5;

/// Checks passwords against the Have I Been Pwned range service.
#[derive(Debug, Clone)]
pub struct HttpCredentialBreachChecker {
    client: reqwest::Client,
    base: url::Url,
}

impl HttpCredentialBreachChecker {
    /// A checker asking the service at `base`, such as [`PWNED_PASSWORDS`]
    /// or a mirror the deployment runs.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when `base` is not a URL, and
    /// `DomainError::Infrastructure` when the client cannot be built.
    pub fn new(base: &str) -> Result<Self, DomainError> {
        let base = url::Url::parse(base.trim_end_matches('/')).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-breach-service-address-is-not",
                "the breach service address is not a URL"
            ))
        })?;
        Ok(Self {
            client: fixed(LOOKUP_TIME)?,
            base,
        })
    }

    /// The suffixes the service knows under `prefix`, as it answered.
    async fn range(&self, prefix: &str) -> Result<String, DomainError> {
        let url = format!(
            "{}/range/{prefix}",
            self.base.as_str().trim_end_matches('/')
        );
        let response = succeeded(
            self.client
                .get(url)
                .header("Add-Padding", "true")
                .send()
                .await,
        )?;
        let body = body_within(response, MOST_ANSWER_BYTES).await?;
        String::from_utf8(body).map_err(DomainError::infra)
    }
}

#[async_trait]
impl CredentialBreachChecker for HttpCredentialBreachChecker {
    async fn check(&self, raw_password: &Secret) -> Result<BreachStatus, DomainError> {
        let hash = sha1_hex(raw_password);
        let Some((prefix, suffix)) = hash.split_at_checked(PREFIX_CHARS) else {
            return Err(DomainError::infra_msg(
                "a password hash was shorter than its prefix",
            ));
        };
        let answer = self.range(prefix).await?;
        Ok(status_of(&answer, suffix))
    }
}

/// The SHA-1 of the password, in upper-case hex as the service writes it.
fn sha1_hex(password: &Secret) -> String {
    data_encoding::HEXUPPER.encode(&Sha1::digest(password.expose().as_bytes()))
}

/// What `answer`, the service's `SUFFIX:COUNT` lines, says of `suffix`. A
/// padding line counts 0 and reads as no match.
fn status_of(answer: &str, suffix: &str) -> BreachStatus {
    let count = answer
        .lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(listed, _)| listed.eq_ignore_ascii_case(suffix))
        .and_then(|(_, count)| count.trim().parse::<u64>().ok())
        .unwrap_or(0);
    match count {
        0 => BreachStatus::Clean,
        found => BreachStatus::Breached(found),
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// The SHA-1 of `password`, split where the service splits it.
    fn split(password: &str) -> (String, String) {
        let hash = sha1_hex(&Secret::new(password));
        let (prefix, suffix) = hash.split_at(PREFIX_CHARS);
        (prefix.to_owned(), suffix.to_owned())
    }

    async fn service(prefix: &str, response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/range/{prefix}")))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    /// The password `password` hashes to the well-known SHA-1 the service
    /// lists it under.
    #[test]
    fn the_hash_is_upper_case_sha1() {
        assert_eq!(
            sha1_hex(&Secret::new("password")),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    /// A password the service lists 42 times reads as breached 42 times; a
    /// padding line of count 0 among the others changes nothing.
    #[tokio::test]
    async fn a_listed_password_is_breached_with_its_count() {
        let (prefix, suffix) = split("hunter2");
        let answer = format!("0018A45C4D1DEF81644B54AB7F969B88D65:0\n{suffix}:42\n");
        let server = service(&prefix, ResponseTemplate::new(200).set_body_string(answer)).await;
        let checker = HttpCredentialBreachChecker::new(&server.uri()).unwrap();

        let status = checker.check(&Secret::new("hunter2")).await.unwrap();

        assert_eq!(status, BreachStatus::Breached(42));
    }

    /// A password the service does not list, or lists only as padding,
    /// reads as clean.
    #[tokio::test]
    async fn an_unlisted_password_is_clean() {
        let (prefix, suffix) = split("correct horse battery staple");
        let answer = format!("{suffix}:0\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3\n");
        let server = service(&prefix, ResponseTemplate::new(200).set_body_string(answer)).await;
        let checker = HttpCredentialBreachChecker::new(&server.uri()).unwrap();

        let status = checker
            .check(&Secret::new("correct horse battery staple"))
            .await
            .unwrap();

        assert_eq!(status, BreachStatus::Clean);
    }

    /// The breach lookup sends one request naming only the hash prefix;
    /// its URL and body contain neither the password nor the hash suffix.
    #[tokio::test]
    async fn only_the_hash_prefix_leaves() {
        let (prefix, suffix) = split("hunter2");
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("Add-Padding", "true"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let checker = HttpCredentialBreachChecker::new(&server.uri()).unwrap();

        checker.check(&Secret::new("hunter2")).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let sent = format!("{} {:?}", requests[0].url, requests[0].body);
        assert_eq!(requests[0].url.path(), format!("/range/{prefix}"));
        assert!(!sent.contains(&suffix), "{sent}");
        assert!(!sent.contains("hunter2"), "{sent}");
    }

    /// A range response delayed beyond the lookup timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_hung_service_is_an_error_not_a_wait() {
        let (prefix, _) = split("hunter2");
        let server = service(
            &prefix,
            ResponseTemplate::new(200).set_delay(Duration::from_secs(5)),
        )
        .await;
        let checker = HttpCredentialBreachChecker::new(&server.uri()).unwrap();

        let result = checker.check(&Secret::new("hunter2")).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A range response exceeding the byte limit returns an infrastructure
    /// error.
    #[tokio::test]
    async fn an_oversized_answer_is_refused() {
        let (prefix, _) = split("hunter2");
        let body = vec![b'A'; MOST_ANSWER_BYTES + 1];
        let server = service(&prefix, ResponseTemplate::new(200).set_body_bytes(body)).await;
        let checker = HttpCredentialBreachChecker::new(&server.uri()).unwrap();

        let result = checker.check(&Secret::new("hunter2")).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// The range service's HTTP 503 returns an infrastructure error instead
    /// of a password status.
    #[tokio::test]
    async fn a_refusal_is_an_error_not_clean() {
        let (prefix, _) = split("hunter2");
        let server = service(&prefix, ResponseTemplate::new(503)).await;
        let checker = HttpCredentialBreachChecker::new(&server.uri()).unwrap();

        let result = checker.check(&Secret::new("hunter2")).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A range-service redirect returns an infrastructure error, with one
    /// request recorded at the service.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let (prefix, _) = split("hunter2");
        let server = service(
            &prefix,
            ResponseTemplate::new(302).insert_header("location", "https://elsewhere.example/"),
        )
        .await;
        let checker = HttpCredentialBreachChecker::new(&server.uri()).unwrap();

        let result = checker.check(&Secret::new("hunter2")).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
