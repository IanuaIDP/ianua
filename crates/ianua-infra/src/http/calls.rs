//! How one call out ends, read the same way by every adapter: a refused
//! address, a timeout, a failure to connect, or an answer.
//!
//! A refused address is the caller's to fix and reads as a validation
//! error. Everything else is the network's, and either goes into the
//! delivery outcome a port reports or becomes an infrastructure error. An
//! error never carries the URL it was sent to, since a Slack hook or a
//! collector keeps its key in the path.

use std::time::{Duration, Instant};

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::DeliveryOutcome;

use crate::http::client::{LONGEST_CALL, ensure_reachable, refused_by_screen};

/// The refusal of an address that resolves only inside the deployment.
const REFUSED: &str = "the address resolves to one this deployment may not reach";

/// What came of sending one request.
#[derive(Debug)]
pub(crate) enum Sent {
    /// Carries the response for the caller to inspect its status and body.
    Answered(reqwest::Response),
    /// It did not answer in time.
    TimedOut,
    /// It could not be reached.
    Unreachable(reqwest::Error),
}

/// `text` as a URL to call, refused when it names an address `networks`
/// does not permit. A name is screened again when it resolves.
///
/// # Errors
///
/// Returns `DomainError::Validation` when it does not parse, names no host,
/// or names an address the deployment may not reach.
pub(crate) fn reachable(text: &str, networks: &UpstreamNetworks) -> Result<url::Url, DomainError> {
    let url = url::Url::parse(text).map_err(|_| {
        DomainError::invalid(message!(
            "infra-the-address-is-not-a-url",
            "the address is not a URL"
        ))
    })?;
    ensure_reachable(&url, networks)?;
    Ok(url)
}

/// What came of `result`, a request just sent.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the screened client refused the
/// name because it resolves only inside the deployment.
pub(crate) fn sent(result: Result<reqwest::Response, reqwest::Error>) -> Result<Sent, DomainError> {
    let error = match result {
        Ok(response) => return Ok(Sent::Answered(response)),
        Err(error) => error,
    };
    if refused_by_screen(&error) {
        return Err(DomainError::invalid(message!(
            "infra-the-address-resolves-to-one-this",
            REFUSED
        )));
    }
    if error.is_timeout() {
        return Ok(Sent::TimedOut);
    }
    Ok(Sent::Unreachable(error.without_url()))
}

/// The delivery outcome of `result`: the code it answered with, a timeout,
/// or unreachable. The answer's body is never read.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the address resolves only inside
/// the deployment.
pub(crate) fn outcome_of(
    result: Result<reqwest::Response, reqwest::Error>,
) -> Result<DeliveryOutcome, DomainError> {
    Ok(match sent(result)? {
        Sent::Answered(response) => DeliveryOutcome::Answered {
            code: response.status().as_u16(),
        },
        Sent::TimedOut => DeliveryOutcome::TimedOut,
        Sent::Unreachable(_) => DeliveryOutcome::Unreachable,
    })
}

/// The answer to `result` when it is a success, for a port that reports a
/// failed call as an error.
///
/// # Errors
///
/// - `DomainError::Validation` when the address resolves only inside the
///   deployment.
/// - `DomainError::Infrastructure` when it timed out, could not be reached,
///   or answered with anything but a success. The error names the status,
///   never the body.
pub(crate) fn succeeded(
    result: Result<reqwest::Response, reqwest::Error>,
) -> Result<reqwest::Response, DomainError> {
    match sent(result)? {
        Sent::Answered(response) if response.status().is_success() => Ok(response),
        Sent::Answered(response) => Err(DomainError::infra_msg(format!(
            "the endpoint answered with status {}",
            response.status().as_u16()
        ))),
        Sent::TimedOut => Err(DomainError::infra_msg(
            "the endpoint did not answer in time",
        )),
        Sent::Unreachable(error) => Err(DomainError::infra(error)),
    }
}

/// `wanted`, held to the longest any call may take, so no caller can
/// stretch a call past it.
pub(crate) fn bounded(wanted: Duration) -> Duration {
    wanted.min(LONGEST_CALL)
}

/// The whole milliseconds since `started`, the most a `u32` holds when a
/// call somehow took longer.
pub(crate) fn millis_since(started: Instant) -> u32 {
    u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)
}

#[cfg(test)]
pub(crate) mod tests {
    use ianua_domain::types::CidrRange;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::client::screened;

    /// The loopback networks the mock servers listen on, as a self-hosted
    /// deployment would list its own.
    pub(crate) fn loopback() -> UpstreamNetworks {
        UpstreamNetworks::new(vec![
            CidrRange::new("127.0.0.0/8").unwrap(),
            CidrRange::new("::1/128").unwrap(),
        ])
    }

    /// The mock's address at `route` by name, so the request goes through
    /// the screening resolver.
    pub(crate) fn by_name(server: &MockServer, route: &str) -> url::Url {
        url::Url::parse(&format!(
            "{}{route}",
            server.uri().replace("127.0.0.1", "localhost")
        ))
        .unwrap()
    }

    async fn answering(response: ResponseTemplate) -> (MockServer, String) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(response)
            .mount(&server)
            .await;
        let url = by_name(&server, "/").to_string();
        (server, url)
    }

    /// An answer of 503 is an outcome with its code, not an error.
    #[tokio::test]
    async fn an_error_status_is_an_outcome_with_its_code() {
        let (_server, url) = answering(ResponseTemplate::new(503)).await;
        let client = screened(Duration::from_secs(5), loopback()).unwrap();

        let outcome = outcome_of(client.get(url).send().await).unwrap();

        assert_eq!(outcome, DeliveryOutcome::Answered { code: 503 });
    }

    /// An endpoint delayed beyond the client's timeout produces a timed-out
    /// delivery outcome.
    #[tokio::test]
    async fn a_hung_endpoint_reads_as_timed_out() {
        let (_server, url) =
            answering(ResponseTemplate::new(200).set_delay(Duration::from_secs(3))).await;
        let client = screened(Duration::from_millis(200), loopback()).unwrap();

        let outcome = outcome_of(client.get(url).send().await).unwrap();

        assert_eq!(outcome, DeliveryOutcome::TimedOut);
    }

    /// A hostname resolving to disallowed loopback addresses returns a
    /// validation error.
    #[tokio::test]
    async fn a_screened_name_is_refused_as_invalid() {
        let (_server, url) = answering(ResponseTemplate::new(200)).await;
        let client = screened(Duration::from_secs(5), UpstreamNetworks::public_only()).unwrap();

        let result = outcome_of(client.get(url).send().await);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A 403 response produces an error containing the status and excluding
    /// the secret present in both the request path and response body.
    #[tokio::test]
    async fn a_refusal_names_the_status_and_not_the_address() {
        let (_server, url) =
            answering(ResponseTemplate::new(403).set_body_string("token=s3cret")).await;
        let client = screened(Duration::from_secs(5), loopback()).unwrap();

        let error = succeeded(client.get(format!("{url}hook/s3cret")).send().await).unwrap_err();

        let printed = format!("{error:?} {}", ianua_domain::shared::errors::causes(&error));
        assert!(printed.contains("403"), "{printed}");
        assert!(!printed.contains("s3cret"), "{printed}");
    }

    /// Validating a literal metadata address returns a validation error.
    #[test]
    fn an_address_written_out_is_refused_before_a_call() {
        let result = reachable(
            "http://169.254.169.254/latest/meta-data/",
            &UpstreamNetworks::public_only(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
