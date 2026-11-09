//! AWS IAM roles: proven by an `sts:GetCallerIdentity` request the workload
//! signed with its role's credentials, as HashiCorp Vault's AWS IAM method
//! proves them.
//!
//! The material is JSON: the `method`, `url`, `headers` and `body` of a
//! request signed with SigV4. The platform never sees the role's secret
//! key. It checks the request, sends it to AWS as it is, and AWS checks the
//! signature and answers with the caller's ARN. The request is taken when:
//!
//! - it is exactly `POST /` with the body
//!   `Action=GetCallerIdentity&Version=2011-06-15`, so it can do nothing
//!   but name its caller;
//! - its URL is `https://sts.amazonaws.com/` or
//!   `https://sts.<region>.amazonaws.com/`, never a host the workload names
//!   freely, and a `Host` header it carries says the same;
//! - it is signed with `AWS4-HMAC-SHA256` for `sts` in that endpoint's
//!   region, and the signed headers include `host`, `x-amz-date` and
//!   `x-ianua-attestation-binding`;
//! - `x-ianua-attestation-binding` is the binding of the platform's nonce
//!   and the key being enrolled, so AWS checked it under the role's
//!   signature and the request was made for this bootstrap and this key;
//! - `x-amz-date` is within five minutes of now;
//! - AWS answers success within the client's time and a bounded body,
//!   naming an assumed role in the commercial partition.
//!
//! The subject is `aws:<account>:role/<role name>`: an assumed-role ARN
//! maps to its role, whatever session name the workload picked. An IAM
//! user, the root user or a federated user is refused: each holds a
//! standing key, which attestation exists to do without.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::agents::{AgentAttestor, AttestationPresentation, EnrolledKey};
use ianua_domain::domains::agents::identity::attestation::{
    AttestationMethod, AttestedIdentity, AttestedSubject,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use reqwest::header::{CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue};
use roxmltree::{Document, Node};
use serde::Deserialize;
use time::OffsetDateTime;
use url::{Host, Url};

use crate::http::client::{body_within, fixed};
use crate::proofs::attestation::binding::AttestationBinding;
use crate::proofs::attestation::signed_requests::{Authorization, signed_at};
use crate::proofs::attestation::{binding_for, material_for, refused};

/// The header that carries the binding, signed with the request.
const BINDING_HEADER: &str = "x-ianua-attestation-binding";

/// The headers the signature must cover.
const SIGNED_HEADERS: [&str; 3] = ["host", "x-amz-date", BINDING_HEADER];

/// The headers a forwarded request may not carry: they steer the
/// connection, not the call.
const CONNECTION_HEADERS: [&str; 8] = [
    "connection",
    "expect",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
];

/// The global STS endpoint's host.
const GLOBAL_HOST: &str = "sts.amazonaws.com";

/// The region requests to the global STS endpoint are signed for.
const GLOBAL_REGION: &str = "us-east-1";

/// The only body a request may carry, as pairs in sorted order.
const GET_CALLER_IDENTITY: [(&str, &str); 2] =
    [("Action", "GetCallerIdentity"), ("Version", "2011-06-15")];

/// How far from now a request may have been signed, either way.
const LONGEST_AGE: time::Duration = time::Duration::minutes(5);

/// The most bytes of AWS's answer read. A caller identity is well under a
/// kilobyte.
const MOST_ANSWER: usize = 16_384;

/// The longest name IAM allows a role.
const LONGEST_ROLE_NAME: usize = 64;

/// The signed request an AWS attestation carries.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresentedRequest {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: String,
}

/// An STS endpoint the allow-list admitted.
struct StsEndpoint {
    url: Url,
    host: String,
    region: String,
}

/// A request checked to be a signed `GetCallerIdentity` for this
/// bootstrap, ready to send.
struct CheckedRequest {
    endpoint: StsEndpoint,
    headers: HeaderMap,
    body: String,
}

/// Who AWS says signed the request.
struct CallerIdentity {
    account: String,
    arn: String,
}

/// Where a checked request is sent.
enum SendTo {
    /// The STS endpoint the request names, which the allow-list admitted.
    NamedEndpoint,
    /// A stand-in for STS, in tests.
    #[cfg(test)]
    StandIn(Url),
}

impl SendTo {
    /// The address a request to `named` goes to.
    fn address(&self, named: &Url) -> Url {
        match self {
            Self::NamedEndpoint => named.clone(),
            #[cfg(test)]
            Self::StandIn(stand_in) => stand_in.clone(),
        }
    }
}

/// The attestor of AWS IAM roles, through the caller identity AWS answers
/// for a request the role signed.
pub struct AwsAgentAttestor {
    client: reqwest::Client,
    send_to: SendTo,
}

impl AwsAgentAttestor {
    /// An attestor asking STS, each call held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(timeout: Duration) -> Result<Self, DomainError> {
        Ok(Self {
            client: fixed(timeout)?,
            send_to: SendTo::NamedEndpoint,
        })
    }

    /// Who AWS says signed `request`, once it answered success.
    async fn caller_of(&self, request: CheckedRequest) -> Result<CallerIdentity, DomainError> {
        let response = self
            .client
            .post(self.send_to.address(&request.endpoint.url))
            .headers(request.headers)
            .body(request.body)
            .send()
            .await
            .map_err(DomainError::infra)?;
        if !response.status().is_success() {
            return Err(refused("AWS refused the signed request"));
        }
        let answer = body_within(response, MOST_ANSWER).await?;
        std::str::from_utf8(&answer)
            .ok()
            .and_then(caller_in)
            .ok_or_else(|| refused("AWS's answer names no caller"))
    }
}

#[async_trait]
impl AgentAttestor for AwsAgentAttestor {
    async fn verify(
        &self,
        presentation: &AttestationPresentation,
        key: &EnrolledKey,
    ) -> Result<AttestedIdentity, DomainError> {
        let material = material_for(presentation, AttestationMethod::AwsIam)?;
        let binding = binding_for(presentation, key)?;
        let request: PresentedRequest = serde_json::from_str(material)
            .map_err(|_| refused("the AWS attestation is not the JSON expected"))?;
        let checked = checked_request(request, &binding, clock::now())?;
        let caller = self.caller_of(checked).await?;
        Ok(AttestedIdentity::new(
            AttestationMethod::AwsIam,
            subject_of(&caller)?,
        ))
    }
}

/// `request`, once it is a `GetCallerIdentity` to an allowed STS endpoint,
/// signed at about `now` over the binding.
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` naming the first rule it breaks.
fn checked_request(
    request: PresentedRequest,
    binding: &AttestationBinding,
    now: OffsetDateTime,
) -> Result<CheckedRequest, DomainError> {
    if request.method != "POST" {
        return Err(refused("the request is not a POST"));
    }
    let endpoint = sts_endpoint(&request.url)?;
    ensure_get_caller_identity(&request.body)?;
    let headers = headers_of(&request.headers, &endpoint)?;
    ensure_signed_for(&headers, &endpoint, binding, now)?;
    Ok(CheckedRequest {
        endpoint,
        headers,
        body: request.body,
    })
}

/// The STS endpoint `text` names, refused unless it is the global one or a
/// regional one, over HTTPS on its own port, at the root.
fn sts_endpoint(text: &str) -> Result<StsEndpoint, DomainError> {
    let not_sts = || refused("the request is not to an STS endpoint");
    let url = Url::parse(text).map_err(|_| not_sts())?;
    let plain = url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    if !plain {
        return Err(not_sts());
    }
    let Some(Host::Domain(host)) = url.host() else {
        return Err(not_sts());
    };
    let Some(region) = region_of(host) else {
        return Err(not_sts());
    };
    Ok(StsEndpoint {
        host: host.to_owned(),
        region: region.to_owned(),
        url,
    })
}

/// The region an STS host serves, or `None` for any other host.
fn region_of(host: &str) -> Option<&str> {
    if host == GLOBAL_HOST {
        return Some(GLOBAL_REGION);
    }
    let region = host.strip_prefix("sts.")?.strip_suffix(".amazonaws.com")?;
    is_region(region).then_some(region)
}

/// Whether `region` reads as an AWS region: lower-case words joined by
/// dashes, at least two, then a number of one or two digits.
fn is_region(region: &str) -> bool {
    let parts: Vec<&str> = region.split('-').collect();
    let Some((number, words)) = parts.split_last() else {
        return false;
    };
    words.len() >= 2
        && words
            .iter()
            .all(|word| !word.is_empty() && word.bytes().all(|b| b.is_ascii_lowercase()))
        && (1..=2).contains(&number.len())
        && number.bytes().all(|b| b.is_ascii_digit())
}

/// Refused unless `body` is exactly `GetCallerIdentity`, in any order of
/// its two pairs.
fn ensure_get_caller_identity(body: &str) -> Result<(), DomainError> {
    let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    pairs.sort();
    let exactly =
        pairs.len() == GET_CALLER_IDENTITY.len()
            && pairs.iter().zip(GET_CALLER_IDENTITY).all(
                |((name, value), (want_name, want_value))| name == want_name && value == want_value,
            );
    if exactly {
        return Ok(());
    }
    Err(refused("the request is not sts:GetCallerIdentity"))
}

/// The headers to send, as `presented` names them, with the endpoint's own
/// `Host`.
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` when a header does not read, is
/// named twice in any case, steers the connection, or names another host.
fn headers_of(
    presented: &BTreeMap<String, String>,
    endpoint: &StsEndpoint,
) -> Result<HeaderMap, DomainError> {
    let unreadable = || refused("a header of the request cannot be read");
    let mut headers = HeaderMap::new();
    for (name, value) in presented {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| unreadable())?;
        let value = HeaderValue::from_str(value).map_err(|_| unreadable())?;
        if CONNECTION_HEADERS
            .iter()
            .any(|steering| *steering == name.as_str())
        {
            return Err(refused("the request carries a connection header"));
        }
        if headers.insert(name, value).is_some() {
            return Err(refused("the request names a header twice"));
        }
    }
    headers.remove(CONTENT_LENGTH);
    let host = HeaderValue::from_str(&endpoint.host).map_err(|_| unreadable())?;
    match headers.insert(HOST, host) {
        Some(named) if named.to_str().ok() != Some(endpoint.host.as_str()) => {
            Err(refused("the request's Host is not its STS endpoint"))
        }
        Some(_) | None => Ok(headers),
    }
}

/// Refused unless `headers` sign the request for `endpoint`'s STS with
/// SigV4, over the host, the date and `binding`, at about `now`.
fn ensure_signed_for(
    headers: &HeaderMap,
    endpoint: &StsEndpoint,
    binding: &AttestationBinding,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    let authorization = text_of(headers, "authorization")
        .and_then(Authorization::read)
        .ok_or_else(|| refused("the request is not signed with SigV4"))?;
    if authorization.service != "sts" || authorization.region != endpoint.region {
        return Err(refused("the request is not signed for its STS endpoint"));
    }
    if !SIGNED_HEADERS.iter().all(|name| authorization.signs(name)) {
        return Err(refused(
            "the request's signature does not cover its host, date and binding",
        ));
    }
    if text_of(headers, BINDING_HEADER) != Some(binding.as_hex()) {
        return Err(refused("the request was not made for this attestation"));
    }
    let date = text_of(headers, "x-amz-date").unwrap_or_default();
    ensure_signed_just_now(date, authorization.day, now)
}

/// Refused unless `date`, an `x-amz-date`, falls on `day` of the
/// signature's scope and within [`LONGEST_AGE`] of `now`.
fn ensure_signed_just_now(date: &str, day: &str, now: OffsetDateTime) -> Result<(), DomainError> {
    let Some(at) = signed_at(date) else {
        return Err(refused("the request names no signing time"));
    };
    let on_its_day = date.starts_with(day) && day.len() == 8;
    let outside = at < now.saturating_sub(LONGEST_AGE) || at > now.saturating_add(LONGEST_AGE);
    if !on_its_day || outside {
        return Err(refused("the request was not signed just now"));
    }
    Ok(())
}

/// The text of the header `name`, when it is there and reads as text.
fn text_of<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers.get(name)?.to_str().ok()
}

/// The caller `answer`, STS's XML, names.
fn caller_in(answer: &str) -> Option<CallerIdentity> {
    let document = Document::parse(answer).ok()?;
    let response = document.root_element();
    if !response.has_tag_name("GetCallerIdentityResponse") {
        return None;
    }
    let result = only_child(response, "GetCallerIdentityResult")?;
    Some(CallerIdentity {
        account: only_child(result, "Account")?.text()?.trim().to_owned(),
        arn: only_child(result, "Arn")?.text()?.trim().to_owned(),
    })
}

/// The one child element of `node` named `name`.
fn only_child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    let mut found = node
        .children()
        .filter(|child| child.is_element() && child.has_tag_name(name));
    let (Some(child), None) = (found.next(), found.next()) else {
        return None;
    };
    Some(child)
}

/// The subject `caller` attests, `aws:<account>:role/<role>`, refused for
/// anything but an assumed role in the commercial partition.
fn subject_of(caller: &CallerIdentity) -> Result<AttestedSubject, DomainError> {
    let Some(role) = role_of(caller) else {
        return Err(refused("the caller is not an assumed IAM role"));
    };
    AttestedSubject::new(format!("aws:{}:role/{role}", caller.account))
        .map_err(|_| refused("the caller names no role"))
}

/// The role `caller`'s ARN assumed, when it is an assumed-role ARN of its
/// own account.
fn role_of(caller: &CallerIdentity) -> Option<&str> {
    let (account, resource) = caller.arn.strip_prefix("arn:aws:sts::")?.split_once(':')?;
    let (role, session) = resource.strip_prefix("assumed-role/")?.split_once('/')?;
    let named = account == caller.account
        && is_account(account)
        && is_role_name(role)
        && !session.is_empty();
    named.then_some(role)
}

/// Whether `account` is an AWS account id: twelve digits.
fn is_account(account: &str) -> bool {
    account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `role` is an IAM role name: letters, digits and `+=,.@_-`.
fn is_role_name(role: &str) -> bool {
    (1..=LONGEST_ROLE_NAME).contains(&role.len())
        && role
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::AttestationProof;
    use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
    use serde_json::{Value, json};
    use wiremock::matchers::{body_string, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::proofs::attestation::tests::enrolled_key;

    const NONCE: &str = "aws-bootstrap-nonce-0123456789abcdef0123";

    const ENDPOINT: &str = "https://sts.eu-central-1.amazonaws.com/";

    const BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";

    /// STS's answer naming `arn` in account 111122223333.
    fn answer(arn: &str) -> String {
        format!(
            "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
             <GetCallerIdentityResult><Arn>{arn}</Arn><UserId>AROAEXAMPLE:session</UserId>\
             <Account>111122223333</Account></GetCallerIdentityResult>\
             <ResponseMetadata><RequestId>01234567</RequestId></ResponseMetadata>\
             </GetCallerIdentityResponse>"
        )
    }

    const ROLE_ARN: &str = "arn:aws:sts::111122223333:assumed-role/agent-runner/i-0abc";

    /// A stand-in for STS answering `status` with `body` to a
    /// `GetCallerIdentity` sent to the regional host.
    async fn sts(status: u16, body: String) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("host", "sts.eu-central-1.amazonaws.com"))
            .and(body_string(BODY))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(&server)
            .await;
        server
    }

    fn attestor(server: &MockServer) -> AwsAgentAttestor {
        AwsAgentAttestor {
            client: fixed(Duration::from_secs(5)).unwrap(),
            send_to: SendTo::StandIn(Url::parse(&format!("{}/", server.uri())).unwrap()),
        }
    }

    /// `at` as an `x-amz-date`.
    fn amz_date(at: OffsetDateTime) -> String {
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            at.year(),
            u8::from(at.month()),
            at.day(),
            at.hour(),
            at.minute(),
            at.second()
        )
    }

    /// The SigV4 header of a request signed on `date`'s day over `signed`.
    fn authorization(date: &str, signed: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/{}/eu-central-1/sts/aws4_request, \
             SignedHeaders={signed}, Signature=0123456789abcdef",
            &date[..8]
        )
    }

    /// A request signed now, carrying `binding`, as a workload makes one.
    fn request(binding: &str) -> Value {
        let date = amz_date(OffsetDateTime::now_utc());
        json!({
            "method": "POST",
            "url": ENDPOINT,
            "headers": {
                "Authorization": authorization(
                    &date,
                    "content-type;host;x-amz-date;x-amz-security-token;x-ianua-attestation-binding",
                ),
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "X-Amz-Date": date,
                "X-Amz-Security-Token": "session-token",
                "X-Ianua-Attestation-Binding": binding,
            },
            "body": BODY,
        })
    }

    fn presented(material: &Value) -> AttestationPresentation {
        AttestationPresentation {
            method: AttestationMethod::AwsIam,
            material: material.to_string(),
            proof: AttestationProof {
                nonce: AttestationNonce::new(NONCE).unwrap(),
                signature: String::new(),
            },
        }
    }

    /// The binding of the test nonce and `key`, in hex.
    fn binding(key: &EnrolledKey) -> String {
        AttestationBinding::of(&AttestationNonce::new(NONCE).unwrap(), &key.public_key)
            .unwrap()
            .as_hex()
            .to_owned()
    }

    async fn verified(
        server: &MockServer,
        material: &Value,
        key: &EnrolledKey,
    ) -> Result<AttestedIdentity, DomainError> {
        attestor(server).verify(&presented(material), key).await
    }

    /// A request the role signed over the binding, which STS answers,
    /// attests the role under its account, whatever its session name.
    #[tokio::test]
    async fn a_signed_caller_identity_attests_its_role() {
        let server = sts(200, answer(ROLE_ARN)).await;
        let key = enrolled_key();

        let attested = verified(&server, &request(&binding(&key)), &key)
            .await
            .unwrap();

        assert_eq!(attested.method(), AttestationMethod::AwsIam);
        assert_eq!(
            attested.subject().as_str(),
            "aws:111122223333:role/agent-runner"
        );
    }

    /// A signed caller-identity request cannot attest a key other than the one in its binding.
    #[tokio::test]
    async fn a_request_made_for_another_key_is_refused() {
        let server = sts(200, answer(ROLE_ARN)).await;
        let workload = enrolled_key();
        let thief = enrolled_key();

        let attested = verified(&server, &request(&binding(&workload)), &thief).await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// Other STS actions, extra parameters, missing versions and GET requests fail validation.
    #[tokio::test]
    async fn another_action_is_refused() {
        let server = sts(200, answer(ROLE_ARN)).await;
        let key = enrolled_key();

        for body in [
            "Action=AssumeRole&Version=2011-06-15&RoleArn=arn",
            "Action=GetCallerIdentity&Version=2011-06-15&Extra=1",
            "Action=GetCallerIdentity",
        ] {
            let mut material = request(&binding(&key));
            material["body"] = json!(body);

            let attested = verified(&server, &material, &key).await;

            assert!(
                matches!(attested, Err(DomainError::Unauthorized(_))),
                "{body}"
            );
        }
        let mut get = request(&binding(&key));
        get["method"] = json!("GET");
        assert!(verified(&server, &get, &key).await.is_err());
    }

    /// Caller-identity requests must use an allowed STS endpoint;
    /// alternate hosts, schemes, ports, credentials, paths and queries are unauthorized.
    #[tokio::test]
    async fn another_host_is_refused() {
        let server = sts(200, answer(ROLE_ARN)).await;
        let key = enrolled_key();

        for url in [
            "https://sts.attacker.example/",
            "https://sts.eu-central-1.amazonaws.com.attacker.example/",
            "https://attacker.example/sts.eu-central-1.amazonaws.com/",
            "http://sts.eu-central-1.amazonaws.com/",
            "https://sts.eu-central-1.amazonaws.com:8443/",
            "https://user@sts.eu-central-1.amazonaws.com/",
            "https://sts.eu-central-1.amazonaws.com/?Action=GetCallerIdentity",
            "https://sts.eu-central-1.amazonaws.com/other",
            "https://sts.Not_A_Region.amazonaws.com/",
            "https://127.0.0.1/",
        ] {
            let mut material = request(&binding(&key));
            material["url"] = json!(url);

            let attested = verified(&server, &material, &key).await;

            assert!(
                matches!(attested, Err(DomainError::Unauthorized(_))),
                "{url}"
            );
        }
    }

    /// A Host header that disagrees with the request URL makes attestation unauthorized.
    #[tokio::test]
    async fn a_host_header_naming_another_host_is_refused() {
        let server = sts(200, answer(ROLE_ARN)).await;
        let key = enrolled_key();
        let mut material = request(&binding(&key));
        material["headers"]["Host"] = json!("sts.us-east-1.amazonaws.com");

        let attested = verified(&server, &material, &key).await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// Missing, unsigned and stale challenge bindings all fail caller-identity attestation.
    #[tokio::test]
    async fn a_missing_unsigned_or_wrong_binding_is_refused() {
        let server = sts(200, answer(ROLE_ARN)).await;
        let key = enrolled_key();
        let mut missing = request(&binding(&key));
        missing["headers"]
            .as_object_mut()
            .unwrap()
            .remove("X-Ianua-Attestation-Binding");
        let mut unsigned = request(&binding(&key));
        let date = unsigned["headers"]["X-Amz-Date"]
            .as_str()
            .unwrap()
            .to_owned();
        unsigned["headers"]["Authorization"] = json!(authorization(&date, "host;x-amz-date"));
        let other_nonce = AttestationBinding::of(
            &AttestationNonce::new("an-earlier-nonce-0123456789abcdef0123").unwrap(),
            &key.public_key,
        )
        .unwrap();
        let wrong = request(other_nonce.as_hex());

        for material in [missing, unsigned, wrong] {
            let attested = verified(&server, &material, &key).await;

            assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
        }
    }

    /// Requests dated twenty minutes in the past or future are outside the accepted signing window.
    #[tokio::test]
    async fn a_stale_or_future_date_is_refused() {
        let server = sts(200, answer(ROLE_ARN)).await;
        let key = enrolled_key();

        for shift in [time::Duration::minutes(-20), time::Duration::minutes(20)] {
            let date = amz_date(OffsetDateTime::now_utc() + shift);
            let mut material = request(&binding(&key));
            material["headers"]["X-Amz-Date"] = json!(date);
            material["headers"]["Authorization"] = json!(authorization(
                &date,
                "host;x-amz-date;x-ianua-attestation-binding"
            ));

            let attested = verified(&server, &material, &key).await;

            assert!(
                matches!(attested, Err(DomainError::Unauthorized(_))),
                "{shift}"
            );
        }
    }

    /// An STS 403 response makes the attestation unauthorized.
    #[tokio::test]
    async fn sts_refusing_the_request_refuses_the_attestation() {
        let server = sts(403, "<ErrorResponse/>".to_owned()).await;
        let key = enrolled_key();

        let attested = verified(&server, &request(&binding(&key)), &key).await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// An STS response exceeding the answer limit makes attestation fail.
    #[tokio::test]
    async fn an_answer_too_large_is_refused() {
        let server = sts(200, answer(&"a".repeat(MOST_ANSWER))).await;
        let key = enrolled_key();

        let attested = verified(&server, &request(&binding(&key)), &key).await;

        assert!(attested.is_err());
    }

    /// Non-role identities, account mismatches, unsupported partitions and malformed role names
    /// cannot authenticate as assumed roles.
    #[tokio::test]
    async fn a_caller_that_is_no_assumed_role_is_refused() {
        let key = enrolled_key();

        for arn in [
            "arn:aws:iam::111122223333:user/alice",
            "arn:aws:iam::111122223333:root",
            "arn:aws:sts::111122223333:federated-user/alice",
            "arn:aws:sts::999988887777:assumed-role/agent-runner/s",
            "arn:aws-us-gov:sts::111122223333:assumed-role/agent-runner/s",
            "arn:aws:sts::111122223333:assumed-role/agent:runner/s",
        ] {
            let server = sts(200, answer(arn)).await;

            let attested = verified(&server, &request(&binding(&key)), &key).await;

            assert!(
                matches!(attested, Err(DomainError::Unauthorized(_))),
                "{arn}"
            );
        }
    }

    /// Case-insensitive duplicate headers and a transfer-encoding header make the request unauthorized.
    #[tokio::test]
    async fn a_doubled_or_connection_header_is_refused() {
        let server = sts(200, answer(ROLE_ARN)).await;
        let key = enrolled_key();
        let mut doubled = request(&binding(&key));
        doubled["headers"]["x-ianua-attestation-binding"] = json!("0".repeat(64));
        let mut steering = request(&binding(&key));
        steering["headers"]["Transfer-Encoding"] = json!("chunked");

        for material in [doubled, steering] {
            let attested = verified(&server, &material, &key).await;

            assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
        }
    }

    /// Only well-formed regions are read from an STS host.
    #[test]
    fn regions_are_read_from_sts_hosts_only() {
        assert_eq!(region_of("sts.amazonaws.com"), Some("us-east-1"));
        assert_eq!(
            region_of("sts.ap-southeast-2.amazonaws.com"),
            Some("ap-southeast-2")
        );
        assert_eq!(
            region_of("sts.us-gov-west-1.amazonaws.com"),
            Some("us-gov-west-1")
        );
        assert_eq!(region_of("sts.eu.amazonaws.com"), None);
        assert_eq!(region_of("sts.eu-central-123.amazonaws.com"), None);
        assert_eq!(region_of("iam.amazonaws.com"), None);
    }
}
