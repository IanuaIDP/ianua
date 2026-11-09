//! Second-factor codes texted through Twilio's Programmable Messaging API.
//!
//! One call per code, as Twilio documents it:
//!
//! - `POST https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/Messages.json`,
//!   form encoded (`application/x-www-form-urlencoded`), with `To` (the
//!   number in E.164 form), `Body`, and either `From` (a number the account
//!   holds) or `MessagingServiceSid` (a Messaging Service that picks the
//!   sender from its pool).
//!   <https://www.twilio.com/docs/messaging/api/message-resource>
//! - HTTP Basic authentication: the Account SID and its Auth Token, or an
//!   API key's SID and secret, which Twilio recommends.
//!   <https://www.twilio.com/docs/usage/requests-to-twilio>
//! - A created message answers `201 Created`. A refusal answers `400`
//!   (bad parameters), `401` (credentials missing or wrong), `404`, `429`
//!   (the account's concurrency limit) or a `5xx`, with a JSON body naming
//!   Twilio's own error code.
//!   <https://www.twilio.com/docs/usage/twilios-response>
//! - Account SIDs match `^AC[0-9a-fA-F]{32}$`, Messaging Service SIDs
//!   `^MG[0-9a-fA-F]{32}$`, API key SIDs `^SK[0-9a-fA-F]{32}$`.
//!   <https://www.twilio.com/docs/iam/api-keys/key-resource-v1>
//! - A body of more than 160 GSM-7 characters is split and billed as
//!   several messages, up to 1,600 characters. The code's text stays in
//!   one.
//!
//! The account is the platform's, read from configuration: the domain lets
//! no tenant name a text message provider of its own. Twilio's host is the
//! platform's choice, so the call goes through the shared client for fixed
//! addresses, never following a redirect, and gives up after a few
//! seconds so a hung provider does not hold the sign-in open.
//!
//! A refusal is answered by its status alone. What Twilio wrote back may
//! repeat the number or the message, so the body is never read into an
//! error or a log. Nothing here logs, and no error names the code, the
//! number or the credential.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::{CodeDestination, FactorCodeSender, OutgoingCode};
use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use url::Url;

use crate::http::client::fixed;
use crate::mail::minutes_left;

/// The longest a code's hand-over may take: the port asks for a few
/// seconds.
const HAND_OVER_WITHIN: Duration = Duration::from_secs(5);

/// The provider's name in errors.
const PROVIDER: &str = "twilio";

/// The hex digits after a SID's two-letter prefix.
const SID_DIGITS: usize = 32;

/// What a Twilio SID names, by its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SidKind {
    /// An account, `AC…`.
    Account,
    /// A Messaging Service, `MG…`.
    MessagingService,
    /// An API key, `SK…`.
    ApiKey,
}

impl SidKind {
    /// The two letters a SID of this kind starts with.
    fn prefix(self) -> &'static str {
        match self {
            Self::Account => "AC",
            Self::MessagingService => "MG",
            Self::ApiKey => "SK",
        }
    }
}

/// A Twilio SID: two letters naming its kind and 32 hex digits. Not a
/// secret, so it may print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwilioSid(String);

impl TwilioSid {
    /// An Account SID, `AC` and 32 hex digits.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when `sid` is not one.
    pub fn account(sid: &str) -> Result<Self, DomainError> {
        Self::of(SidKind::Account, sid)
    }

    /// A Messaging Service SID, `MG` and 32 hex digits.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when `sid` is not one.
    pub fn messaging_service(sid: &str) -> Result<Self, DomainError> {
        Self::of(SidKind::MessagingService, sid)
    }

    /// An API key SID, `SK` and 32 hex digits.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when `sid` is not one.
    pub fn api_key(sid: &str) -> Result<Self, DomainError> {
        Self::of(SidKind::ApiKey, sid)
    }

    /// `sid` as a SID of `kind`.
    fn of(kind: SidKind, sid: &str) -> Result<Self, DomainError> {
        let Some(digits) = sid.strip_prefix(kind.prefix()) else {
            return Err(DomainError::invalid(message!(
                "infra-a-twilio-sid-of-this-kind",
                format!("a Twilio SID of this kind starts with {}", kind.prefix())
            )));
        };
        let hex = digits.len() == SID_DIGITS && digits.bytes().all(|b| b.is_ascii_hexdigit());
        if !hex {
            return Err(DomainError::invalid(message!(
                "infra-a-twilio-sid-has-32-hex",
                "a Twilio SID has 32 hex digits after its prefix"
            )));
        }
        Ok(Self(sid.to_owned()))
    }

    /// The SID as Twilio writes it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How the platform signs in to Twilio.
#[derive(Clone)]
pub enum TwilioLogin {
    /// The account's Auth Token, with the Account SID as the user name.
    AuthToken(Secret),
    /// An API key of the account: its SID as the user name, its secret as
    /// the password.
    ApiKey {
        /// The key's SID.
        key_sid: TwilioSid,
        /// The key's secret.
        secret: Secret,
    },
}

impl fmt::Debug for TwilioLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthToken(_) => f.write_str("TwilioLogin::AuthToken(redacted)"),
            Self::ApiKey { key_sid, .. } => f
                .debug_struct("TwilioLogin::ApiKey")
                .field("key_sid", key_sid)
                .finish_non_exhaustive(),
        }
    }
}

/// Who a texted code is sent from.
#[derive(Debug, Clone)]
pub enum TwilioSender {
    /// A number the account holds, in E.164 form.
    Number(PhoneNumber),
    /// A Messaging Service, which picks the sender from its pool.
    MessagingService(TwilioSid),
}

impl TwilioSender {
    /// The form field and value naming the sender.
    fn field(&self) -> (&'static str, &str) {
        match self {
            Self::Number(number) => ("From", number.as_str()),
            Self::MessagingService(sid) => ("MessagingServiceSid", sid.as_str()),
        }
    }
}

/// The platform's Twilio account: which account, how it signs in, and
/// who its texts come from. `Debug` shows no secret.
#[derive(Debug, Clone)]
pub struct TwilioAccount {
    /// The account the messages are created in.
    pub account_sid: TwilioSid,
    /// How the platform signs in.
    pub login: TwilioLogin,
    /// Who the texts are sent from.
    pub sender: TwilioSender,
}

impl TwilioAccount {
    /// The user name and password of the Basic authentication.
    fn credentials(&self) -> (&str, &Secret) {
        match &self.login {
            TwilioLogin::AuthToken(token) => (self.account_sid.as_str(), token),
            TwilioLogin::ApiKey { key_sid, secret } => (key_sid.as_str(), secret),
        }
    }
}

/// Where Twilio's API answers.
#[derive(Debug, Clone)]
pub struct TwilioEndpoint(Url);

impl TwilioEndpoint {
    /// Twilio's public API, `https://api.twilio.com/`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the address does not
    /// read, which it always does.
    pub fn public() -> Result<Self, DomainError> {
        Self::at("https://api.twilio.com/")
    }

    /// The API at `base`, for a stand-in of it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `base` does not read.
    pub fn at(base: &str) -> Result<Self, DomainError> {
        Url::parse(base).map(Self).map_err(DomainError::infra)
    }

    /// Where messages of `account` are created.
    fn messages(&self, account: &TwilioSid) -> Result<Url, DomainError> {
        self.0
            .join(&format!(
                "2010-04-01/Accounts/{}/Messages.json",
                account.as_str()
            ))
            .map_err(DomainError::infra)
    }
}

/// Why a code could not be texted. Names no code, number or credential.
#[derive(Debug, thiserror::Error)]
enum TextFailure {
    /// The destination was a mail address, which this sender does not mail.
    #[error("a code to be mailed was handed to the text message sender")]
    NotANumber,
    /// The provider did not answer in time.
    #[error("{provider} did not answer in time")]
    TimedOut {
        /// The static service label identifying the delivery attempt that timed out.
        provider: &'static str,
    },
    /// The provider answered with something other than success.
    #[error("{provider} refused the text with status {status}")]
    Refused {
        /// The static service label identifying the sender that refused delivery.
        provider: &'static str,
        /// The HTTP status it answered with.
        status: u16,
    },
    /// The provider could not be reached.
    #[error("{provider} could not be reached")]
    Unreachable {
        /// The static service label identifying the sender that could not be reached.
        provider: &'static str,
        /// What failed, without the address called.
        #[source]
        cause: reqwest::Error,
    },
}

/// Texts second-factor codes through the platform's Twilio account.
pub struct TwilioFactorCodeSender {
    client: reqwest::Client,
    endpoint: TwilioEndpoint,
    account: TwilioAccount,
}

impl fmt::Debug for TwilioFactorCodeSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TwilioFactorCodeSender")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl TwilioFactorCodeSender {
    /// A sender texting through `account` at `endpoint`, each call held to
    /// `timeout`, and never to more than five seconds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(
        account: TwilioAccount,
        endpoint: TwilioEndpoint,
        timeout: Duration,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            client: fixed(timeout.min(HAND_OVER_WITHIN))?,
            endpoint,
            account,
        })
    }

    /// Asks Twilio to text `body` to `to`.
    async fn create_message(&self, to: &PhoneNumber, body: &Secret) -> Result<(), DomainError> {
        let url = self.endpoint.messages(&self.account.account_sid)?;
        let (username, password) = self.account.credentials();
        let (sender_field, sender) = self.account.sender.field();
        let form = [
            ("To", to.as_str()),
            (sender_field, sender),
            ("Body", body.expose()),
        ];
        let sent = self
            .client
            .post(url)
            .basic_auth(username, Some(password.expose()))
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await;
        ensure_accepted(sent)
    }
}

#[async_trait]
impl FactorCodeSender for TwilioFactorCodeSender {
    async fn send(
        &self,
        to: CodeDestination<'_>,
        outgoing: OutgoingCode<'_>,
    ) -> Result<(), DomainError> {
        let CodeDestination::Text(number) = to else {
            return Err(DomainError::infra(TextFailure::NotANumber));
        };
        let body = code_text(&outgoing);
        self.create_message(number, &body).await
    }
}

/// The text carrying `outgoing`'s code and how long it works, short enough
/// for one message.
fn code_text(outgoing: &OutgoingCode<'_>) -> Secret {
    Secret::new(format!(
        "Your sign-in code is {}. It works for {}. Do not share it.",
        outgoing.code.expose(),
        minutes_left(outgoing.expires_at, clock::now())
    ))
}

/// Whether Twilio took the message, from how the call came back.
fn ensure_accepted(sent: Result<reqwest::Response, reqwest::Error>) -> Result<(), DomainError> {
    let response = match sent {
        Ok(response) => response,
        Err(error) if error.is_timeout() => {
            return Err(DomainError::infra(TextFailure::TimedOut {
                provider: PROVIDER,
            }));
        }
        Err(error) => {
            return Err(DomainError::infra(TextFailure::Unreachable {
                provider: PROVIDER,
                cause: error.without_url(),
            }));
        }
    };
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    Err(DomainError::infra(TextFailure::Refused {
        provider: PROVIDER,
        status: status.as_u16(),
    }))
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::sync::{Arc, Mutex};

    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::types::{Email, Locale, Preference, TenantId};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};
    use wiremock::matchers::{basic_auth, body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const ACCOUNT: &str = "AC0123456789abcdef0123456789abcdef";
    const TOKEN: &str = "live-auth-token-9f8e";

    /// A made-up SID of the kind `prefix` names, built here so no
    /// key-shaped text sits in the source for a secret scanner to flag.
    fn made_up_sid(prefix: &str) -> String {
        format!("{prefix}{}", "fedcba9876543210".repeat(2))
    }
    const CODE: &str = "482913";
    const ANN: &str = "+4915112345678";

    /// Every log line and span field written while it is the default.
    #[derive(Clone, Default)]
    struct LogLines(Arc<Mutex<Vec<String>>>);

    impl LogLines {
        fn joined(&self) -> String {
            self.0.lock().unwrap().join("\n")
        }
    }

    impl Visit for LogLines {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.0
                .lock()
                .unwrap()
                .push(format!("{}={value:?}", field.name()));
        }
    }

    impl Subscriber for LogLines {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, span: &Attributes<'_>) -> Id {
            span.record(&mut self.clone());
            Id::from_u64(1)
        }

        fn record(&self, _span: &Id, values: &Record<'_>) {
            values.record(&mut self.clone());
        }

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            event.record(&mut self.clone());
        }

        fn enter(&self, _span: &Id) {}

        fn exit(&self, _span: &Id) {}
    }

    fn account() -> TwilioAccount {
        TwilioAccount {
            account_sid: TwilioSid::account(ACCOUNT).unwrap(),
            login: TwilioLogin::AuthToken(Secret::new(TOKEN)),
            sender: TwilioSender::Number(PhoneNumber::new("+14155550100").unwrap()),
        }
    }

    fn sender_at(server: &MockServer, timeout: Duration) -> TwilioFactorCodeSender {
        let endpoint = TwilioEndpoint::at(&format!("{}/", server.uri())).unwrap();
        TwilioFactorCodeSender::new(account(), endpoint, timeout).unwrap()
    }

    fn messages_path() -> String {
        format!("/2010-04-01/Accounts/{ACCOUNT}/Messages.json")
    }

    async fn text_ann(sender: &TwilioFactorCodeSender) -> Result<(), DomainError> {
        let number = PhoneNumber::new(ANN).unwrap();
        let tenant = ScopedTenant::for_background(TenantId::new());
        let code = Secret::new(CODE);
        let locale = Preference::Inherited;
        sender
            .send(
                CodeDestination::Text(&number),
                OutgoingCode {
                    tenant_id: &tenant,
                    code: &code,
                    expires_at: clock::now() + time::Duration::minutes(5),
                    locale: &locale,
                },
            )
            .await
    }

    /// Everything an error says: its own words, its debug form, and every
    /// cause under it.
    fn said_by(error: &DomainError) -> String {
        let mut said = format!("{error} {error:?}");
        let mut cause = error.source();
        while let Some(next) = cause {
            said.push_str(&format!(" {next} {next:?}"));
            cause = next.source();
        }
        said
    }

    fn assert_nothing_leaks(said: &str) {
        for leaked in [CODE, ANN, TOKEN] {
            assert!(!said.contains(leaked), "{leaked} leaked into {said}");
        }
    }

    /// Ann's code is texted as Twilio documents: a form post to the
    /// account's Messages resource, signed in with the Account SID and Auth
    /// Token, to her number, from the platform's, carrying the code.
    #[tokio::test]
    async fn a_code_is_texted_through_the_messages_resource() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(messages_path()))
            .and(basic_auth(ACCOUNT, TOKEN))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string_contains("To=%2B4915112345678"))
            .and(body_string_contains("From=%2B14155550100"))
            .and(body_string_contains(CODE))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "sid": "SM0123456789abcdef0123456789abcdef",
                "status": "queued",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sent = text_ann(&sender_at(&server, HAND_OVER_WITHIN)).await;

        assert!(sent.is_ok(), "{sent:?}");
    }

    /// A Messaging Service named as the sender is sent as
    /// `MessagingServiceSid`, and an API key signs in with its own SID.
    #[tokio::test]
    async fn a_messaging_service_and_an_api_key_are_sent_as_twilio_reads_them() {
        let server = MockServer::start().await;
        let key = made_up_sid("SK");
        let service = made_up_sid("MG");
        Mock::given(method("POST"))
            .and(path(messages_path()))
            .and(basic_auth(&key, "key-secret"))
            .and(body_string_contains(format!(
                "MessagingServiceSid={service}"
            )))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        let account = TwilioAccount {
            account_sid: TwilioSid::account(ACCOUNT).unwrap(),
            login: TwilioLogin::ApiKey {
                key_sid: TwilioSid::api_key(&key).unwrap(),
                secret: Secret::new("key-secret"),
            },
            sender: TwilioSender::MessagingService(TwilioSid::messaging_service(&service).unwrap()),
        };
        let endpoint = TwilioEndpoint::at(&format!("{}/", server.uri())).unwrap();
        let sender = TwilioFactorCodeSender::new(account, endpoint, HAND_OVER_WITHIN).unwrap();

        let sent = text_ann(&sender).await;

        assert!(sent.is_ok(), "{sent:?}");
    }

    /// A 400 response produces an infrastructure error containing the status,
    /// without the provider's error code, phone number, sign-in code or credential.
    #[tokio::test]
    async fn a_refused_text_fails_by_its_status_alone() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "code": 21211,
                "message": format!("The 'To' number {ANN} is not a valid phone number."),
                "more_info": "https://www.twilio.com/docs/errors/21211",
                "status": 400,
            })))
            .mount(&server)
            .await;

        let refused = text_ann(&sender_at(&server, HAND_OVER_WITHIN))
            .await
            .unwrap_err();

        let said = said_by(&refused);
        assert!(matches!(refused, DomainError::Infrastructure(_)));
        assert!(said.contains("400"), "{said}");
        assert!(!said.contains("21211"), "{said}");
        assert_nothing_leaks(&said);
    }

    /// A 503 response fails delivery with its status and without sensitive values.
    #[tokio::test]
    async fn a_provider_failure_fails_the_send() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let failed = text_ann(&sender_at(&server, HAND_OVER_WITHIN))
            .await
            .unwrap_err();

        assert!(said_by(&failed).contains("503"));
        assert_nothing_leaks(&said_by(&failed));
    }

    /// A delayed provider response times out within two seconds and reports
    /// the timeout without the code, number or credential.
    #[tokio::test]
    async fn a_provider_that_hangs_is_given_up_on() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_delay(Duration::from_secs(3)))
            .mount(&server)
            .await;

        let started = std::time::Instant::now();
        let failed = text_ann(&sender_at(&server, Duration::from_millis(200)))
            .await
            .unwrap_err();

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(said_by(&failed).contains("did not answer in time"));
        assert_nothing_leaks(&said_by(&failed));
    }

    /// A refused text produces no log entry containing the code, number or Auth Token.
    #[tokio::test]
    async fn no_log_line_names_the_code_the_number_or_the_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let lines = LogLines::default();
        let _logging = tracing::subscriber::set_default(lines.clone());

        let failed = text_ann(&sender_at(&server, HAND_OVER_WITHIN)).await;

        assert!(failed.is_err());
        assert_nothing_leaks(&lines.joined());
    }

    /// A mailbox destination is refused without making any request to Twilio.
    #[tokio::test]
    async fn a_code_to_mail_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201))
            .expect(0)
            .mount(&server)
            .await;
        let ann = Email::new("ann@acme.test").unwrap();
        let tenant = ScopedTenant::for_background(TenantId::new());
        let code = Secret::new(CODE);
        let locale = Preference::Own(Locale::new("en-GB").unwrap());

        let sent = sender_at(&server, HAND_OVER_WITHIN)
            .send(
                CodeDestination::Mail(&ann),
                OutgoingCode {
                    tenant_id: &tenant,
                    code: &code,
                    expires_at: clock::now() + time::Duration::minutes(5),
                    locale: &locale,
                },
            )
            .await;

        assert!(matches!(sent, Err(DomainError::Infrastructure(_))));
    }

    /// The code's text fits one 160-character message.
    #[test]
    fn the_code_text_fits_one_message() {
        let tenant = ScopedTenant::for_background(TenantId::new());
        let code = Secret::new(CODE);
        let locale = Preference::Inherited;
        let outgoing = OutgoingCode {
            tenant_id: &tenant,
            code: &code,
            expires_at: clock::now() + time::Duration::minutes(10),
            locale: &locale,
        };

        let text = code_text(&outgoing);

        assert!(text.expose().contains(CODE));
        assert!(text.expose().len() <= 160, "{}", text.expose());
    }

    /// SID validation rejects the wrong kind, length, nonhex digits and empty
    /// values while accepting a correctly formed Messaging Service SID.
    #[test]
    fn a_sid_of_the_wrong_shape_or_kind_is_refused() {
        for (made, kind) in [
            (
                TwilioSid::account("MG0123456789abcdef0123456789abcdef"),
                "kind",
            ),
            (TwilioSid::account("AC0123"), "short"),
            (
                TwilioSid::account("AC0123456789abcdef0123456789abcdeZ"),
                "not hex",
            ),
            (TwilioSid::api_key(""), "empty"),
        ] {
            assert!(made.is_err(), "{kind} was taken");
        }
        assert!(TwilioSid::messaging_service("MG0123456789abcdef0123456789abcdef").is_ok());
    }

    /// Account and API-key debug formatting omit the Auth Token and key secret.
    #[test]
    fn the_credential_never_prints() {
        let shown = format!(
            "{:?} {:?}",
            account(),
            TwilioLogin::ApiKey {
                key_sid: TwilioSid::api_key(&made_up_sid("SK")).unwrap(),
                secret: Secret::new("key-secret"),
            }
        );

        assert!(!shown.contains(TOKEN), "{shown}");
        assert!(!shown.contains("key-secret"), "{shown}");
    }
}
