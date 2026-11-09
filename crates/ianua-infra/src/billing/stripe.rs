//! The payment provider: Stripe, over its HTTP API.
//!
//! A checkout is a Stripe Checkout session in setup mode, so the member
//! saves a card or a mandate and nothing is charged. The organization's id
//! goes into the session's and the setup intent's metadata, and comes back
//! in the event that reports the saved method; the invoices the platform
//! raises carry it the same way. A notice is read only after its signature
//! verifies against the endpoint's signing secret and its moment is fresh.
//!
//! Every call goes to Stripe's address, which the platform chose, through
//! the fixed client: no redirects, a timeout, and a bounded answer. The
//! API version is pinned, so an account upgraded at Stripe's end never
//! changes what is read.

mod notices;
mod signature;

use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::organization::{
    CheckoutRequest, PaymentProvider, PaymentWebhook, ReceivedNotice,
};
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::HttpsUrl;
use serde::Deserialize;
use url::Url;

use self::notices::{ORGANIZATION_KEY, notice_of};
use self::signature::ensure_signed;
use crate::http::client::{body_within, fixed};

/// Where Stripe's API listens.
pub const STRIPE_API: &str = "https://api.stripe.com";

/// The Stripe API version every call and every event is read in.
const API_VERSION: &str = "2024-06-20";

/// The longest answer read from Stripe, in bytes.
const LONGEST_ANSWER: usize = 64 * 1024;

/// How the platform reaches Stripe and where it sends members back to.
pub struct StripeSettings {
    /// Stripe's API, `https://api.stripe.com` outside tests.
    pub api: Url,
    /// The platform's secret API key.
    pub api_key: Secret,
    /// The signing secret of the endpoint Stripe posts events to.
    pub webhook_secret: Secret,
    /// Where a member lands after saving a payment method.
    pub success_url: HttpsUrl,
    /// Where a member lands after leaving the checkout.
    pub cancel_url: HttpsUrl,
    /// The currency the organization is charged in, as Stripe writes it,
    /// such as `eur`; it decides which payment methods the checkout offers.
    pub currency: String,
    /// How long one call to Stripe may take.
    pub timeout: Duration,
}

impl std::fmt::Debug for StripeSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StripeSettings")
            .field("api", &self.api.as_str())
            .field("api_key", &"<redacted>")
            .field("webhook_secret", &"<redacted>")
            .field("success_url", &self.success_url.as_str())
            .field("cancel_url", &self.cancel_url.as_str())
            .field("currency", &self.currency)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// The payment provider over Stripe's API.
pub struct StripePaymentProvider {
    settings: StripeSettings,
    client: reqwest::Client,
}

impl std::fmt::Debug for StripePaymentProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StripePaymentProvider")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// The part of a checkout session read back: the page to send the member
/// to.
#[derive(Deserialize)]
struct Session {
    url: Option<String>,
}

impl StripePaymentProvider {
    /// A provider reaching Stripe as `settings` say.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when the currency is not three lower
    ///   case letters.
    /// - `DomainError::Infrastructure` when the client cannot be built.
    pub fn new(settings: StripeSettings) -> Result<Self, DomainError> {
        let well_formed = settings.currency.len() == 3
            && settings
                .currency
                .bytes()
                .all(|byte| byte.is_ascii_lowercase());
        if !well_formed {
            return Err(DomainError::invalid(message!(
                "infra-a-currency-is-three-lower-case",
                "a currency is three lower case letters, such as eur"
            )));
        }
        let client = fixed(settings.timeout)?;
        Ok(Self { settings, client })
    }

    /// The address of Stripe's checkout sessions.
    fn sessions_address(&self) -> Result<Url, DomainError> {
        self.settings
            .api
            .join("v1/checkout/sessions")
            .map_err(DomainError::infra)
    }

    /// The form a setup-mode checkout for `request` is opened with.
    fn checkout_form(&self, request: &CheckoutRequest) -> Vec<(String, String)> {
        let organization = request.organization_id.as_uuid().to_string();
        vec![
            ("mode".to_owned(), "setup".to_owned()),
            ("currency".to_owned(), self.settings.currency.clone()),
            ("customer_creation".to_owned(), "always".to_owned()),
            (
                "customer_email".to_owned(),
                request.billing_email.as_str().to_owned(),
            ),
            ("client_reference_id".to_owned(), organization.clone()),
            (
                format!("metadata[{ORGANIZATION_KEY}]"),
                organization.clone(),
            ),
            (
                format!("setup_intent_data[metadata][{ORGANIZATION_KEY}]"),
                organization,
            ),
            (
                "success_url".to_owned(),
                self.settings.success_url.as_str().to_owned(),
            ),
            (
                "cancel_url".to_owned(),
                self.settings.cancel_url.as_str().to_owned(),
            ),
        ]
    }
}

/// The checkout page an answer from Stripe names.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when Stripe refused, or answered
/// with no page or with one that is not an HTTPS address.
async fn checkout_page(response: reqwest::Response) -> Result<HttpsUrl, DomainError> {
    let status = response.status();
    if !status.is_success() {
        return Err(DomainError::infra_msg(format!(
            "Stripe refused to open a checkout, with status {}",
            status.as_u16()
        )));
    }
    let body = body_within(response, LONGEST_ANSWER).await?;
    let session: Session = serde_json::from_slice(&body).map_err(DomainError::infra)?;
    let Some(page) = session.url else {
        return Err(DomainError::infra_msg(
            "Stripe opened a checkout with no page",
        ));
    };
    HttpsUrl::new(page).map_err(DomainError::infra)
}

#[async_trait]
impl PaymentProvider for StripePaymentProvider {
    async fn start_checkout(&self, request: &CheckoutRequest) -> Result<HttpsUrl, DomainError> {
        let response = self
            .client
            .post(self.sessions_address()?)
            .bearer_auth(self.settings.api_key.expose())
            .header("Stripe-Version", API_VERSION)
            .form(&self.checkout_form(request))
            .send()
            .await
            .map_err(DomainError::infra)?;
        checkout_page(response).await
    }

    fn read_notice(&self, webhook: &PaymentWebhook) -> Result<ReceivedNotice, DomainError> {
        ensure_signed(
            webhook.signature.as_str(),
            &webhook.payload,
            &self.settings.webhook_secret,
            clock::now().unix_timestamp(),
        )?;
        notice_of(&webhook.payload)
    }
}

#[cfg(test)]
mod tests {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac as _};
    use ianua_app::ports::organization::{PaymentNotice, PaymentSignature};
    use ianua_domain::types::{Email, OrganizationId};
    use sha2::Sha256;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const API_KEY: &str = "sk_test_platform_key";
    const SIGNING: &str = "whsec_endpoint_secret";

    fn settings(api: &MockServer, timeout: Duration) -> StripeSettings {
        StripeSettings {
            api: Url::parse(&api.uri()).unwrap(),
            api_key: Secret::new(API_KEY),
            webhook_secret: Secret::new(SIGNING),
            success_url: HttpsUrl::new("https://app.ianua.cloud/billing/done").unwrap(),
            cancel_url: HttpsUrl::new("https://app.ianua.cloud/billing").unwrap(),
            currency: "eur".to_owned(),
            timeout,
        }
    }

    fn provider(api: &MockServer) -> StripePaymentProvider {
        StripePaymentProvider::new(settings(api, Duration::from_secs(5))).unwrap()
    }

    fn request() -> CheckoutRequest {
        CheckoutRequest {
            organization_id: OrganizationId::new(),
            billing_email: Email::new("olivia@acme.com").unwrap(),
        }
    }

    async fn stripe_answering(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/checkout/sessions"))
            .and(header(
                "authorization",
                format!("Bearer {API_KEY}").as_str(),
            ))
            .and(header("stripe-version", API_VERSION))
            .and(body_string_contains("mode=setup"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    fn signed(body: &[u8], at: i64) -> PaymentWebhook {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(SIGNING.as_bytes()).unwrap();
        mac.update(format!("{at}.").as_bytes());
        mac.update(body);
        let signature = data_encoding::HEXLOWER.encode(&mac.finalize().into_bytes());
        PaymentWebhook {
            payload: body.to_vec(),
            signature: PaymentSignature::new(format!("t={at},v1={signature}")),
        }
    }

    /// Olivia opens a checkout: Stripe is asked for a setup-mode session
    /// carrying Acme's id, and its page is handed back.
    #[tokio::test]
    async fn a_checkout_opens_a_setup_session_and_returns_its_page() {
        let server =
            stripe_answering(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "cs_test_1",
                "url": "https://checkout.stripe.com/c/pay/cs_test_1"
            })))
            .await;
        let checkout = request();

        let page = provider(&server).start_checkout(&checkout).await.unwrap();

        assert_eq!(page.as_str(), "https://checkout.stripe.com/c/pay/cs_test_1");
        let sent = server.received_requests().await.unwrap();
        let form = String::from_utf8(sent[0].body.clone()).unwrap();
        assert!(form.contains(&checkout.organization_id.as_uuid().to_string()));
    }

    /// A checkout receiving HTTP 500 returns an infrastructure error whose
    /// debug output does not expose the API key.
    #[tokio::test]
    async fn a_refused_checkout_is_an_error_without_the_key() {
        let server = stripe_answering(ResponseTemplate::new(500)).await;

        let failed = provider(&server)
            .start_checkout(&request())
            .await
            .unwrap_err();

        assert!(matches!(failed, DomainError::Infrastructure(_)));
        assert!(!format!("{failed:?}").contains(API_KEY));
    }

    /// A checkout response delayed beyond the configured timeout returns an infrastructure error.
    #[tokio::test]
    async fn a_stripe_that_hangs_is_given_up() {
        let server = stripe_answering(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"url": "https://checkout.stripe.com/x"}))
                .set_delay(Duration::from_secs(5)),
        )
        .await;
        let provider =
            StripePaymentProvider::new(settings(&server, Duration::from_millis(200))).unwrap();

        let failed = provider.start_checkout(&request()).await;

        assert!(matches!(failed, Err(DomainError::Infrastructure(_))));
    }

    /// A signed, fresh notice is read.
    #[tokio::test]
    async fn a_signed_notice_is_read() {
        let server = MockServer::start().await;
        let body = br#"{"id":"evt_1","created":1700000000,"type":"customer.created","data":{"object":{}}}"#;

        let notice = provider(&server)
            .read_notice(&signed(body, clock::now().unix_timestamp()))
            .unwrap();

        assert_eq!(notice.report, PaymentNotice::Ignored);
        assert_eq!(notice.event.id.as_str(), "evt_1");
    }

    /// Reading an invoice notice signed an hour ago returns unauthorized.
    #[tokio::test]
    async fn an_old_notice_is_refused() {
        let server = MockServer::start().await;
        let body = br#"{"id":"evt_1","type":"invoice.paid","data":{"object":{}}}"#;
        let an_hour_ago = clock::now().unix_timestamp() - 3600;

        let refused = provider(&server).read_notice(&signed(body, an_hour_ago));

        assert!(matches!(refused, Err(DomainError::Unauthorized(_))));
    }

    /// An uppercase currency code prevents construction of the Stripe provider.
    #[tokio::test]
    async fn a_malformed_currency_is_refused_at_start() {
        let server = MockServer::start().await;
        let mut wrong = settings(&server, Duration::from_secs(5));
        wrong.currency = "EUR".to_owned();

        assert!(StripePaymentProvider::new(wrong).is_err());
    }
}
