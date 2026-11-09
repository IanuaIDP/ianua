//! Posting a notification to an organization's destination outside the
//! app: a Slack channel, a Teams channel or a webhook of its own.
//!
//! A Slack or Teams address is the key to its channel, so it is kept
//! sealed and opened here only for the post; a webhook's signing secret
//! the same. Every address is the organization's choice, so the post goes
//! through the [`screened`] client: the opened address is screened before
//! the call and its name again as it resolves, no redirect is followed,
//! and each post is held to ten seconds so a channel that hangs never
//! holds the fan-out. A failed post names its status, never the address
//! or what the destination answered.

mod messages;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::{SealedFor, SecretEncryptor};
use ianua_app::ports::notifications::DestinationPoster;
use ianua_domain::domains::notifications::destination::{DestinationEndpoint, EndpointDelivery};
use ianua_domain::domains::notifications::notification::Notification;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::SealedSecret;

use crate::http::calls::{reachable, succeeded};
use crate::http::client::DeliveryReach;
use crate::http::deliveries::notifications::messages::{Message, slack, teams, webhook};

/// How long a destination has to take one post.
const POST_TIME: Duration = Duration::from_secs(10);

/// Posts notifications to Slack, Teams and webhook destinations.
pub struct HttpDestinationPoster {
    client: reqwest::Client,
    networks: UpstreamNetworks,
    encryptor: Arc<dyn SecretEncryptor>,
}

impl fmt::Debug for HttpDestinationPoster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpDestinationPoster")
            .field("networks", &self.networks)
            .finish_non_exhaustive()
    }
}

impl HttpDestinationPoster {
    /// A poster opening sealed addresses and secrets with `encryptor`, and
    /// reaching public addresses and those in `networks`, the deployment's
    /// own, by the path `reach` says.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(
        encryptor: Arc<dyn SecretEncryptor>,
        networks: UpstreamNetworks,
        reach: &DeliveryReach,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            client: reach.client(POST_TIME, networks.clone())?,
            networks,
            encryptor,
        })
    }

    /// The address to post to and what to post there, the sealed parts of
    /// `delivery` opened from `place` for this post alone.
    async fn opened(
        &self,
        delivery: EndpointDelivery<'_>,
        place: &SealedFor,
        notification: &Notification,
    ) -> Result<(Secret, Message), DomainError> {
        match delivery {
            EndpointDelivery::Slack(hook) => {
                Ok((self.open(hook, place).await?, slack(notification)?))
            }
            EndpointDelivery::Teams(hook) => {
                Ok((self.open(hook, place).await?, teams(notification)?))
            }
            EndpointDelivery::Webhook {
                url,
                signing_secret,
            } => {
                let secret = self.open(signing_secret, place).await?;
                Ok((Secret::new(url.as_str()), webhook(notification, &secret)?))
            }
        }
    }

    /// `sealed`, kept at `place`, opened as text.
    async fn open(&self, sealed: &SealedSecret, place: &SealedFor) -> Result<Secret, DomainError> {
        let bytes = self.encryptor.decrypt(sealed, place).await?;
        String::from_utf8(bytes)
            .map(Secret::new)
            .map_err(|_| DomainError::infra_msg("a sealed destination value did not open as text"))
    }

    /// Posts `message` to `url`.
    async fn deliver(&self, url: url::Url, message: Message) -> Result<(), DomainError> {
        let request = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        let request = match message.signed {
            Some(headers) => headers.applied(request),
            None => request,
        };
        succeeded(request.body(message.body).send().await)?;
        Ok(())
    }
}

#[async_trait]
impl DestinationPoster for HttpDestinationPoster {
    async fn post(
        &self,
        endpoint: &DestinationEndpoint,
        sealed_for: &SealedFor,
        notification: &Notification,
    ) -> Result<(), DomainError> {
        let (address, message) = self
            .opened(endpoint.delivery(), sealed_for, notification)
            .await?;
        let url = reachable(address.expose(), &self.networks)?;
        self.deliver(url, message).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::notifications::destination_endpoint_place;
    use ianua_domain::domains::notifications::notification::{
        AboutResource, CreateNotificationParams,
    };
    use ianua_domain::domains::notifications::reach::ToldAs;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::domains::webhooks::signing::SignedDelivery;
    use ianua_domain::types::{
        EventType, Label, NotificationDestinationId, NotificationId, OrganizationId, PublicHttpsUrl,
    };
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::http::calls::tests::{by_name, loopback};
    use crate::http::signing::signatures;

    fn encryptor() -> Arc<dyn SecretEncryptor> {
        Arc::new(AesGcmSecretEncryptor::new(
            SealingKey::new("k1", [7; 32]).unwrap(),
            Vec::new(),
        ))
    }

    fn poster(networks: UpstreamNetworks) -> HttpDestinationPoster {
        HttpDestinationPoster::new(encryptor(), networks, &DeliveryReach::default()).unwrap()
    }

    fn alert() -> Notification {
        Notification::create(CreateNotificationParams {
            id: NotificationId::new(),
            event_type: EventType::parse("tenant.provisioned").unwrap(),
            severity: NotificationSeverity::Info,
            title: Label::new("title", "Tenant provisioned").unwrap(),
            body: None,
            resource_id: AboutResource::Nothing,
            told_as: ToldAs::Overseer,
        })
    }

    /// Where Acme's one destination keeps its endpoint.
    fn acme_place() -> SealedFor {
        destination_endpoint_place(
            &OrganizationId::from_uuid(uuid::Uuid::nil()),
            &NotificationDestinationId::from_uuid(uuid::Uuid::nil()),
        )
    }

    /// A Slack destination whose hook `address`, as an administrator pasted
    /// it, the platform sealed for `place`.
    async fn sealed_for(address: &str, place: &SealedFor) -> DestinationEndpoint {
        let sealed = encryptor()
            .encrypt(address.as_bytes(), place)
            .await
            .unwrap();
        let shown = PublicHttpsUrl::new("https://hooks.slack.com/services/T0/B0/x").unwrap();
        DestinationEndpoint::slack(&shown, sealed).unwrap()
    }

    /// Acme's Slack destination whose sealed hook is `address`.
    async fn slack_sealing(address: &str) -> DestinationEndpoint {
        sealed_for(address, &acme_place()).await
    }

    /// A Slack hook sealed for Globex cannot open for Acme's destination;
    /// posting returns an infrastructure error and sends no request.
    #[tokio::test]
    async fn a_hook_sealed_for_another_organization_is_not_posted_to() {
        let server = channel(ResponseTemplate::new(200)).await;
        let globex = destination_endpoint_place(
            &OrganizationId::new(),
            &NotificationDestinationId::from_uuid(uuid::Uuid::nil()),
        );
        let endpoint =
            sealed_for(by_name(&server, "/services/T0/B0/s3cret").as_str(), &globex).await;

        let result = poster(loopback())
            .post(&endpoint, &acme_place(), &alert())
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    async fn channel(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/T0/B0/s3cret"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    /// The sealed Slack hook is opened and posted to, with the
    /// notification as the message text.
    #[tokio::test]
    async fn a_slack_hook_is_opened_and_posted_to() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/T0/B0/s3cret"))
            .and(body_partial_json(
                serde_json::json!({ "text": "[info] Tenant provisioned" }),
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let endpoint = slack_sealing(by_name(&server, "/services/T0/B0/s3cret").as_str()).await;

        let result = poster(loopback())
            .post(&endpoint, &acme_place(), &alert())
            .await;

        assert!(result.is_ok());
    }

    /// A sealed Slack hook resolving to disallowed loopback addresses
    /// returns a validation error without receiving a request.
    #[tokio::test]
    async fn an_opened_hook_resolving_inside_is_refused() {
        let server = channel(ResponseTemplate::new(200)).await;
        let endpoint = slack_sealing(by_name(&server, "/services/T0/B0/s3cret").as_str()).await;

        let result = poster(UpstreamNetworks::public_only())
            .post(&endpoint, &acme_place(), &alert())
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A refused Slack post produces an infrastructure error containing
    /// HTTP 404 but neither the hook's secret nor the response body.
    #[tokio::test]
    async fn a_refused_post_names_neither_the_hook_nor_the_answer() {
        let server = channel(ResponseTemplate::new(404).set_body_string("no_service")).await;
        let endpoint = slack_sealing(by_name(&server, "/services/T0/B0/s3cret").as_str()).await;

        let error = poster(loopback())
            .post(&endpoint, &acme_place(), &alert())
            .await
            .unwrap_err();

        let printed = format!("{error:?} {}", ianua_domain::shared::errors::causes(&error));
        assert!(matches!(error, DomainError::Infrastructure(_)));
        assert!(printed.contains("404"), "{printed}");
        assert!(!printed.contains("s3cret"), "{printed}");
        assert!(!printed.contains("no_service"), "{printed}");
    }

    /// A channel redirect to the metadata address fails the post with an
    /// infrastructure error.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let server = channel(
            ResponseTemplate::new(302).insert_header("location", "http://169.254.169.254/"),
        )
        .await;
        let endpoint = slack_sealing(by_name(&server, "/services/T0/B0/s3cret").as_str()).await;

        let result = poster(loopback())
            .post(&endpoint, &acme_place(), &alert())
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A channel response delayed beyond the post timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_hung_channel_is_given_up_on() {
        let server = channel(ResponseTemplate::new(200).set_delay(Duration::from_secs(15))).await;
        let endpoint = slack_sealing(by_name(&server, "/services/T0/B0/s3cret").as_str()).await;

        let result = poster(loopback())
            .post(&endpoint, &acme_place(), &alert())
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A webhook post carries the three Standard Webhooks headers, and its
    /// signature checks out under the destination's secret.
    #[tokio::test]
    async fn a_webhook_post_is_signed_with_its_secret() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hooks"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let secret = Secret::new("dsec_aw==");
        let message = webhook(&alert(), &secret).unwrap();

        poster(loopback())
            .deliver(by_name(&server, "/hooks"), message)
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        let request = &requests[0];
        assert_webhook_signature(request, &secret);
    }

    /// Checks the destination's signature against its exact received ID, time and body.
    fn assert_webhook_signature(request: &wiremock::Request, secret: &Secret) {
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        };
        let content = format!(
            "{}.{}.{}",
            header(SignedDelivery::ID_HEADER),
            header(SignedDelivery::TIMESTAMP_HEADER),
            String::from_utf8(request.body.clone()).unwrap()
        );
        assert_eq!(
            header(SignedDelivery::SIGNATURE_HEADER),
            signatures(content.as_bytes(), std::slice::from_ref(secret)).unwrap()
        );
    }
}
