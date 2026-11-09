//! Telling an app's server that a person signed out, by posting the signed
//! logout token to the back-channel address the app registered (OpenID
//! Connect Back-Channel Logout 1.0).
//!
//! The address is the tenant's app's, so the call goes through the
//! [`screened`] client: a name that resolves inside the deployment is
//! refused, and no redirect is followed. One app whose server hangs must
//! not hold up telling the others, so each post is held to five seconds.
//! The token is put only in the form body, never in an error or a log.

use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::oauth::BackChannelLogoutSender;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::HttpsUrl;

use crate::http::calls::{reachable, succeeded};
use crate::http::client::screened;

/// How long an app's server has to take one logout token.
const POST_TIME: Duration = Duration::from_secs(5);

/// Posts logout tokens to the back-channel addresses apps registered.
#[derive(Debug, Clone)]
pub struct HttpBackChannelLogoutSender {
    client: reqwest::Client,
    networks: UpstreamNetworks,
}

impl HttpBackChannelLogoutSender {
    /// A sender reaching public addresses and those in `networks`, the
    /// deployment's own.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(networks: UpstreamNetworks) -> Result<Self, DomainError> {
        Ok(Self {
            client: screened(POST_TIME, networks.clone())?,
            networks,
        })
    }

    /// Posts `logout_token` to `url` as the form field the standard names.
    async fn post_to(&self, url: url::Url, logout_token: &Secret) -> Result<(), DomainError> {
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("logout_token", logout_token.expose())
            .finish();
        succeeded(
            self.client
                .post(url)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(form)
                .send()
                .await,
        )?;
        Ok(())
    }
}

#[async_trait]
impl BackChannelLogoutSender for HttpBackChannelLogoutSender {
    async fn deliver(&self, uri: &HttpsUrl, logout_token: &Secret) -> Result<(), DomainError> {
        let url = reachable(uri.as_str(), &self.networks)?;
        self.post_to(url, logout_token).await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_string, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::calls::tests::{by_name, loopback};

    const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.e30.c2ln";

    async fn app_server(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/logout"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    /// The token goes as the `logout_token` form field, and an answer of 200
    /// is taken as told.
    #[tokio::test]
    async fn the_token_is_posted_as_a_form_field() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/logout"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string(format!("logout_token={TOKEN}")))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let sender = HttpBackChannelLogoutSender::new(loopback()).unwrap();

        let result = sender
            .post_to(by_name(&server, "/logout"), &Secret::new(TOKEN))
            .await;

        assert!(result.is_ok());
    }

    /// An app's HTTP 400 returns an infrastructure error excluding the
    /// logout token echoed in the response body.
    #[tokio::test]
    async fn a_refusal_is_an_error_without_the_token() {
        let server = app_server(ResponseTemplate::new(400).set_body_string(TOKEN)).await;
        let sender = HttpBackChannelLogoutSender::new(loopback()).unwrap();

        let error = sender
            .post_to(by_name(&server, "/logout"), &Secret::new(TOKEN))
            .await
            .unwrap_err();

        let printed = format!("{error:?} {}", ianua_domain::shared::errors::causes(&error));
        assert!(matches!(error, DomainError::Infrastructure(_)));
        assert!(!printed.contains(TOKEN), "{printed}");
    }

    /// A logout host resolving to disallowed loopback addresses returns a
    /// validation error without receiving a post.
    #[tokio::test]
    async fn an_internal_address_is_refused() {
        let server = app_server(ResponseTemplate::new(200)).await;
        let sender = HttpBackChannelLogoutSender::new(UpstreamNetworks::public_only()).unwrap();

        let result = sender
            .post_to(by_name(&server, "/logout"), &Secret::new(TOKEN))
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A logout redirect to the metadata address returns an infrastructure
    /// error.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let server = app_server(
            ResponseTemplate::new(307).insert_header("location", "http://169.254.169.254/"),
        )
        .await;
        let sender = HttpBackChannelLogoutSender::new(loopback()).unwrap();

        let result = sender
            .post_to(by_name(&server, "/logout"), &Secret::new(TOKEN))
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A logout response delayed beyond the post timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_hung_server_is_given_up_on() {
        let server = app_server(ResponseTemplate::new(200).set_delay(Duration::from_secs(8))).await;
        let sender = HttpBackChannelLogoutSender::new(loopback()).unwrap();

        let result = sender
            .post_to(by_name(&server, "/logout"), &Secret::new(TOKEN))
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }
}
