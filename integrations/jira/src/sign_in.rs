//! Signing in at Atlassian to connect a Jira account. One sign-in may
//! reach several Jira sites, so the person names theirs, such as
//! `acme.atlassian.net`. Once the code is swapped, Atlassian is asked which
//! sites the grant reaches, and the account keeps the named site's cloud id
//! beside the grant; a site the grant does not reach is refused, so an
//! account never names a site it cannot use.

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::connect::{Exchange, SignIn, SignInLink, Swap};
use ianua_integration::rest::sign_in::OAuthSignIn;
use ianua_integration::{ServiceEndpoint, client};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue};
use serde::Deserialize;
use serde_json::Value;

/// The word for the place a person names.
const SITE: &str = "site";

/// The most of Atlassian's list of sites read, in bytes.
const LARGEST_LIST: usize = 64 * 1024;

/// One site a grant reaches, as Atlassian lists it.
#[derive(Deserialize)]
struct Resource {
    id: String,
    url: String,
}

/// Signing in at Atlassian for one Jira site.
pub(crate) struct CloudSignIn {
    oauth: OAuthSignIn,
    resources: ServiceEndpoint,
    client: reqwest::Client,
}

impl CloudSignIn {
    /// A sign-in through `oauth`, asking `gateway` which sites a grant
    /// reaches, each question held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the address cannot be
    /// made or the client cannot be built.
    pub(crate) fn new(
        oauth: OAuthSignIn,
        gateway: &ServiceEndpoint,
        timeout: std::time::Duration,
    ) -> Result<Self, DomainError> {
        let resources = gateway
            .url(&["oauth", "token", "accessible-resources"])
            .map_err(|_| DomainError::infra_msg("Atlassian's address takes no path"))?;
        Ok(Self {
            oauth,
            resources: ServiceEndpoint::at(resources.as_str())?,
            client: client(timeout)?,
        })
    }

    /// The cloud id of `site` among the sites `token` reaches.
    async fn cloud_id(&self, token: &Secret, site: &str) -> Result<String, Exchange> {
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", token.expose()))
            .map_err(|_| Exchange::Refused)?;
        bearer.set_sensitive(true);
        let Ok(response) = self
            .client
            .get(self.resources.base().clone())
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, bearer)
            .send()
            .await
        else {
            return Err(Exchange::Unreachable);
        };
        if !response.status().is_success() {
            return Err(Exchange::Unreachable);
        }
        let Ok(body) = response.bytes().await else {
            return Err(Exchange::Unreachable);
        };
        if body.len() > LARGEST_LIST {
            return Err(Exchange::Refused);
        }
        let listed: Vec<Resource> = serde_json::from_slice(&body).map_err(|_| Exchange::Refused)?;
        listed_site(listed, site)
    }
}

/// Selects the named site's cloud identity only from the resources reached by the grant.
fn listed_site(listed: Vec<Resource>, site: &str) -> Result<String, Exchange> {
    let wanted = host_of(site).ok_or(Exchange::Refused)?;
    listed
        .into_iter()
        .find(|resource| host_of(&resource.url).as_deref() == Some(wanted.as_str()))
        .map(|resource| resource.id)
        .ok_or(Exchange::Refused)
}

#[async_trait]
impl SignIn for CloudSignIn {
    fn asks_for_place(&self) -> Option<&'static str> {
        Some(SITE)
    }

    fn authorize_address(&self, link: SignInLink<'_>) -> String {
        self.oauth.authorize_address(link)
    }

    async fn exchange(&self, swap: Swap<'_>) -> Exchange {
        let Some(site) = swap.place else {
            return Exchange::Refused;
        };
        let swapped = match self.oauth.swapped(swap).await {
            Ok(swapped) => swapped,
            Err(failed) => return failed,
        };
        let cloud_id = match self.cloud_id(&swapped.access_token, site).await {
            Ok(cloud_id) => cloud_id,
            Err(failed) => return failed,
        };
        with_cloud_id(&swapped.kept, &cloud_id).map_or(Exchange::Refused, Exchange::Issued)
    }
}

/// The host `written` names, lower-cased, whether or not it starts with
/// `https://`.
fn host_of(written: &str) -> Option<String> {
    let written = written.trim();
    let address = match written.contains("://") {
        true => written.to_owned(),
        false => format!("https://{written}"),
    };
    url::Url::parse(&address)
        .ok()?
        .host_str()
        .map(str::to_ascii_lowercase)
}

/// The grant `kept` with `cloud_id` beside it.
fn with_cloud_id(kept: &Secret, cloud_id: &str) -> Option<Secret> {
    let Ok(Value::Object(mut grant)) = serde_json::from_str::<Value>(kept.expose()) else {
        return None;
    };
    grant.insert("cloud_id".to_owned(), Value::String(cloud_id.to_owned()));
    Some(Secret::new(Value::Object(grant).to_string()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_integration::rest::sign_in::{
        Keeps, OAuthApp, OAuthSignInParams, SignInSettings, TokenBody,
    };
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// Registers the token exchange and the two sites that the issued grant reaches.
    async fn mount_resources(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "an hour's token", "refresh_token": "the grant"
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/oauth/token/accessible-resources"))
            .and(header("authorization", "Bearer an hour's token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                { "id": "globex-cloud", "url": "https://globex.atlassian.net" },
                { "id": "acme-cloud", "url": "https://acme.atlassian.net" }
            ])))
            .mount(server)
            .await;
    }

    /// Builds a sign-in against the registered token and resource endpoints.
    async fn sign_in(server: &MockServer) -> CloudSignIn {
        mount_resources(server).await;
        let base = ServiceEndpoint::at(&server.uri()).unwrap();
        let oauth = OAuthSignIn::new(OAuthSignInParams {
            at: SignInSettings {
                app: OAuthApp {
                    client_id: "the app".to_owned(),
                    client_secret: Secret::new("the app's words".to_owned()),
                },
                authorize: ServiceEndpoint::at(&format!("{}/authorize", server.uri())).unwrap(),
                token: ServiceEndpoint::at(&format!("{}/oauth/token", server.uri())).unwrap(),
            },
            scopes: &["read:jira-work"],
            scope_separator: " ",
            extra: &[],
            swap_extra: &[],
            token_body: TokenBody::Json,
            keeps: Keeps::RefreshGrant,
            place: None,
            timeout: Duration::from_secs(2),
        })
        .unwrap();
        CloudSignIn::new(oauth, &base, Duration::from_secs(2)).unwrap()
    }

    fn swap<'a>(code: &'a Secret, place: Option<&'a str>) -> Swap<'a> {
        Swap {
            code,
            verifier: code,
            redirect: "https://ianua.test/api/v1/integrations/callback",
            place,
        }
    }

    /// Tess names acme.atlassian.net: the account keeps the grant with
    /// Acme's cloud id, not Globex's.
    #[tokio::test]
    async fn the_named_site_s_cloud_id_is_kept() {
        let server = MockServer::start().await;
        let code = Secret::new("the code".to_owned());

        let issued = sign_in(&server)
            .await
            .exchange(swap(&code, Some("acme.atlassian.net")))
            .await;

        let Exchange::Issued(kept) = issued else {
            panic!("nothing was issued");
        };
        let kept: Value = serde_json::from_str(kept.expose()).unwrap();
        assert_eq!(kept["cloud_id"], "acme-cloud");
        assert_eq!(kept["refresh_token"], "the grant");
    }

    /// Exchanging a code for an unlisted site or without naming a site
    /// returns a refusal instead of issuing credentials.
    #[tokio::test]
    async fn a_site_the_grant_does_not_reach_is_refused() {
        let server = MockServer::start().await;
        let code = Secret::new("the code".to_owned());
        let sign_in = sign_in(&server).await;

        let elsewhere = sign_in
            .exchange(swap(&code, Some("initech.atlassian.net")))
            .await;
        let nowhere = sign_in.exchange(swap(&code, None)).await;

        assert!(matches!(elsewhere, Exchange::Refused));
        assert!(matches!(nowhere, Exchange::Refused));
    }
}
