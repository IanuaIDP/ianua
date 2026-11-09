//! Exchanging an account's lasting grant for a short-lived token before a
//! call: the grant is `{"client_id", "client_secret", "refresh_token"}`,
//! with whatever else the account keeps beside it, such as the Azure DevOps
//! organization or the Jira site it reaches.
//!
//! Some services hand back a new refresh token with every exchange and
//! retire the old one, as Atlassian, Microsoft and GitLab do; the account
//! then keeps the grant with the new token in the old one's place, which
//! the exchange reports as [`Renewed::To`]. The short-lived token is kept
//! beside the grant with the time it runs out, and reused until a minute
//! before then, so an account exchanges its grant about once per token's
//! life rather than on every call: two calls at once on a rotating grant
//! would otherwise send the same refresh token, and the service would
//! refuse the second. Before a token gets that close to its end the
//! platform exchanges the grant ahead of the call, one exchange per account
//! at a time across every worker ([`is_due`], [`renewed_ahead`]). The grant
//! is sent only to the token address the deployment names, the call follows
//! no redirect, and its answer is read to a bound.

use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::{Map, Value};
use time::Duration;
use url::form_urlencoded::Serializer;

use crate::answer::{body_within, failed, turned_away};
use crate::rest::sign_in::TokenBody;
use crate::{Renewed, ServiceEndpoint};

/// The largest answer a token address may give, in bytes.
const LARGEST_TOKEN_ANSWER: usize = 16 * 1024;

/// How long before a kept token runs out it is no longer used.
const REUSE_MARGIN: Duration = Duration::minutes(1);

/// How long before a kept token runs out it is exchanged ahead of a call.
/// Wider than [`REUSE_MARGIN`], so a call that starts just inside it still
/// finds its token good by the time it is sent.
const AHEAD_MARGIN: Duration = Duration::minutes(2);

/// How long a token is kept when the service does not say how long it
/// lasts, as Salesforce does not: shorter than any session it sets.
const UNSTATED_LIFE: Duration = Duration::minutes(10);

/// The name the short-lived token is kept under, beside the grant.
const KEPT_TOKEN: &str = "access_token";

/// The name the kept token's end is kept under, in Unix seconds.
const KEPT_UNTIL: &str = "access_expires_at";

/// Where and how a grant is exchanged.
#[derive(Debug, Clone)]
pub struct GrantAt {
    /// The token address.
    pub token: ServiceEndpoint,
    /// How the grant is sent: a form, or JSON as Atlassian takes it.
    pub body: TokenBody,
    /// The scope the token is asked for, where the service needs one named,
    /// as Microsoft Entra does.
    pub scope: Option<&'static str>,
}

/// A token issued for a grant, and the grant to keep from now on.
pub(crate) struct Exchanged {
    /// The short-lived token.
    pub(crate) access_token: String,
    /// The grant with a refresh token the service replaced, when it did.
    pub(crate) renewed: Renewed,
}

/// What a token address answers with a token.
#[derive(Deserialize)]
struct Issued {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
}

/// A grant's parts, as the account holds them.
struct Grant {
    whole: Map<String, Value>,
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

/// The token for the grant `credential` holds: the kept one while it has
/// more than a minute left, or else the one `at` issues.
///
/// # Errors
///
/// A failed outcome when the credential holds no grant or the token
/// address refuses it; turned away when the token address cannot be reached
/// or is busy.
pub(crate) async fn exchanged(
    client: &reqwest::Client,
    at: &GrantAt,
    credential: &Secret,
) -> Result<Exchanged, ActionOutcome> {
    let grant = grant_of(credential)?;
    if let Some(access_token) = kept_token(&grant.whole, REUSE_MARGIN) {
        return Ok(Exchanged {
            access_token,
            renewed: Renewed::Unchanged,
        });
    }
    exchange(client, at, grant).await
}

/// Whether `credential` holds a grant whose kept token is gone or within
/// [`AHEAD_MARGIN`] of its end.
pub(crate) fn is_due(credential: &Secret) -> bool {
    grant_of(credential).is_ok_and(|grant| kept_token(&grant.whole, AHEAD_MARGIN).is_none())
}

/// The grant `credential` holds, exchanged at `at` now whatever is left of
/// its token.
///
/// # Errors
///
/// As [`exchanged`].
pub(crate) async fn renewed_ahead(
    client: &reqwest::Client,
    at: &GrantAt,
    credential: &Secret,
) -> Result<Renewed, ActionOutcome> {
    let grant = grant_of(credential)?;
    Ok(exchange(client, at, grant).await?.renewed)
}

/// The token `at` issues for `grant`.
async fn exchange(
    client: &reqwest::Client,
    at: &GrantAt,
    grant: Grant,
) -> Result<Exchanged, ActionOutcome> {
    let Ok(response) = request(client, at, &grant).send().await else {
        return Err(turned_away(
            "the service's token address could not be reached",
        ));
    };
    let issued = issued(response).await?;
    Ok(Exchanged {
        access_token: issued.access_token.clone(),
        renewed: renewed(grant, issued),
    })
}

/// The token kept in `whole`, while more than `margin` is left of it.
fn kept_token(whole: &Map<String, Value>, margin: Duration) -> Option<String> {
    let until = whole.get(KEPT_UNTIL).and_then(Value::as_i64)?;
    let fresh_until = clock::now().saturating_add(margin).unix_timestamp();
    if until <= fresh_until {
        return None;
    }
    whole
        .get(KEPT_TOKEN)
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
}

/// The grant `credential` holds.
fn grant_of(credential: &Secret) -> Result<Grant, ActionOutcome> {
    let refused = || failed("the account holds no client id, client secret and refresh token");
    let Ok(Value::Object(whole)) = serde_json::from_str::<Value>(credential.expose()) else {
        return Err(refused());
    };
    let text = |name: &str| {
        whole
            .get(name)
            .and_then(Value::as_str)
            .map(|value| value.trim().to_owned())
    };
    let (Some(client_id), Some(client_secret), Some(refresh_token)) = (
        text("client_id"),
        text("client_secret"),
        text("refresh_token"),
    ) else {
        return Err(refused());
    };
    Ok(Grant {
        client_id,
        client_secret,
        refresh_token,
        whole,
    })
}

/// The request exchanging `grant` at `at`.
fn request(client: &reqwest::Client, at: &GrantAt, grant: &Grant) -> reqwest::RequestBuilder {
    let mut fields = vec![
        ("grant_type", "refresh_token"),
        ("client_id", grant.client_id.as_str()),
        ("client_secret", grant.client_secret.as_str()),
        ("refresh_token", grant.refresh_token.as_str()),
    ];
    if let Some(scope) = at.scope {
        fields.push(("scope", scope));
    }
    let request = client
        .post(at.token.base().clone())
        .header(ACCEPT, "application/json");
    match at.body {
        TokenBody::Form => request
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Serializer::new(String::new()).extend_pairs(fields).finish()),
        TokenBody::Json => {
            let body: Map<String, Value> = fields
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.into()))
                .collect();
            request.json(&body)
        }
    }
}

/// What a token address issued in `response`.
async fn issued(response: reqwest::Response) -> Result<Issued, ActionOutcome> {
    let status = response.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return Err(turned_away("the service's token address is busy"));
    }
    if !status.is_success() {
        return Err(failed("the service refused the account's grant"));
    }
    let Ok(body) = body_within(response, LARGEST_TOKEN_ANSWER).await else {
        return Err(turned_away(
            "the service's token address did not answer whole",
        ));
    };
    serde_json::from_slice::<Issued>(&body)
        .map_err(|_| failed("the service's token address issued no token"))
}

/// The grant to keep after an exchange answered `issued`: with any new
/// refresh token in the old one's place, and the token kept with the time
/// it runs out, which is [`UNSTATED_LIFE`] from now when the service does
/// not say.
fn renewed(grant: Grant, issued: Issued) -> Renewed {
    let new_refresh = issued
        .refresh_token
        .filter(|new| !new.is_empty() && *new != grant.refresh_token);
    let lasts = issued
        .expires_in
        .filter(|seconds| *seconds > 0)
        .map_or(UNSTATED_LIFE, Duration::seconds);
    let mut whole = grant.whole;
    if let Some(new) = new_refresh {
        whole.insert("refresh_token".to_owned(), Value::String(new));
    }
    let until = clock::now().saturating_add(lasts);
    whole.insert(KEPT_TOKEN.to_owned(), Value::String(issued.access_token));
    whole.insert(KEPT_UNTIL.to_owned(), Value::from(until.unix_timestamp()));
    Renewed::To(Secret::new(Value::Object(whole).to_string()))
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_json, body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const GRANT: &str = r#"{"organization":"contoso","client_id":"the app","client_secret":"the app's words","refresh_token":"first grant"}"#;

    fn at(server: &MockServer, body: TokenBody, scope: Option<&'static str>) -> GrantAt {
        GrantAt {
            token: ServiceEndpoint::at(&format!("{}/token", server.uri())).unwrap(),
            body,
            scope,
        }
    }

    fn client() -> reqwest::Client {
        crate::client(std::time::Duration::from_secs(2)).unwrap()
    }

    /// Microsoft hands back a new refresh token: the account keeps the
    /// grant with it, its organization beside it as before.
    #[tokio::test]
    async fn a_new_refresh_token_is_kept_in_the_grant() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("scope=the+scope"))
            .and(body_string_contains("refresh_token=first+grant"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "an hour's token", "refresh_token": "second grant"
            })))
            .mount(&server)
            .await;

        let exchanged = exchanged(
            &client(),
            &at(&server, TokenBody::Form, Some("the scope")),
            &Secret::new(GRANT.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(exchanged.access_token, "an hour's token");
        let Renewed::To(kept) = exchanged.renewed else {
            panic!("the new grant was not kept");
        };
        let kept: Value = serde_json::from_str(kept.expose()).unwrap();
        assert_eq!(kept["refresh_token"], "second grant");
        assert_eq!(kept["organization"], "contoso");
    }

    /// Atlassian takes the grant as JSON. A service that does not say how
    /// long its token lasts has it kept for ten minutes, with the refresh
    /// token as it was.
    #[tokio::test]
    async fn a_token_of_unstated_life_is_kept_for_a_while() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_json(serde_json::json!({
                "grant_type": "refresh_token",
                "client_id": "the app",
                "client_secret": "the app's words",
                "refresh_token": "first grant"
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "access_token": "t" })),
            )
            .mount(&server)
            .await;

        let exchanged = exchanged(
            &client(),
            &at(&server, TokenBody::Json, None),
            &Secret::new(GRANT.to_owned()),
        )
        .await
        .unwrap();

        let Renewed::To(kept) = exchanged.renewed else {
            panic!("the token was not kept");
        };
        let held: Value = serde_json::from_str(kept.expose()).unwrap();
        assert_eq!(held["refresh_token"], "first grant");
        assert_eq!(held[KEPT_TOKEN], "t");
        let until = held[KEPT_UNTIL].as_i64().unwrap();
        let most = clock::now().saturating_add(UNSTATED_LIFE).unix_timestamp();
        assert!(until <= most && until > clock::now().unix_timestamp());
    }

    /// A grant with no token kept yet is due, and so is one whose token has
    /// less than two minutes left; one with an hour left is not, and a
    /// bare token holds no grant to exchange.
    #[test]
    fn a_grant_is_due_ahead_of_its_token_running_out() {
        let with_left = |seconds: i64| {
            let until = clock::now().saturating_add(Duration::seconds(seconds));
            let mut grant: Value = serde_json::from_str(GRANT).unwrap();
            grant[KEPT_TOKEN] = Value::from("a token");
            grant[KEPT_UNTIL] = Value::from(until.unix_timestamp());
            Secret::new(grant.to_string())
        };

        assert!(is_due(&Secret::new(GRANT.to_owned())));
        assert!(is_due(&with_left(90)));
        assert!(!is_due(&with_left(3600)));
        assert!(!is_due(&Secret::new("a bare token".to_owned())));
    }

    /// Exchanged ahead of a call, a grant whose token still has ninety
    /// seconds goes to the token address anyway, and the new token is what
    /// the call then reuses without asking again.
    #[tokio::test]
    async fn an_exchange_ahead_is_what_the_next_call_reuses() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("refresh_token=first+grant"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ahead token",
                "refresh_token": "second grant",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let at = at(&server, TokenBody::Form, None);
        let until = clock::now().saturating_add(Duration::seconds(90));
        let mut grant: Value = serde_json::from_str(GRANT).unwrap();
        grant[KEPT_TOKEN] = Value::from("old token");
        grant[KEPT_UNTIL] = Value::from(until.unix_timestamp());

        let renewed = renewed_ahead(&client(), &at, &Secret::new(grant.to_string()))
            .await
            .unwrap();
        let Renewed::To(kept) = renewed else {
            panic!("the exchange kept nothing");
        };
        let called = exchanged(&client(), &at, &kept).await.unwrap();

        assert_eq!(called.access_token, "ahead token");
        assert!(matches!(called.renewed, Renewed::Unchanged));
    }

    /// GitLab's token lasts two hours: the account keeps it with its end,
    /// and the next call within that time uses it without asking GitLab,
    /// so two calls at once never spend the same refresh token.
    #[tokio::test]
    async fn a_token_is_kept_and_reused_until_it_runs_out() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "two hours' token",
                "refresh_token": "second grant",
                "expires_in": 7200
            })))
            .expect(1)
            .mount(&server)
            .await;
        let at = at(&server, TokenBody::Form, None);

        let first = exchanged(&client(), &at, &Secret::new(GRANT.to_owned()))
            .await
            .unwrap();
        let Renewed::To(kept) = first.renewed else {
            panic!("the token was not kept");
        };
        let again = exchanged(&client(), &at, &kept).await.unwrap();

        assert_eq!(again.access_token, "two hours' token");
        assert!(matches!(again.renewed, Renewed::Unchanged));
        let held: Value = serde_json::from_str(kept.expose()).unwrap();
        assert_eq!(held["refresh_token"], "second grant");
        assert!(held[KEPT_UNTIL].as_i64().unwrap() > clock::now().unix_timestamp());
    }

    /// A kept token with less than a minute left is not used: the grant
    /// is exchanged again, and the new token takes its place.
    #[tokio::test]
    async fn a_token_about_to_run_out_is_exchanged_again() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("refresh_token=first+grant"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new token", "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let nearly_out = clock::now().saturating_add(Duration::seconds(30));
        let mut grant: Value = serde_json::from_str(GRANT).unwrap();
        grant[KEPT_TOKEN] = Value::from("old token");
        grant[KEPT_UNTIL] = Value::from(nearly_out.unix_timestamp());

        let exchanged = exchanged(
            &client(),
            &at(&server, TokenBody::Form, None),
            &Secret::new(grant.to_string()),
        )
        .await
        .unwrap();

        assert_eq!(exchanged.access_token, "new token");
        let Renewed::To(kept) = exchanged.renewed else {
            panic!("the new token was not kept");
        };
        assert!(kept.expose().contains("new token"));
    }

    /// A bare token and a grant rejected by the token endpoint both
    /// return failed outcomes instead of exchanged credentials.
    #[tokio::test]
    async fn no_grant_or_a_refused_one_gives_no_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        let at = at(&server, TokenBody::Form, None);

        let none = exchanged(&client(), &at, &Secret::new("a bare token".to_owned())).await;
        let refused = exchanged(&client(), &at, &Secret::new(GRANT.to_owned())).await;

        assert!(matches!(none, Err(ActionOutcome::Failed(_))));
        assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
    }
}
