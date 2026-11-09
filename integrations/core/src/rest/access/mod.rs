//! How a service is reached through an account: the address its API
//! answers at, and the credential's header, from what the account holds.
//!
//! A credential is opened by the platform and handed to the integration
//! for one call; it is sent only where its [`Access`] says, never to an
//! address a step names. An account that names its own site, as a Jira
//! one does, is held to the sites the deployment allows. An account that
//! holds a lasting grant, as a Google one does, is exchanged for a
//! short-lived token at the deployment's token address before each call.

mod grants;
mod headers;
mod sites;

use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::security::secret::Secret;
use reqwest::header::HeaderValue;
use serde::Deserialize;

use self::grants::{form_at, names_allowed_site, refreshed, site_granted};
use self::headers::{after_scheme, basic, bearer, key_and_token};
use self::sites::{SiteApi, site_reach};
use crate::answer::failed;
use crate::rest::grant::{GrantAt, exchanged, is_due, renewed_ahead};
use crate::rest::operation::Verb;
use crate::{Renewed, ServiceEndpoint};

/// The hosts an account may name as its own site, such as
/// `.atlassian.net` for Jira Cloud; an exact host is written without the
/// leading dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedSites {
    hosts: Vec<String>,
}

impl AllowedSites {
    /// The sites `hosts` allow: each an exact host, or `.suffix` for every
    /// host under it.
    #[must_use]
    pub fn new(hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            hosts: hosts
                .into_iter()
                .map(|host| host.into().to_ascii_lowercase())
                .collect(),
        }
    }

    /// Whether `host` is allowed.
    #[must_use]
    pub fn allows(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.hosts
            .iter()
            .any(|allowed| match allowed.strip_prefix('.') {
                Some(suffix) => {
                    host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}"))
                }
                None => host == *allowed,
            })
    }

    /// Whether the deployment listed `host` together with `port`, as a
    /// company's own Jira server on port 8443 is, written
    /// `jira.acme.example:8443`.
    #[must_use]
    pub fn allows_on_port(&self, host: &str, port: u16) -> bool {
        self.hosts
            .contains(&format!("{}:{port}", host.to_ascii_lowercase()))
    }
}

/// The addresses a service answers at, one per region, such as Mailgun's
/// `us` and `eu`; the first is where an account naming no region goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Regions {
    first: (String, ServiceEndpoint),
    others: Vec<(String, ServiceEndpoint)>,
}

impl Regions {
    /// `first`, where an account naming no region goes, and `others`.
    #[must_use]
    pub fn new(
        first: (&str, ServiceEndpoint),
        others: impl IntoIterator<Item = (&'static str, ServiceEndpoint)>,
    ) -> Self {
        Self {
            first: (first.0.to_ascii_lowercase(), first.1),
            others: others
                .into_iter()
                .map(|(name, endpoint)| (name.to_ascii_lowercase(), endpoint))
                .collect(),
        }
    }

    /// The address of the region `name`, or the first region's when no
    /// name is given; none for a region the service does not have.
    #[must_use]
    pub fn endpoint(&self, name: Option<&str>) -> Option<&ServiceEndpoint> {
        let Some(name) = name else {
            return Some(&self.first.1);
        };
        let name = name.trim().to_ascii_lowercase();
        std::iter::once(&self.first)
            .chain(&self.others)
            .find(|(region, _)| *region == name)
            .map(|(_, endpoint)| endpoint)
    }
}

/// How a key limited to one place, such as a Mailgun key that may only send
/// from one domain, proves itself without acting: a request at that place
/// that the service takes the key for, then refuses for what it lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitedProbe {
    /// The name the account gives its place under, such as `domain`.
    pub field: &'static str,
    /// The verb it calls with.
    pub verb: Verb,
    /// The path before the place.
    pub before: &'static [&'static str],
    /// The path after the place.
    pub after: &'static [&'static str],
    /// The status the service answers once it has taken the key, such as
    /// `400` for a send naming nobody.
    pub taken: u16,
}

/// How a service is reached through an account.
#[derive(Debug, Clone)]
pub enum Access {
    /// The account holds a token alone, sent as `Bearer` to `endpoint`, as
    /// GitHub's and Slack's are.
    Bearer {
        /// Where the API answers.
        endpoint: ServiceEndpoint,
    },
    /// The account holds a token alone, sent as `Bearer` to `endpoint`, or,
    /// when it signed in, a grant exchanged at `signed_in` for a token sent
    /// the same way, as GitLab takes a pasted access token or an OAuth
    /// token that lasts two hours.
    BearerOrGrant {
        /// Where the API answers.
        endpoint: ServiceEndpoint,
        /// Where a signed-in account's grant is exchanged.
        signed_in: GrantAt,
    },
    /// The account holds a token alone, sent after `scheme` to `endpoint`:
    /// nothing before it as Linear takes an API key, `Bot ` as Discord
    /// takes a bot's token, `Token token=` as PagerDuty takes an API key.
    Scheme {
        /// Where the API answers.
        endpoint: ServiceEndpoint,
        /// What goes before the token in the header.
        scheme: &'static str,
    },
    /// The account holds a token alone, or `{"token", "from"}`: the token
    /// is sent after `scheme` to `endpoint`, and `from`, the email address
    /// of a person at the service, in the `From` header, as PagerDuty takes
    /// a change from an account-wide key only on behalf of a named user.
    SchemeActingFor {
        /// Where the API answers.
        endpoint: ServiceEndpoint,
        /// What goes before the token in the header.
        scheme: &'static str,
    },
    /// The account holds `{"key", "token"}`, sent as Trello's `OAuth`
    /// header naming both to `endpoint`.
    KeyAndToken {
        /// Where the API answers.
        endpoint: ServiceEndpoint,
    },
    /// The account holds a key alone, or `{"key"}` with a `"region"` naming
    /// one of `regions` and, for a key limited to one place, that place
    /// under the name `limited` gives. The key is sent as the password of
    /// the fixed user `user` to its region, the first one when it names
    /// none, as Mailgun takes an API key as `api` in its US or EU region,
    /// or a key that may only send from one domain.
    Key {
        /// Where the API answers, by region.
        regions: Regions,
        /// The user name the key is sent with.
        user: &'static str,
        /// How a key limited to one place proves itself, when the service
        /// has such keys.
        limited: Option<LimitedProbe>,
    },
    /// The account holds `{"organization", "token"}`; the token is sent as
    /// a password with no user name to `base` with the organization's name
    /// after it, as Azure DevOps takes a personal access token. With
    /// `signed_in`, an account that signed in holds the organization beside
    /// a grant instead, exchanged at `signed_in` for a token sent as
    /// `Bearer`.
    Organization {
        /// The API's address, before the organization's name.
        base: ServiceEndpoint,
        /// Where a signed-in account's grant is exchanged, when the
        /// deployment lets people sign in.
        signed_in: Option<GrantAt>,
    },
    /// The account holds `{"account", "token"}` and may hold `"key"`; the
    /// token is sent as the password of the key, or else of the account, to
    /// `base` with the account's id after it, as Twilio takes an account SID
    /// with its auth token, or an API key and its secret.
    Account {
        /// The API's address, before the account's id.
        base: ServiceEndpoint,
    },
    /// The account holds `{"client_id", "client_secret", "refresh_token"}`,
    /// a lasting grant exchanged at `token` for a short-lived token before
    /// each call, sent as `Bearer` to `endpoint`, as Google's APIs take an
    /// OAuth grant.
    Refreshed {
        /// Where the API answers.
        endpoint: ServiceEndpoint,
        /// Where the grant is exchanged for a token.
        token: ServiceEndpoint,
    },
    /// The account holds `{"site", "user", "token"}`; the user and token
    /// are sent as a password to the account's own site, under `api`, as
    /// Jira takes an email and an API token. The site must be `https` and
    /// allowed by `sites`. With `cloud`, an account that signed in holds
    /// its site's cloud id beside a grant instead, and is reached through
    /// Atlassian's gateway with a token exchanged for the grant.
    Site {
        /// The sites an account may name.
        sites: AllowedSites,
        /// The path of the API under a site, such as `rest/api/3`.
        api: &'static [&'static str],
        /// Atlassian's gateway, when the deployment lets people sign in.
        cloud: Option<AtlassianCloud>,
    },
    /// The account holds `{"site", "client_id", "client_secret",
    /// "refresh_token"}`: a lasting grant exchanged at `token` for a
    /// short-lived token before each call, sent as `Bearer` to the
    /// account's own site under `api`, as Salesforce takes an OAuth grant
    /// for a company's own domain. The site must be `https` and allowed by
    /// `sites`; the grant goes only to `token`.
    SiteGrant {
        /// The sites an account may name.
        sites: AllowedSites,
        /// The path of the API under a site, such as `services/data/v62.0`.
        api: &'static [&'static str],
        /// Where the grant is exchanged for a token.
        token: ServiceEndpoint,
    },
    /// The account holds a token alone, sent as the first part of the
    /// address under `endpoint` after `prefix`, as Telegram takes a bot's
    /// token in `bot<token>/sendMessage`. The token may hold only letters,
    /// digits, `:`, `_` and `-`, so it is always one part of the address,
    /// and no header is sent.
    PathToken {
        /// Where the API answers.
        endpoint: ServiceEndpoint,
        /// What goes before the token in its part, such as `bot`.
        prefix: &'static str,
    },
}

/// Where a call goes and the header that signs it.
#[derive(Debug)]
pub struct Reached {
    /// The API's address for this account.
    pub endpoint: ServiceEndpoint,
    /// The `Authorization` header, marked sensitive so it is never logged;
    /// none when the credential is part of the address instead, as a
    /// Telegram bot's token is.
    pub authorization: Option<HeaderValue>,
    /// The `From` header naming the person a change is made on behalf of,
    /// when the account names one, as a PagerDuty account-wide key's does.
    pub acting_for: Option<HeaderValue>,
    /// The one place the credential is limited to, such as a Mailgun
    /// domain, when it is.
    pub place: Option<String>,
    /// The credential to keep from now on, when reaching the service
    /// replaced it, as an exchanged Jira or Azure DevOps grant is.
    pub renewed: Renewed,
}

/// `request` signed with `authorization`, when the call carries one.
pub(crate) fn with_authorization(
    request: reqwest::RequestBuilder,
    authorization: Option<HeaderValue>,
) -> reqwest::RequestBuilder {
    match authorization {
        Some(header) => request.header(reqwest::header::AUTHORIZATION, header),
        None => request,
    }
}

/// `request` naming the person it acts for in `From`, when the account
/// names one.
pub(crate) fn with_acting_for(
    request: reqwest::RequestBuilder,
    acting_for: Option<HeaderValue>,
) -> reqwest::RequestBuilder {
    match acting_for {
        Some(header) => request.header(reqwest::header::FROM, header),
        None => request,
    }
}

/// Jira Cloud reached through Atlassian's gateway, for an account that
/// signed in: the gateway's address, before `ex/jira/{cloud id}`, and where
/// its grant is exchanged.
#[derive(Debug, Clone)]
pub struct AtlassianCloud {
    /// The gateway, such as `https://api.atlassian.com/`.
    pub gateway: ServiceEndpoint,
    /// Where an account's grant is exchanged for a token.
    pub grant: GrantAt,
}

/// A key account as sealed when it holds more than the key.
#[derive(Deserialize)]
struct KeyAccount {
    key: String,
    region: Option<String>,
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

/// An Azure DevOps account as sealed.
#[derive(Deserialize)]
struct OrganizationAccount {
    organization: String,
    token: String,
}

/// A key with the person its changes are made for, as sealed.
#[derive(Deserialize)]
struct ActingAccount {
    token: String,
    from: String,
}

/// A Twilio account as sealed.
#[derive(Deserialize)]
struct ServiceAccount {
    account: String,
    key: Option<String>,
    token: String,
}

/// What a signed-in account keeps beside its grant: the Azure DevOps
/// organization, or the Jira site's cloud id.
#[derive(Deserialize)]
struct GrantPlace {
    organization: Option<String>,
    cloud_id: Option<String>,
}

impl Access {
    /// Where `credential` reaches, and the header it is sent in, exchanging
    /// a lasting grant through `client` first where the access takes one.
    ///
    /// # Errors
    ///
    /// A failed outcome when the credential is missing, is not what this
    /// access takes, names a site the deployment does not allow, or holds a
    /// grant the token address refuses; turned away when the token address
    /// cannot be reached or is busy.
    ///
    /// One arm per kind of access, so every kind a service may take is read
    /// in one place; each arm hands its work to a function of its own.
    #[allow(clippy::too_many_lines)]
    pub async fn reach(
        &self,
        client: &reqwest::Client,
        credential: Option<&Secret>,
    ) -> Result<Reached, ActionOutcome> {
        let credential = required_credential(credential)?;
        match self {
            Self::Bearer { endpoint } => Ok(token_at(endpoint, bearer(credential.expose())?)),
            Self::BearerOrGrant {
                endpoint,
                signed_in,
            } => bearer_or_grant(client, endpoint, signed_in, credential).await,
            Self::Scheme { endpoint, scheme } => schemed(endpoint, scheme, credential),
            Self::SchemeActingFor { endpoint, scheme } => acting_for(endpoint, scheme, credential),
            Self::KeyAndToken { endpoint } => key_and_token(endpoint, credential),
            Self::Key {
                regions,
                user,
                limited,
            } => key(regions, user, limited.as_ref(), credential),
            Self::Organization { base, signed_in } => {
                organization_reach(client, base, signed_in.as_ref(), credential).await
            }
            Self::Account { base } => account(base, credential),
            Self::Site { sites, api, cloud } => {
                let api = SiteApi::new(sites, api);
                site_reach(client, &api, cloud.as_ref(), credential).await
            }
            Self::Refreshed { endpoint, token } => {
                refreshed(client, endpoint, token, credential).await
            }
            Self::SiteGrant { sites, api, token } => {
                site_granted(client, &SiteApi::new(sites, api), token, credential).await
            }
            Self::PathToken { endpoint, prefix } => in_path(endpoint, prefix, credential),
        }
    }

    /// Whether `credential` holds a grant this access exchanges, with its
    /// token gone or near its end.
    #[must_use]
    pub fn grant_due(&self, credential: &Secret) -> bool {
        self.grant_address(credential).is_some() && is_due(credential)
    }

    /// The grant `credential` holds, exchanged now through `client`, and
    /// the credential to keep. Unchanged when this access takes no grant.
    ///
    /// # Errors
    ///
    /// A failed outcome when the token address refuses the grant; turned
    /// away when it cannot be reached or is busy.
    pub async fn renew_grant(
        &self,
        client: &reqwest::Client,
        credential: &Secret,
    ) -> Result<Renewed, ActionOutcome> {
        match self.grant_address(credential) {
            Some(at) => renewed_ahead(client, &at, credential).await,
            None => Ok(Renewed::Unchanged),
        }
    }

    /// Where this access exchanges the grant `credential` holds, if it
    /// holds one this access takes.
    fn grant_address(&self, credential: &Secret) -> Option<GrantAt> {
        match self {
            Self::BearerOrGrant { signed_in, .. } => {
                holds_grant(credential).then(|| signed_in.clone())
            }
            Self::Organization { signed_in, .. } => {
                signed_in.clone().filter(|_| holds_grant(credential))
            }
            Self::Site { cloud, .. } => cloud
                .as_ref()
                .filter(|_| holds_grant(credential))
                .map(|cloud| cloud.grant.clone()),
            Self::Refreshed { token, .. } => Some(form_at(token)),
            Self::SiteGrant { sites, api, token } => {
                names_allowed_site(&SiteApi::new(sites, api), credential).then(|| form_at(token))
            }
            Self::Bearer { .. }
            | Self::Scheme { .. }
            | Self::SchemeActingFor { .. }
            | Self::KeyAndToken { .. }
            | Self::Key { .. }
            | Self::Account { .. }
            | Self::PathToken { .. } => None,
        }
    }

    /// How a credential limited to one place proves itself, when this
    /// access takes such credentials.
    #[must_use]
    pub fn limited_probe(&self) -> Option<&LimitedProbe> {
        match self {
            Self::Key { limited, .. } => limited.as_ref(),
            Self::Bearer { .. }
            | Self::BearerOrGrant { .. }
            | Self::Scheme { .. }
            | Self::SchemeActingFor { .. }
            | Self::KeyAndToken { .. }
            | Self::Organization { .. }
            | Self::Account { .. }
            | Self::Site { .. }
            | Self::Refreshed { .. }
            | Self::SiteGrant { .. }
            | Self::PathToken { .. } => None,
        }
    }
}

/// Reaches a fixed endpoint with an already validated token header.
fn token_at(endpoint: &ServiceEndpoint, authorization: Option<HeaderValue>) -> Reached {
    Reached {
        endpoint: endpoint.clone(),
        authorization,
        place: None,
        acting_for: None,
        renewed: Renewed::Unchanged,
    }
}

/// Refuses access before choosing an authentication scheme when no account was supplied.
fn required_credential(credential: Option<&Secret>) -> Result<&Secret, ActionOutcome> {
    credential
        .ok_or_else(|| failed("the operation acts through an account, and none was handed over"))
}

/// The reach of a key account: a bare key in the first region, or a key
/// naming its region and, when limited, its place.
fn key(
    regions: &Regions,
    user: &str,
    limited: Option<&LimitedProbe>,
    credential: &Secret,
) -> Result<Reached, ActionOutcome> {
    let held = credential.expose().trim();
    if !held.starts_with('{') {
        return Ok(Reached {
            endpoint: regions.endpoint(None).cloned().ok_or_else(no_region)?,
            authorization: basic(user, held)?,
            place: None,
            acting_for: None,
            renewed: Renewed::Unchanged,
        });
    }
    let Ok(account) = serde_json::from_str::<KeyAccount>(held) else {
        return Err(failed("the account holds no key"));
    };
    let Some(endpoint) = regions.endpoint(account.region.as_deref()) else {
        return Err(no_region());
    };
    Ok(Reached {
        endpoint: endpoint.clone(),
        authorization: basic(user, &account.key)?,
        place: limited_place(limited, &account.rest)?,
        acting_for: None,
        renewed: Renewed::Unchanged,
    })
}

/// The place a limited key names under the probe's field. Anything else
/// the account holds is refused, so a misspelt field never passes for a
/// key that is not limited.
fn limited_place(
    limited: Option<&LimitedProbe>,
    rest: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<String>, ActionOutcome> {
    let field = limited.map(|limited| limited.field);
    if rest.keys().any(|name| Some(name.as_str()) != field) {
        return Err(failed(
            "the account holds something this service does not take",
        ));
    }
    let Some(place) = field.and_then(|field| rest.get(field)) else {
        return Ok(None);
    };
    let Some(place) = place
        .as_str()
        .map(str::trim)
        .filter(|place| !place.is_empty())
    else {
        return Err(failed("the account's place is not text"));
    };
    Ok(Some(place.to_owned()))
}

/// The refusal for a region the service does not have.
fn no_region() -> ActionOutcome {
    failed("the account names a region this service does not have")
}

/// The reach of an Azure DevOps account.
fn organization(base: &ServiceEndpoint, credential: &Secret) -> Result<Reached, ActionOutcome> {
    let Ok(account) = serde_json::from_str::<OrganizationAccount>(credential.expose()) else {
        return Err(failed("the account holds no organization and token"));
    };
    let url = base.url(&[account.organization.trim()])?;
    Ok(Reached {
        endpoint: endpoint_at(url.as_str())?,
        authorization: basic("", &account.token)?,
        place: None,
        acting_for: None,
        renewed: Renewed::Unchanged,
    })
}

/// The reach of an Azure DevOps account: through its grant when it signed
/// in and the deployment lets people, or else its organization and token.
async fn organization_reach(
    client: &reqwest::Client,
    base: &ServiceEndpoint,
    signed_in: Option<&GrantAt>,
    credential: &Secret,
) -> Result<Reached, ActionOutcome> {
    let Some(grant) = signed_in.filter(|_| holds_grant(credential)) else {
        return organization(base, credential);
    };
    let organization = held_place(credential)?
        .organization
        .ok_or_else(|| failed("the account names no organization"))?;
    let url = base.url(&[organization.trim()])?;
    let exchanged = exchanged(client, grant, credential).await?;
    Ok(Reached {
        endpoint: endpoint_at(url.as_str())?,
        authorization: bearer(&exchanged.access_token)?,
        place: None,
        acting_for: None,
        renewed: exchanged.renewed,
    })
}

/// The reach of an account holding a token, or a grant when it signed in.
async fn bearer_or_grant(
    client: &reqwest::Client,
    endpoint: &ServiceEndpoint,
    signed_in: &GrantAt,
    credential: &Secret,
) -> Result<Reached, ActionOutcome> {
    if !holds_grant(credential) {
        return Ok(token_at(endpoint, bearer(credential.expose())?));
    }
    let exchanged = exchanged(client, signed_in, credential).await?;
    Ok(Reached {
        endpoint: endpoint.clone(),
        authorization: bearer(&exchanged.access_token)?,
        place: None,
        acting_for: None,
        renewed: exchanged.renewed,
    })
}

/// The reach of a token sent after `scheme`.
fn schemed(
    endpoint: &ServiceEndpoint,
    scheme: &str,
    credential: &Secret,
) -> Result<Reached, ActionOutcome> {
    Ok(token_at(
        endpoint,
        after_scheme(scheme, credential.expose())?,
    ))
}

/// The reach of a key held alone, or with the email address of the person
/// its changes are made for, sent in `From`.
fn acting_for(
    endpoint: &ServiceEndpoint,
    scheme: &str,
    credential: &Secret,
) -> Result<Reached, ActionOutcome> {
    let Ok(account) = serde_json::from_str::<ActingAccount>(credential.expose()) else {
        return Ok(token_at(
            endpoint,
            after_scheme(scheme, credential.expose())?,
        ));
    };
    let from = account.from.trim();
    if !from.contains('@') {
        return Err(failed(
            "the account's person to act for is no email address",
        ));
    }
    let Ok(acting_for) = HeaderValue::from_str(from) else {
        return Err(failed(
            "the account's person to act for is no email address",
        ));
    };
    Ok(Reached {
        acting_for: Some(acting_for),
        ..token_at(endpoint, after_scheme(scheme, &account.token)?)
    })
}

/// Whether `credential` holds a grant, as an account that signed in does.
fn holds_grant(credential: &Secret) -> bool {
    serde_json::from_str::<serde_json::Value>(credential.expose())
        .is_ok_and(|held| held.get("refresh_token").is_some())
}

/// What a signed-in account keeps beside its grant.
fn held_place(credential: &Secret) -> Result<GrantPlace, ActionOutcome> {
    serde_json::from_str::<GrantPlace>(credential.expose())
        .map_err(|_| failed("the account holds no grant"))
}

/// The reach of a Twilio account, signed by its key when it holds one.
fn account(base: &ServiceEndpoint, credential: &Secret) -> Result<Reached, ActionOutcome> {
    let Ok(account) = serde_json::from_str::<ServiceAccount>(credential.expose()) else {
        return Err(failed("the account holds no account id and token"));
    };
    let id = account.account.trim();
    let url = base.url(&[id])?;
    let user = account.key.as_deref().map_or(id, str::trim);
    Ok(Reached {
        endpoint: endpoint_at(url.as_str())?,
        authorization: basic(user, &account.token)?,
        place: None,
        acting_for: None,
        renewed: Renewed::Unchanged,
    })
}

/// The reach of a Telegram bot: its token after `prefix` as the address's
/// first part under `endpoint`, refused when blank or holding anything but
/// letters, digits, `:`, `_` and `-`.
fn in_path(
    endpoint: &ServiceEndpoint,
    prefix: &str,
    credential: &Secret,
) -> Result<Reached, ActionOutcome> {
    let token = credential.expose().trim();
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-');
    if token.is_empty() || !token.chars().all(plain) {
        return Err(failed(
            "the account's token must be letters, digits, colons, underscores and dashes",
        ));
    }
    let url = endpoint.url(&[format!("{prefix}{token}").as_str()])?;
    Ok(Reached {
        endpoint: endpoint_at(url.as_str())?,
        authorization: None,
        place: None,
        acting_for: None,
        renewed: Renewed::Unchanged,
    })
}

/// The service endpoint at `address`.
fn endpoint_at(address: &str) -> Result<ServiceEndpoint, ActionOutcome> {
    ServiceEndpoint::at(address).map_err(|_| failed("the account's address cannot be reached"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use wiremock::matchers::{body_string, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::rest::sign_in::TokenBody;

    fn jira() -> Access {
        Access::Site {
            sites: AllowedSites::new([".atlassian.net"]),
            api: &["rest", "api", "3"],
            cloud: None,
        }
    }

    fn secret(value: &str) -> Secret {
        Secret::new(value.to_owned())
    }

    /// The header `reached` signs its calls with.
    fn signed(reached: &Reached) -> HeaderValue {
        reached.authorization.clone().unwrap()
    }

    async fn reach(access: &Access, credential: Option<&Secret>) -> Result<Reached, ActionOutcome> {
        let client = crate::client(Duration::from_secs(2)).unwrap();
        access.reach(&client, credential).await
    }

    /// A token alone reaches the fixed endpoint as `Bearer`.
    #[tokio::test]
    async fn a_token_reaches_its_endpoint_as_bearer() {
        let access = Access::Bearer {
            endpoint: ServiceEndpoint::at("https://api.github.com/").unwrap(),
        };

        let reached = reach(&access, Some(&secret("test token"))).await.unwrap();

        assert_eq!(signed(&reached), "Bearer test token");
        assert!(signed(&reached).is_sensitive());
    }

    /// A bot's token goes after Discord's `Bot ` and a bare key goes as it
    /// is, both marked sensitive.
    #[tokio::test]
    async fn a_token_goes_after_its_scheme() {
        let discord = Access::Scheme {
            endpoint: ServiceEndpoint::at("https://discord.com/api/v10/").unwrap(),
            scheme: "Bot ",
        };
        let linear = Access::Scheme {
            endpoint: ServiceEndpoint::at("https://api.linear.app/").unwrap(),
            scheme: "",
        };

        let bot = reach(&discord, Some(&secret("bot token"))).await.unwrap();
        let key = reach(&linear, Some(&secret("lin key"))).await.unwrap();

        assert_eq!(signed(&bot), "Bot bot token");
        assert_eq!(signed(&key), "lin key");
        assert!(signed(&bot).is_sensitive());
    }

    /// A Trello key and token form one `OAuth` header; a token containing
    /// quotes is refused instead of becoming part of that header.
    #[tokio::test]
    async fn a_key_and_token_go_in_one_header() {
        let trello = Access::KeyAndToken {
            endpoint: ServiceEndpoint::at("https://api.trello.com/1/").unwrap(),
        };

        let reached = reach(
            &trello,
            Some(&secret(r#"{"key":"abc123","token":"def456"}"#)),
        )
        .await
        .unwrap();
        let crooked = reach(
            &trello,
            Some(&secret(r#"{"key":"abc","token":"x\", y=\"z"}"#)),
        )
        .await;

        assert_eq!(
            signed(&reached),
            r#"OAuth oauth_consumer_key="abc123", oauth_token="def456""#
        );
        assert!(crooked.is_err());
    }

    fn mailgun() -> Access {
        Access::Key {
            regions: Regions::new(
                (
                    "us",
                    ServiceEndpoint::at("https://api.mailgun.net/").unwrap(),
                ),
                [(
                    "eu",
                    ServiceEndpoint::at("https://api.eu.mailgun.net/").unwrap(),
                )],
            ),
            user: "api",
            limited: Some(LimitedProbe {
                field: "domain",
                verb: Verb::Post,
                before: &["v3"],
                after: &["messages"],
                taken: 400,
            }),
        }
    }

    /// A bare Mailgun key goes to the first region as the password of the
    /// user `api`.
    #[tokio::test]
    async fn a_bare_key_goes_to_the_first_region_as_its_users_password() {
        let reached = reach(&mailgun(), Some(&secret("test key"))).await.unwrap();

        assert_eq!(reached.endpoint.base().as_str(), "https://api.mailgun.net/");
        assert_eq!(
            signed(&reached),
            format!("Basic {}", STANDARD.encode("api:test key"))
        );
        assert!(signed(&reached).is_sensitive());
        assert_eq!(reached.place, None);
    }

    /// A key naming the EU region goes there, and one limited to sending
    /// from a domain says which.
    #[tokio::test]
    async fn a_key_reaches_its_region_and_names_its_place() {
        let european = secret(r#"{"key": "test key", "region": "EU"}"#);
        let limited = secret(r#"{"key": "test key", "region": "eu", "domain": "mail.acme.test"}"#);

        let in_europe = reach(&mailgun(), Some(&european)).await.unwrap();
        let sending = reach(&mailgun(), Some(&limited)).await.unwrap();

        assert_eq!(
            in_europe.endpoint.base().as_str(),
            "https://api.eu.mailgun.net/"
        );
        assert_eq!(in_europe.place, None);
        assert_eq!(sending.place.as_deref(), Some("mail.acme.test"));
    }

    /// Key accounts with an unknown region, misspelled field, non-text
    /// domain or missing key fail credential validation.
    #[tokio::test]
    async fn an_unknown_region_or_field_is_refused() {
        for held in [
            r#"{"key": "test key", "region": "ap"}"#,
            r#"{"key": "test key", "domian": "mail.acme.test"}"#,
            r#"{"key": "test key", "domain": 7}"#,
            r#"{"region": "eu"}"#,
        ] {
            assert!(
                reach(&mailgun(), Some(&secret(held))).await.is_err(),
                "{held}"
            );
        }
    }

    fn twilio() -> Access {
        Access::Account {
            base: ServiceEndpoint::at("https://api.twilio.com/2010-04-01/Accounts").unwrap(),
        }
    }

    /// A Twilio account reaches its own place under the API, signed by its
    /// id and token, or by its API key and secret when it holds a key.
    #[tokio::test]
    async fn a_service_account_reaches_its_place_signed_by_key_or_account() {
        let own = secret(r#"{"account": "AC1", "token": "auth token"}"#);
        let keyed = secret(r#"{"account": "AC1", "key": "SK1", "token": "key secret"}"#);

        let by_account = reach(&twilio(), Some(&own)).await.unwrap();
        let by_key = reach(&twilio(), Some(&keyed)).await.unwrap();

        assert_eq!(
            by_account.endpoint.base().as_str(),
            "https://api.twilio.com/2010-04-01/Accounts/AC1"
        );
        assert_eq!(
            signed(&by_account),
            format!("Basic {}", STANDARD.encode("AC1:auth token"))
        );
        assert_eq!(
            signed(&by_key),
            format!("Basic {}", STANDARD.encode("SK1:key secret"))
        );
    }

    /// A grant the account holds.
    fn grant() -> Secret {
        secret(
            r#"{"client_id": "ann app", "client_secret": "app words", "refresh_token": "lasting grant"}"#,
        )
    }

    fn google(token: &MockServer) -> Access {
        Access::Refreshed {
            endpoint: ServiceEndpoint::at("https://www.googleapis.com/calendar/v3/").unwrap(),
            token: ServiceEndpoint::at(&format!("{}/token", token.uri())).unwrap(),
        }
    }

    /// A Google grant is exchanged at the token address, and the token it
    /// issues signs the call as `Bearer`.
    #[tokio::test]
    async fn a_grant_is_exchanged_for_a_short_lived_token() {
        let token = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string(
                "grant_type=refresh_token&client_id=ann+app&client_secret=app+words&refresh_token=lasting+grant",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "short token",
                "token_type": "Bearer",
                "expires_in": 3599
            })))
            .expect(1)
            .mount(&token)
            .await;

        let reached = reach(&google(&token), Some(&grant())).await.unwrap();

        assert_eq!(signed(&reached), "Bearer short token");
        assert!(signed(&reached).is_sensitive());
    }

    /// A rejected grant fails and a busy token endpoint turns the call
    /// away. A bare token fails without contacting the token endpoint.
    #[tokio::test]
    async fn a_refused_grant_fails_and_a_busy_token_address_turns_away() {
        let refusing = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({ "error": "invalid_grant" })),
            )
            .mount(&refusing)
            .await;
        let busy = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&busy)
            .await;
        let silent = MockServer::start().await;

        let refused = reach(&google(&refusing), Some(&grant())).await;
        let turned = reach(&google(&busy), Some(&grant())).await;
        let empty = reach(&google(&silent), Some(&secret("just a token"))).await;

        assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
        assert!(matches!(turned, Err(ActionOutcome::TurnedAway(_))));
        assert!(matches!(empty, Err(ActionOutcome::Failed(_))));
        assert_eq!(silent.received_requests().await.unwrap().len(), 0);
    }

    fn telegram() -> Access {
        Access::PathToken {
            endpoint: ServiceEndpoint::at("https://api.telegram.org/").unwrap(),
            prefix: "bot",
        }
    }

    /// A bot's token goes in the address after `bot`, and no header is
    /// sent.
    #[tokio::test]
    async fn a_path_token_is_part_of_the_address() {
        let reached = reach(&telegram(), Some(&secret("123456:ABC-def_ghi")))
            .await
            .unwrap();

        assert_eq!(
            reached.endpoint.base().as_str(),
            "https://api.telegram.org/bot123456:ABC-def_ghi"
        );
        assert!(reached.authorization.is_none());
    }

    /// Blank path tokens and tokens containing a traversal or query are
    /// refused when resolving service access.
    #[tokio::test]
    async fn a_crooked_path_token_is_refused() {
        for crooked in ["123/../admin", "123?x=1", "  "] {
            let reached = reach(&telegram(), Some(&secret(crooked))).await;

            assert!(
                matches!(reached, Err(ActionOutcome::Failed(_))),
                "{crooked}"
            );
        }
    }

    fn salesforce(token: &MockServer) -> Access {
        Access::SiteGrant {
            sites: AllowedSites::new([".my.salesforce.com"]),
            api: &["services", "data", "v62.0"],
            token: ServiceEndpoint::at(&format!("{}/token", token.uri())).unwrap(),
        }
    }

    /// Acme's Salesforce account names its own domain: the grant is
    /// exchanged at the deployment's token address, and only the token
    /// goes to the domain's API.
    #[tokio::test]
    async fn a_site_grant_reaches_its_own_domain_with_the_token() {
        let token = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "access_token": "short token" })),
            )
            .expect(1)
            .mount(&token)
            .await;
        let held = secret(
            r#"{"site": "https://acme.my.salesforce.com", "client_id": "acme app", "client_secret": "app words", "refresh_token": "lasting grant"}"#,
        );

        let reached = reach(&salesforce(&token), Some(&held)).await.unwrap();

        assert_eq!(
            reached.endpoint.base().as_str(),
            "https://acme.my.salesforce.com/services/data/v62.0"
        );
        assert_eq!(signed(&reached), "Bearer short token");
    }

    /// A Salesforce grant naming a disallowed domain fails without a
    /// request to the token endpoint.
    #[tokio::test]
    async fn a_site_grant_for_another_domain_sends_nothing() {
        let token = MockServer::start().await;
        let held = secret(
            r#"{"site": "https://salesforce.evil.test", "client_id": "app", "client_secret": "words", "refresh_token": "grant"}"#,
        );

        let reached = reach(&salesforce(&token), Some(&held)).await;

        assert!(matches!(reached, Err(ActionOutcome::Failed(_))));
        assert_eq!(token.received_requests().await.unwrap().len(), 0);
    }

    /// An Azure DevOps account reaches its organization, with the token as
    /// a password and no user name.
    #[tokio::test]
    async fn an_organization_account_reaches_its_organization() {
        let access = Access::Organization {
            base: ServiceEndpoint::at("https://dev.azure.com/").unwrap(),
            signed_in: None,
        };
        let account = secret(r#"{"organization": "acme", "token": "pat"}"#);

        let reached = reach(&access, Some(&account)).await.unwrap();

        assert_eq!(
            reached.endpoint.base().as_str(),
            "https://dev.azure.com/acme"
        );
        assert_eq!(
            signed(&reached),
            format!("Basic {}", STANDARD.encode(":pat"))
        );
    }

    /// A Jira account reaches its own site's API with its user and token.
    #[tokio::test]
    async fn a_site_account_reaches_its_allowed_site() {
        let account = secret(
            r#"{"site": "https://acme.atlassian.net", "user": "ann@acme.test", "token": "tok"}"#,
        );

        let reached = reach(&jira(), Some(&account)).await.unwrap();

        assert_eq!(
            reached.endpoint.base().as_str(),
            "https://acme.atlassian.net/rest/api/3"
        );
        assert_eq!(
            signed(&reached),
            format!("Basic {}", STANDARD.encode("ann@acme.test:tok"))
        );
    }

    /// Jira access refuses disallowed or look-alike hosts, plain HTTP,
    /// embedded credentials and a missing account credential.
    #[tokio::test]
    async fn a_site_the_deployment_does_not_allow_is_refused() {
        for site in [
            "https://evil.example.test",
            "http://acme.atlassian.net",
            "https://acme.atlassian.net.evil.test",
            "https://atlassian.net",
            "https://user:pw@acme.atlassian.net",
        ] {
            let account = secret(&format!(
                r#"{{"site": "{site}", "user": "u", "token": "t"}}"#
            ));
            assert!(reach(&jira(), Some(&account)).await.is_err(), "{site}");
        }
        assert!(reach(&jira(), None).await.is_err());
    }

    /// Blank tokens, malformed account credentials and dot-segment
    /// organization or account identifiers fail access resolution.
    #[tokio::test]
    async fn a_blank_or_malformed_credential_is_refused() {
        let bearer = Access::Bearer {
            endpoint: ServiceEndpoint::at("https://api.github.com/").unwrap(),
        };
        let azure = Access::Organization {
            base: ServiceEndpoint::at("https://dev.azure.com/").unwrap(),
            signed_in: None,
        };

        for (access, credential) in [
            (&bearer, "  "),
            (&azure, "just a token"),
            (&azure, r#"{"organization": "..", "token": "t"}"#),
            (&twilio(), r#"{"account": "..", "token": "t"}"#),
            (&twilio(), r#"{"account": "AC1", "token": " "}"#),
        ] {
            assert!(
                reach(access, Some(&secret(credential))).await.is_err(),
                "{credential}"
            );
        }
    }

    /// A token address issuing an hour's token and a new refresh token.
    async fn rotating(server: &wiremock::MockServer) -> GrantAt {
        wiremock::Mock::given(wiremock::matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "an hour's token", "refresh_token": "the next grant"
                })),
            )
            .mount(server)
            .await;
        GrantAt {
            token: ServiceEndpoint::at(&format!("{}/token", server.uri())).unwrap(),
            body: TokenBody::Json,
            scope: None,
        }
    }

    /// Tess signed in at Atlassian for acme.atlassian.net: her account
    /// reaches the site through the gateway under its cloud id, with an
    /// exchanged token, and keeps the refresh token Atlassian replaced.
    #[tokio::test]
    async fn a_signed_in_jira_account_goes_through_the_gateway() {
        let server = wiremock::MockServer::start().await;
        let access = Access::Site {
            sites: AllowedSites::new([".atlassian.net"]),
            api: &["rest", "api", "3"],
            cloud: Some(AtlassianCloud {
                gateway: ServiceEndpoint::at("https://api.atlassian.com/").unwrap(),
                grant: rotating(&server).await,
            }),
        };
        let account = secret(
            r#"{"cloud_id": "c1", "client_id": "a", "client_secret": "s", "refresh_token": "r"}"#,
        );

        let reached = reach(&access, Some(&account)).await.unwrap();

        assert_eq!(
            reached.endpoint.base().as_str(),
            "https://api.atlassian.com/ex/jira/c1/rest/api/3"
        );
        assert_eq!(signed(&reached), "Bearer an hour's token");
        assert!(matches!(reached.renewed, Renewed::To(_)));
    }

    /// A GitLab account that signed in reaches the API with a token its
    /// grant was exchanged for; one holding a pasted access token sends it
    /// as it is, and asks the token address nothing.
    #[tokio::test]
    async fn a_gitlab_account_uses_its_token_or_its_grant() {
        let server = wiremock::MockServer::start().await;
        let access = Access::BearerOrGrant {
            endpoint: ServiceEndpoint::at("https://gitlab.com/api/v4/").unwrap(),
            signed_in: rotating(&server).await,
        };
        let signed_in = secret(r#"{"client_id": "a", "client_secret": "s", "refresh_token": "r"}"#);
        let pasted = secret("a pasted token");

        let granted = reach(&access, Some(&signed_in)).await.unwrap();
        let kept = reach(&access, Some(&pasted)).await.unwrap();

        assert_eq!(signed(&granted), "Bearer an hour's token");
        assert!(matches!(granted.renewed, Renewed::To(_)));
        assert_eq!(signed(&kept), "Bearer a pasted token");
        assert!(matches!(kept.renewed, Renewed::Unchanged));
    }

    /// An Azure DevOps account that signed in reaches its organization with
    /// an exchanged token; one holding a personal access token still
    /// reaches it as before.
    #[tokio::test]
    async fn a_signed_in_azure_account_uses_its_grant() {
        let server = wiremock::MockServer::start().await;
        let access = Access::Organization {
            base: ServiceEndpoint::at("https://dev.azure.com/").unwrap(),
            signed_in: Some(rotating(&server).await),
        };
        let signed_in = secret(
            r#"{"organization": "contoso", "client_id": "a", "client_secret": "s", "refresh_token": "r"}"#,
        );
        let pasted = secret(r#"{"organization": "contoso", "token": "pat"}"#);

        let granted = reach(&access, Some(&signed_in)).await.unwrap();
        let kept = reach(&access, Some(&pasted)).await.unwrap();

        assert_eq!(
            granted.endpoint.base().as_str(),
            "https://dev.azure.com/contoso"
        );
        assert_eq!(signed(&granted), "Bearer an hour's token");
        assert!(matches!(kept.renewed, Renewed::Unchanged));
    }
}
