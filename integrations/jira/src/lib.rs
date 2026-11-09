//! Jira as a workflow integration, installed under `jira`: a step creates,
//! reads, edits, deletes, comments on, moves and assigns issues, searches
//! with JQL and finds people, through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A Jira
//! account names its own site, so it holds `{"site", "user", "token"}`:
//! the site, such as `https://acme.atlassian.net`, and the email and API
//! token signing its calls. The site must be one the deployment allows,
//! `.atlassian.net` by default, so a token is never sent to a server an
//! account chose. Calls go to Jira's REST API version 2, which takes
//! descriptions and comments as plain text.
//!
//! With the deployment's Atlassian app set, a person connects an account by
//! signing in at Atlassian instead, naming their site; the account keeps
//! the site's cloud id beside a grant, and reaches the site through
//! Atlassian's gateway with a token exchanged before each call, keeping
//! the refresh token Atlassian replaces each time. A workflow may also
//! start when an issue is created or updated in a project (`events`),
//! through a webhook only a signed-in account may register.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod events;
mod operations;
mod sign_in;

use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::form::{PreviewKind, PreviewPart};
use ianua_domain::shared::errors::DomainError;
use ianua_integration::ServiceEndpoint;
use ianua_integration::connect::SignIn;
use ianua_integration::describe::ProfileText;
use ianua_integration::form::PreviewText;
use ianua_integration::rest::access::{Access, AllowedSites, AtlassianCloud};
use ianua_integration::rest::event::ServiceEvents;
use ianua_integration::rest::grant::GrantAt;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};
use ianua_integration::rest::sign_in::{
    Keeps, OAuthSignIn, OAuthSignInParams, SignInSettings, TokenBody,
};
use ianua_integration::rest::watch::WatchCalls;

use crate::events::Webhooks;
use crate::sign_in::CloudSignIn;

/// Where Jira's REST API sits under a site.
const API: &[&str] = &["rest", "api", "2"];

/// The headers every call carries.
const HEADERS: &[(&str, &str)] = &[("accept", "application/json")];

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Jira",
    description: "Creates, updates, moves and searches issues in a team's Jira site, through an email and API token the tenant connects.",
    icon: "jira",
    picture: include_str!("../assets/icon.svg"),
    brand: "0052cc",
};

/// How creating an issue is previewed: as Jira shows one.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "create-issue",
    kind: PreviewKind::Issue,
    parts: &[
        (PreviewPart::Place, "project"),
        (PreviewPart::Title, "summary"),
        (PreviewPart::Body, "description"),
        (PreviewPart::Labels, "labels"),
    ],
}];

/// How the Jira integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct JiraSettings {
    /// The sites an account may name, such as `.atlassian.net`, or a
    /// company's own Jira server.
    pub sites: AllowedSites,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send to Jira, and so the most
    /// sensitive an answer or an event is counted as.
    pub ceiling: DataClassLevel,
    /// The deployment's app at Atlassian, at [`PUBLIC_AUTHORIZE`] and
    /// [`PUBLIC_TOKEN`] or a stand-in's, when one is registered; without
    /// it, accounts are connected with an email and API token pasted in.
    pub sign_in: Option<SignInSettings>,
    /// Atlassian's gateway signed-in accounts reach their site through:
    /// `https://api.atlassian.com/`, or a stand-in's.
    pub gateway: ServiceEndpoint,
}

/// Where Atlassian signs people in.
pub const PUBLIC_AUTHORIZE: &str = "https://auth.atlassian.com/authorize";

/// Where Atlassian swaps codes and exchanges grants.
pub const PUBLIC_TOKEN: &str = "https://auth.atlassian.com/oauth/token";

/// The scopes a signed-in account is granted: reading and changing work
/// and people for the steps, managing webhooks for the events, and a grant
/// that lasts.
const SCOPES: &[&str] = &[
    "read:jira-work",
    "write:jira-work",
    "read:jira-user",
    "manage:jira-webhook",
    "offline_access",
];

/// What Atlassian's authorize address carries besides the usual: the API
/// the grant is for, and asking for consent every time.
const AUTHORIZE_EXTRA: &[(&str, &str)] =
    &[("audience", "api.atlassian.com"), ("prompt", "consent")];

/// The Jira integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: JiraSettings) -> Result<RestService, DomainError> {
    let cloud = cloud_access(settings.sign_in.as_ref(), &settings.gateway);
    let access = Access::Site {
        sites: settings.sites,
        api: API,
        cloud,
    };
    let events = service_events(&access, settings.timeout, settings.ceiling)?;
    let sign_in = settings
        .sign_in
        .map(|at| sign_in(at, &settings.gateway, settings.timeout))
        .transpose()?;
    RestService::new(RestServiceParams {
        key: "jira",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access,
        headers: HEADERS,
        probe: Probe {
            verb: Verb::Get,
            path: &["myself"],
            query: &[],
        },
        answers: Answers::ByStatus,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in,
        events: Some(events),
    })
}

/// Enables gateway access only when the deployment has configured Atlassian sign-in.
fn cloud_access(at: Option<&SignInSettings>, gateway: &ServiceEndpoint) -> Option<AtlassianCloud> {
    at.map(|at| AtlassianCloud {
        gateway: gateway.clone(),
        grant: GrantAt {
            token: at.token.clone(),
            body: TokenBody::Json,
            scope: None,
        },
    })
}

/// Describes Jira events and builds their webhook client with the same account access.
fn service_events(
    access: &Access,
    timeout: Duration,
    ceiling: DataClassLevel,
) -> Result<ServiceEvents, DomainError> {
    let webhooks = Webhooks::new(WatchCalls::new(access.clone(), HEADERS, timeout)?, ceiling);
    Ok(ServiceEvents {
        described: events::all(),
        watcher: Box::new(webhooks),
    })
}

/// Signing in at Atlassian through the deployment's app `at`, finding the
/// named site's cloud id through `gateway`.
fn sign_in(
    at: SignInSettings,
    gateway: &ServiceEndpoint,
    timeout: Duration,
) -> Result<Box<dyn SignIn>, DomainError> {
    let oauth = OAuthSignIn::new(OAuthSignInParams {
        at,
        scopes: SCOPES,
        scope_separator: " ",
        extra: AUTHORIZE_EXTRA,
        swap_extra: &[],
        token_body: TokenBody::Json,
        keeps: Keeps::RefreshGrant,
        place: None,
        timeout,
    })?;
    Ok(Box::new(CloudSignIn::new(oauth, gateway, timeout)?))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_integration::Integration;
    use ianua_integration::rest::openapi::Description;

    use super::*;
    use crate::operations::all;

    /// The sites the test deployment allows a connected account to name.
    const CLOUD_SITES: &str = ".atlassian.net";

    /// The gateway used when describing Jira without a stand-in server.
    const PUBLIC_GATEWAY: &str = "https://api.atlassian.com/";

    /// Atlassian's own description of Jira's REST API version 2, which
    /// every operation is checked against. Atlassian publishes it at
    /// `https://developer.atlassian.com/cloud/jira/platform/swagger.v3.json`;
    /// what the operations use of it is kept in `api-description.json`. To
    /// refresh it, download the file and run the tests with
    /// `IANUA_JIRA_API_DESCRIPTION=/path/to/swagger.v3.json`. Its paths start
    /// with the API's place under a site, which the account's address holds.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_JIRA_API_DESCRIPTION",
            lead: API,
        }
    }

    /// Every operation calls an endpoint Jira describes, with only the
    /// parameters and body properties it knows, always sending those it
    /// requires, and promising only outputs and statuses its answer
    /// carries; and the extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_jiras_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_JIRA_API_DESCRIPTION"
        );
    }

    fn jira() -> RestService {
        integration(JiraSettings {
            sites: AllowedSites::new([CLOUD_SITES]),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
            sign_in: None,
            gateway: ServiceEndpoint::at(PUBLIC_GATEWAY).unwrap(),
        })
        .unwrap()
    }

    /// A site outside the allowed Jira Cloud suffix refuses the account
    /// check.
    #[tokio::test]
    async fn an_account_on_a_site_not_allowed_is_refused() {
        let account = Secret::new(
            r#"{"site": "https://jira.evil.example", "user": "ann@acme.test", "token": "t"}"#
                .to_owned(),
        );

        let answer = jira().check_account(&account).await;

        assert!(matches!(answer, AccountCheck::Refused(_)), "{answer:?}");
    }

    /// Jira presents itself with a title and icon, and explains every
    /// operation.
    #[test]
    fn jira_presents_itself_and_explains_its_operations() {
        let jira = jira();

        assert_eq!(jira.profile().icon().as_str(), "jira");
        assert_eq!(jira.guides().len(), jira.operations().len());
    }
}
