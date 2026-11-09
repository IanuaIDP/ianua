//! The outside services workflow steps call through a tenant's accounts:
//! where each one's API answers, how long a call may take, and the most
//! sensitive data a step may send it.

use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::ServiceEndpoint;
use ianua_integration::rest::sign_in::{OAuthApp, SignInSettings};

/// GitHub's public API.
const GITHUB_PUBLIC_API: &str = "https://api.github.com/";

/// Where GitHub signs people in and swaps codes for its OAuth apps.
const GITHUB_SIGN_IN: PublicSignIn = PublicSignIn {
    prefix: "GITHUB",
    authorize: "https://github.com/login/oauth/authorize",
    token: "https://github.com/login/oauth/access_token",
};

/// Slack's public Web API.
const SLACK_PUBLIC_API: &str = "https://slack.com/api/";

/// Where Slack signs people in and swaps codes for its apps.
const SLACK_SIGN_IN: PublicSignIn = PublicSignIn {
    prefix: "SLACK",
    authorize: "https://slack.com/oauth/v2/authorize",
    token: "https://slack.com/api/oauth.v2.access",
};

/// Azure DevOps' public address, before an organization's name.
const AZURE_DEVOPS_PUBLIC_API: &str = "https://dev.azure.com/";

/// Mailgun's public API in the US.
const MAILGUN_PUBLIC_API: &str = "https://api.mailgun.net/";

/// Mailgun's public API in the EU.
const MAILGUN_PUBLIC_EU_API: &str = "https://api.eu.mailgun.net/";

/// Twilio's public API.
const TWILIO_PUBLIC_API: &str = "https://api.twilio.com/";

/// Google Calendar's public API.
const GOOGLE_CALENDAR_PUBLIC_API: &str = "https://www.googleapis.com/calendar/v3/";

/// Google Sheets' public API.
const GOOGLE_SHEETS_PUBLIC_API: &str = "https://sheets.googleapis.com/v4/";

/// Gmail's public API.
const GMAIL_PUBLIC_API: &str = "https://gmail.googleapis.com/gmail/v1/";

/// GitLab.com's API.
const GITLAB_PUBLIC_API: &str = "https://gitlab.com/api/v4/";

/// Linear's public API, under which its GraphQL endpoint answers.
const LINEAR_PUBLIC_API: &str = "https://api.linear.app/";

/// Asana's public API.
const ASANA_PUBLIC_API: &str = "https://app.asana.com/api/1.0/";

/// Trello's public API.
const TRELLO_PUBLIC_API: &str = "https://api.trello.com/1/";

/// ClickUp's public API.
const CLICKUP_PUBLIC_API: &str = "https://api.clickup.com/api/v2/";

/// Microsoft Graph, which Teams is reached through.
const TEAMS_PUBLIC_API: &str = "https://graph.microsoft.com/v1.0/";

/// Microsoft's token address for any work or school directory, where a
/// Teams account's grant is exchanged for a token.
const MICROSOFT_PUBLIC_TOKEN: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

/// Discord's public API.
const DISCORD_PUBLIC_API: &str = "https://discord.com/api/v10/";

/// Notion's public API.
const NOTION_PUBLIC_API: &str = "https://api.notion.com/v1/";

/// Airtable's public API.
const AIRTABLE_PUBLIC_API: &str = "https://api.airtable.com/v0/";

/// HubSpot's public API.
const HUBSPOT_PUBLIC_API: &str = "https://api.hubapi.com/";

/// Stripe's public API.
const STRIPE_PUBLIC_API: &str = "https://api.stripe.com/v1/";

/// Telegram's Bot API.
const TELEGRAM_PUBLIC_API: &str = "https://api.telegram.org/";

/// Salesforce's token address, where an account's grant is exchanged.
const SALESFORCE_PUBLIC_TOKEN: &str = "https://login.salesforce.com/services/oauth2/token";

/// The domains a Salesforce account may name when nothing else is set:
/// every company's own Salesforce domain.
const SALESFORCE_DOMAINS: &str = ".my.salesforce.com";

/// PagerDuty's public API.
const PAGERDUTY_PUBLIC_API: &str = "https://api.pagerduty.com/";

/// Google's token address, where an account's grant is exchanged for a
/// token.
const GOOGLE_PUBLIC_TOKEN: &str = "https://oauth2.googleapis.com/token";

/// Where Google signs people in, and swaps codes at the same token address
/// grants are exchanged at.
const GOOGLE_SIGN_IN: PublicSignIn = PublicSignIn {
    prefix: "GOOGLE",
    authorize: "https://accounts.google.com/o/oauth2/v2/auth",
    token: GOOGLE_PUBLIC_TOKEN,
};

/// Where Atlassian signs people in and swaps codes for its apps.
const JIRA_SIGN_IN: PublicSignIn = PublicSignIn {
    prefix: "JIRA",
    authorize: "https://auth.atlassian.com/authorize",
    token: "https://auth.atlassian.com/oauth/token",
};

/// Atlassian's gateway, which signed-in Jira accounts reach their site
/// through.
const JIRA_PUBLIC_GATEWAY: &str = "https://api.atlassian.com/";

/// Where gitlab.com signs people in and swaps codes; a self-managed
/// GitLab names its own with `GITLAB_AUTHORIZE_URL` and `GITLAB_TOKEN_URL`.
const GITLAB_SIGN_IN: PublicSignIn = PublicSignIn {
    prefix: "GITLAB",
    authorize: "https://gitlab.com/oauth/authorize",
    token: "https://gitlab.com/oauth/token",
};

/// Where Microsoft Entra signs people of any work or school directory in,
/// for Azure DevOps.
const AZURE_DEVOPS_SIGN_IN: PublicSignIn = PublicSignIn {
    prefix: "AZURE_DEVOPS",
    authorize: "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
    token: "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
};

/// The sites a Jira account may name when nothing else is set: every Jira
/// Cloud site.
const JIRA_CLOUD_SITES: &str = ".atlassian.net";

/// A Google integration's settings, such as Calendar's or Sheets'.
#[derive(Debug, Clone)]
pub(crate) struct GoogleSettings {
    /// Where its API answers.
    pub endpoint: ServiceEndpoint,
    /// Where an account's grant is exchanged for a token.
    pub token: ServiceEndpoint,
    /// The most sensitive data a step may send it.
    pub ceiling: DataClassLevel,
    /// The deployment's OAuth client at Google, when one is registered.
    pub sign_in: Option<SignInSettings>,
}

/// The Mailgun integration's settings.
#[derive(Debug, Clone)]
pub struct MailgunSettings {
    /// Where its US region answers, for accounts naming no region.
    pub us: ServiceEndpoint,
    /// Where its EU region answers.
    pub eu: ServiceEndpoint,
    /// The most sensitive data a step may send it.
    pub ceiling: DataClassLevel,
}

/// The Jira integration's settings.
#[derive(Debug, Clone)]
pub struct JiraSettings {
    /// The sites an account may name: each an exact host, or `.suffix` for
    /// every host under it.
    pub sites: Vec<String>,
    /// The most sensitive data a step may send it.
    pub ceiling: DataClassLevel,
    /// The deployment's app at Atlassian, when one is registered.
    pub sign_in: Option<SignInSettings>,
    /// Atlassian's gateway, which signed-in accounts reach their site
    /// through.
    pub gateway: ServiceEndpoint,
}

/// The settings of an outside service people may sign in at to connect an
/// account.
#[derive(Debug, Clone)]
pub(crate) struct AppServiceSettings {
    /// Where its API answers.
    pub endpoint: ServiceEndpoint,
    /// The most sensitive data a step may send it.
    pub ceiling: DataClassLevel,
    /// The deployment's app there, when one is registered.
    pub sign_in: Option<SignInSettings>,
}

/// The Slack integration's settings.
#[derive(Debug, Clone)]
pub struct SlackSettings {
    /// Where its Web API answers.
    pub endpoint: ServiceEndpoint,
    /// The most sensitive data a step may send it.
    pub ceiling: DataClassLevel,
    /// The deployment's Slack app, when one is registered.
    pub sign_in: Option<SignInSettings>,
    /// The app's signing secret, which every event is signed with.
    pub signing_secret: Option<Secret>,
}

/// Where one service signs people in when nothing else is set.
struct PublicSignIn {
    /// The settings' first word, such as `GITHUB`.
    prefix: &'static str,
    /// Where the browser is sent.
    authorize: &'static str,
    /// Where the code is swapped.
    token: &'static str,
}

/// One outside service's settings.
#[derive(Debug, Clone)]
pub(crate) struct ServiceSettings {
    /// Where its API answers.
    pub endpoint: ServiceEndpoint,
    /// The most sensitive data a step may send it.
    pub ceiling: DataClassLevel,
}

/// The settings of an outside service whose accounts hold a grant that is
/// exchanged for a token before each call.
#[derive(Debug, Clone)]
pub(crate) struct GrantServiceSettings {
    /// Where its API answers.
    pub endpoint: ServiceEndpoint,
    /// Where an account's grant is exchanged for a token.
    pub token: ServiceEndpoint,
    /// The most sensitive data a step may send it.
    pub ceiling: DataClassLevel,
}

/// The outside services workflow steps call.
#[derive(Debug, Clone)]
pub(crate) struct IntegrationsConfig {
    /// `INTEGRATION_TIMEOUT_SECONDS` (10): one call to any of them.
    pub timeout: Duration,
    /// `GITHUB_API_URL` (`https://api.github.com/`), a GitHub Enterprise
    /// server's API or a stand-in's; `GITHUB_DATA_CEILING` (`internal`);
    /// and the OAuth app people sign in through, `GITHUB_CLIENT_ID` with
    /// `GITHUB_CLIENT_SECRET` (or `_FILE`), at `GITHUB_AUTHORIZE_URL`
    /// (`https://github.com/login/oauth/authorize`) and `GITHUB_TOKEN_URL`
    /// (`https://github.com/login/oauth/access_token`).
    pub github: AppServiceSettings,
    /// `SLACK_API_URL` (`https://slack.com/api/`), or a stand-in's;
    /// `SLACK_DATA_CEILING` (`internal`); the app people sign in through,
    /// `SLACK_CLIENT_ID` with `SLACK_CLIENT_SECRET` (or `_FILE`), at
    /// `SLACK_AUTHORIZE_URL` (`https://slack.com/oauth/v2/authorize`) and
    /// `SLACK_TOKEN_URL` (`https://slack.com/api/oauth.v2.access`); and
    /// `SLACK_SIGNING_SECRET` (or `_FILE`), which offers its events.
    pub slack: SlackSettings,
    /// `AZURE_DEVOPS_API_URL` (`https://dev.azure.com/`), the address
    /// before an organization's name, or a stand-in's;
    /// `AZURE_DEVOPS_DATA_CEILING` (`internal`); and the app in Microsoft
    /// Entra people sign in through, `AZURE_DEVOPS_CLIENT_ID` with
    /// `AZURE_DEVOPS_CLIENT_SECRET` (or `_FILE`), at
    /// `AZURE_DEVOPS_AUTHORIZE_URL` and `AZURE_DEVOPS_TOKEN_URL`
    /// (Microsoft's `organizations` addresses).
    pub azure_devops: AppServiceSettings,
    /// `JIRA_SITES` (`.atlassian.net`), the sites a Jira account may name,
    /// separated by commas, each an exact host or `.suffix`;
    /// `JIRA_DATA_CEILING` (`internal`); the Atlassian app people sign in
    /// through, `JIRA_CLIENT_ID` with `JIRA_CLIENT_SECRET` (or `_FILE`), at
    /// `JIRA_AUTHORIZE_URL` (`https://auth.atlassian.com/authorize`) and
    /// `JIRA_TOKEN_URL` (`https://auth.atlassian.com/oauth/token`); and
    /// `JIRA_GATEWAY_URL` (`https://api.atlassian.com/`), Atlassian's
    /// gateway.
    pub jira: JiraSettings,
    /// `MAILGUN_API_URL` (`https://api.mailgun.net/`) and
    /// `MAILGUN_EU_API_URL` (`https://api.eu.mailgun.net/`), Mailgun's
    /// regions, each account naming its own, or stand-ins'; and
    /// `MAILGUN_DATA_CEILING` (`internal`).
    pub mailgun: MailgunSettings,
    /// `TWILIO_API_URL` (`https://api.twilio.com/`), or a stand-in's; and
    /// `TWILIO_DATA_CEILING` (`internal`).
    pub twilio: ServiceSettings,
    /// `GOOGLE_CALENDAR_API_URL`
    /// (`https://www.googleapis.com/calendar/v3/`), `GOOGLE_TOKEN_URL`
    /// (`https://oauth2.googleapis.com/token`), or stand-ins';
    /// `GOOGLE_CALENDAR_DATA_CEILING` (`internal`); and the OAuth client
    /// people sign in through, `GOOGLE_CLIENT_ID` with
    /// `GOOGLE_CLIENT_SECRET` (or `_FILE`), at `GOOGLE_AUTHORIZE_URL`
    /// (`https://accounts.google.com/o/oauth2/v2/auth`), swapping codes at
    /// `GOOGLE_TOKEN_URL`.
    pub google_calendar: GoogleSettings,
    /// `GOOGLE_SHEETS_API_URL` (`https://sheets.googleapis.com/v4/`), or a
    /// stand-in's; `GOOGLE_SHEETS_DATA_CEILING` (`internal`); and the
    /// token address and OAuth client Google Calendar uses.
    pub google_sheets: GoogleSettings,
    /// `GMAIL_API_URL` (`https://gmail.googleapis.com/gmail/v1/`), or a
    /// stand-in's; `GMAIL_DATA_CEILING` (`internal`); and the token
    /// address and OAuth client Google Calendar uses.
    pub gmail: GoogleSettings,
    /// `GITLAB_API_URL` (`https://gitlab.com/api/v4/`), a self-managed
    /// GitLab's API or a stand-in's; `GITLAB_DATA_CEILING` (`internal`);
    /// and, so people may sign in, `GITLAB_CLIENT_ID` with
    /// `GITLAB_CLIENT_SECRET`, at `GITLAB_AUTHORIZE_URL` and
    /// `GITLAB_TOKEN_URL` (gitlab.com's by default).
    pub gitlab: AppServiceSettings,
    /// `LINEAR_API_URL` (`https://api.linear.app/`), or a stand-in's; and
    /// `LINEAR_DATA_CEILING` (`internal`).
    pub linear: ServiceSettings,
    /// `ASANA_API_URL` (`https://app.asana.com/api/1.0/`), or a
    /// stand-in's; and `ASANA_DATA_CEILING` (`internal`).
    pub asana: ServiceSettings,
    /// `TRELLO_API_URL` (`https://api.trello.com/1/`), or a stand-in's; and
    /// `TRELLO_DATA_CEILING` (`internal`).
    pub trello: ServiceSettings,
    /// `CLICKUP_API_URL` (`https://api.clickup.com/api/v2/`), or a
    /// stand-in's; and `CLICKUP_DATA_CEILING` (`internal`).
    pub clickup: ServiceSettings,
    /// `TEAMS_API_URL` (`https://graph.microsoft.com/v1.0/`) and
    /// `MICROSOFT_TOKEN_URL`
    /// (`https://login.microsoftonline.com/common/oauth2/v2.0/token`), or
    /// stand-ins'; and `TEAMS_DATA_CEILING` (`internal`).
    pub teams: GrantServiceSettings,
    /// `DISCORD_API_URL` (`https://discord.com/api/v10/`), or a
    /// stand-in's; and `DISCORD_DATA_CEILING` (`internal`).
    pub discord: ServiceSettings,
    /// `PAGERDUTY_API_URL` (`https://api.pagerduty.com/`), or a
    /// stand-in's; and `PAGERDUTY_DATA_CEILING` (`internal`).
    pub pagerduty: ServiceSettings,
    /// `NOTION_API_URL` (`https://api.notion.com/v1/`), or a stand-in's;
    /// and `NOTION_DATA_CEILING` (`internal`).
    pub notion: ServiceSettings,
    /// `AIRTABLE_API_URL` (`https://api.airtable.com/v0/`), or a
    /// stand-in's; and `AIRTABLE_DATA_CEILING` (`internal`).
    pub airtable: ServiceSettings,
    /// `HUBSPOT_API_URL` (`https://api.hubapi.com/`), or a stand-in's; and
    /// `HUBSPOT_DATA_CEILING` (`internal`).
    pub hubspot: ServiceSettings,
    /// `STRIPE_API_URL` (`https://api.stripe.com/v1/`), or a stand-in's;
    /// and `STRIPE_DATA_CEILING` (`internal`).
    pub stripe: ServiceSettings,
    /// `SALESFORCE_SITES` (`.my.salesforce.com`), the domains an account may
    /// name, separated by commas; `SALESFORCE_TOKEN_URL`
    /// (`https://login.salesforce.com/services/oauth2/token`), or a
    /// stand-in's; and `SALESFORCE_DATA_CEILING` (`internal`).
    pub salesforce: SiteGrantSettings,
    /// `TELEGRAM_API_URL` (`https://api.telegram.org/`), or a stand-in's;
    /// and `TELEGRAM_DATA_CEILING` (`internal`).
    pub telegram: ServiceSettings,
}

/// The settings of an outside service whose accounts name a site of their
/// own and hold a grant exchanged for a token before each call.
#[derive(Debug, Clone)]
pub(crate) struct SiteGrantSettings {
    /// The sites an account may name: each an exact host, or `.suffix` for
    /// every host under it.
    pub sites: Vec<String>,
    /// Where an account's grant is exchanged for a token.
    pub token: ServiceEndpoint,
    /// The most sensitive data a step may send it.
    pub ceiling: DataClassLevel,
}

impl IntegrationsConfig {
    /// The integration settings `vars` holds, in `environment`.
    ///
    /// # Errors
    ///
    /// An address that is no web address that takes a path, one that is
    /// not `https` in production, or a ceiling that is no data class.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        let read = Services { vars, environment };
        Ok(Self {
            timeout: vars.seconds("INTEGRATION_TIMEOUT_SECONDS", Duration::from_secs(10))?,
            github: read.app(&GITHUB_SIGN_IN, GITHUB_PUBLIC_API)?,
            slack: read.slack()?,
            azure_devops: read.app(&AZURE_DEVOPS_SIGN_IN, AZURE_DEVOPS_PUBLIC_API)?,
            jira: read.jira()?,
            mailgun: read.mailgun()?,
            twilio: service(vars, environment, "TWILIO", TWILIO_PUBLIC_API)?,
            google_calendar: read.google("GOOGLE_CALENDAR", GOOGLE_CALENDAR_PUBLIC_API)?,
            google_sheets: read.google("GOOGLE_SHEETS", GOOGLE_SHEETS_PUBLIC_API)?,
            gmail: read.google("GMAIL", GMAIL_PUBLIC_API)?,
            gitlab: read.app(&GITLAB_SIGN_IN, GITLAB_PUBLIC_API)?,
            linear: service(vars, environment, "LINEAR", LINEAR_PUBLIC_API)?,
            asana: service(vars, environment, "ASANA", ASANA_PUBLIC_API)?,
            trello: service(vars, environment, "TRELLO", TRELLO_PUBLIC_API)?,
            clickup: service(vars, environment, "CLICKUP", CLICKUP_PUBLIC_API)?,
            teams: read.teams()?,
            discord: service(vars, environment, "DISCORD", DISCORD_PUBLIC_API)?,
            pagerduty: service(vars, environment, "PAGERDUTY", PAGERDUTY_PUBLIC_API)?,
            notion: service(vars, environment, "NOTION", NOTION_PUBLIC_API)?,
            airtable: service(vars, environment, "AIRTABLE", AIRTABLE_PUBLIC_API)?,
            hubspot: service(vars, environment, "HUBSPOT", HUBSPOT_PUBLIC_API)?,
            stripe: service(vars, environment, "STRIPE", STRIPE_PUBLIC_API)?,
            salesforce: read.salesforce()?,
            telegram: service(vars, environment, "TELEGRAM", TELEGRAM_PUBLIC_API)?,
        })
    }
}

/// The environment and transport policy used to read each service's settings.
struct Services<'a> {
    vars: &'a Env,
    environment: Environment,
}

impl Services<'_> {
    /// Reads an API and the optional OAuth app used to connect its accounts.
    fn app(&self, public: &PublicSignIn, api: &str) -> Read<AppServiceSettings> {
        let prefix = public.prefix;
        Ok(AppServiceSettings {
            endpoint: endpoint(
                self.vars,
                self.environment,
                &format!("{prefix}_API_URL"),
                api,
            )?,
            ceiling: data_ceiling(self.vars, &format!("{prefix}_DATA_CEILING"))?,
            sign_in: sign_in(self.vars, self.environment, public)?,
        })
    }

    /// Reads Slack's API, OAuth app and optional event-signing secret.
    fn slack(&self) -> Read<SlackSettings> {
        let app = self.app(&SLACK_SIGN_IN, SLACK_PUBLIC_API)?;
        Ok(SlackSettings {
            endpoint: app.endpoint,
            ceiling: app.ceiling,
            sign_in: app.sign_in,
            signing_secret: self.vars.secret("SLACK_SIGNING_SECRET")?,
        })
    }

    /// Reads Jira's permitted sites and the Atlassian app and gateway.
    fn jira(&self) -> Read<JiraSettings> {
        Ok(JiraSettings {
            sites: sites(self.vars, self.environment, "JIRA_SITES", JIRA_CLOUD_SITES)?,
            ceiling: data_ceiling(self.vars, "JIRA_DATA_CEILING")?,
            sign_in: sign_in(self.vars, self.environment, &JIRA_SIGN_IN)?,
            gateway: endpoint(
                self.vars,
                self.environment,
                "JIRA_GATEWAY_URL",
                JIRA_PUBLIC_GATEWAY,
            )?,
        })
    }

    /// Reads both Mailgun regional endpoints with their shared data ceiling.
    fn mailgun(&self) -> Read<MailgunSettings> {
        Ok(MailgunSettings {
            us: endpoint(
                self.vars,
                self.environment,
                "MAILGUN_API_URL",
                MAILGUN_PUBLIC_API,
            )?,
            eu: endpoint(
                self.vars,
                self.environment,
                "MAILGUN_EU_API_URL",
                MAILGUN_PUBLIC_EU_API,
            )?,
            ceiling: data_ceiling(self.vars, "MAILGUN_DATA_CEILING")?,
        })
    }

    /// Reads a Google API with the shared token endpoint and OAuth app.
    fn google(&self, prefix: &str, api: &str) -> Read<GoogleSettings> {
        Ok(GoogleSettings {
            endpoint: endpoint(
                self.vars,
                self.environment,
                &format!("{prefix}_API_URL"),
                api,
            )?,
            token: endpoint(
                self.vars,
                self.environment,
                "GOOGLE_TOKEN_URL",
                GOOGLE_PUBLIC_TOKEN,
            )?,
            ceiling: data_ceiling(self.vars, &format!("{prefix}_DATA_CEILING"))?,
            sign_in: sign_in(self.vars, self.environment, &GOOGLE_SIGN_IN)?,
        })
    }

    /// Reads Microsoft Graph and the token endpoint used by Teams grants.
    fn teams(&self) -> Read<GrantServiceSettings> {
        Ok(GrantServiceSettings {
            endpoint: endpoint(
                self.vars,
                self.environment,
                "TEAMS_API_URL",
                TEAMS_PUBLIC_API,
            )?,
            token: endpoint(
                self.vars,
                self.environment,
                "MICROSOFT_TOKEN_URL",
                MICROSOFT_PUBLIC_TOKEN,
            )?,
            ceiling: data_ceiling(self.vars, "TEAMS_DATA_CEILING")?,
        })
    }

    /// Reads allowed Salesforce sites and the endpoint exchanging their grants.
    fn salesforce(&self) -> Read<SiteGrantSettings> {
        Ok(SiteGrantSettings {
            sites: sites(
                self.vars,
                self.environment,
                "SALESFORCE_SITES",
                SALESFORCE_DOMAINS,
            )?,
            token: endpoint(
                self.vars,
                self.environment,
                "SALESFORCE_TOKEN_URL",
                SALESFORCE_PUBLIC_TOKEN,
            )?,
            ceiling: data_ceiling(self.vars, "SALESFORCE_DATA_CEILING")?,
        })
    }
}

/// The service `prefix` names: its API at `PREFIX_API_URL` or `public`,
/// and its ceiling at `PREFIX_DATA_CEILING`.
///
/// # Errors
///
/// As [`endpoint`] and [`data_ceiling`].
fn service(
    vars: &Env,
    environment: Environment,
    prefix: &str,
    public: &str,
) -> Read<ServiceSettings> {
    Ok(ServiceSettings {
        endpoint: endpoint(vars, environment, &format!("{prefix}_API_URL"), public)?,
        ceiling: data_ceiling(vars, &format!("{prefix}_DATA_CEILING"))?,
    })
}

/// The sites `name` allows, or the service's own cloud, `cloud`. A suffix
/// must name a domain of its own, never a bare top-level one such as
/// `.net`, which would let an account send its token to any site under it.
/// An exact host may name a port, as `jira.acme.example:8443`, only
/// outside production.
fn sites(vars: &Env, environment: Environment, name: &str, cloud: &str) -> Read<Vec<String>> {
    let sites = vars.list(name)?;
    if sites.is_empty() {
        return Ok(vec![cloud.to_owned()]);
    }
    let too_wide = sites
        .iter()
        .any(|site| site.trim_start_matches('.').split('.').count() < 2);
    if too_wide {
        return Err(ConfigError::invalid(
            name,
            "hosts or suffixes naming a domain of their own, such as .atlassian.net or jira.acme.example",
        ));
    }
    if environment.is_production() && sites.iter().any(|site| site.contains(':')) {
        return Err(ConfigError::contradicts(
            name,
            "names a site with a port, which only a test deployment reaches",
        ));
    }
    Ok(sites)
}

/// The app `public.prefix` names, `PREFIX_CLIENT_ID` with
/// `PREFIX_CLIENT_SECRET`, signing people in at `PREFIX_AUTHORIZE_URL` and
/// swapping codes at `PREFIX_TOKEN_URL`, or at the service's public
/// addresses; `None` when no app is set.
///
/// # Errors
///
/// [`ConfigError::Contradicts`] when only one of the id and secret is set,
/// or as [`endpoint`].
fn sign_in(
    vars: &Env,
    environment: Environment,
    public: &PublicSignIn,
) -> Read<Option<SignInSettings>> {
    let prefix = public.prefix;
    let Some(app) = oauth_app(vars, prefix)? else {
        return Ok(None);
    };
    Ok(Some(SignInSettings {
        app,
        authorize: endpoint(
            vars,
            environment,
            &format!("{prefix}_AUTHORIZE_URL"),
            public.authorize,
        )?,
        token: endpoint(
            vars,
            environment,
            &format!("{prefix}_TOKEN_URL"),
            public.token,
        )?,
    }))
}

/// Requires an OAuth client identifier and secret together, or neither.
fn oauth_app(vars: &Env, prefix: &str) -> Read<Option<OAuthApp>> {
    let id_name = format!("{prefix}_CLIENT_ID");
    let secret_name = format!("{prefix}_CLIENT_SECRET");
    let (client_id, client_secret) = match (vars.optional(&id_name)?, vars.secret(&secret_name)?) {
        (None, None) => return Ok(None),
        (Some(id), Some(secret)) => (id, secret),
        (Some(_), None) | (None, Some(_)) => {
            return Err(ConfigError::contradicts(
                &id_name,
                format!("and {secret_name} are set together or not at all"),
            ));
        }
    };
    Ok(Some(OAuthApp {
        client_id,
        client_secret,
    }))
}

/// The service's API at the address `name` holds, or at `public`. A plain
/// `http` address is refused in production: every call carries an
/// account's token.
fn endpoint(
    vars: &Env,
    environment: Environment,
    name: &str,
    public: &str,
) -> Read<ServiceEndpoint> {
    let Some(url) = vars.url(name)? else {
        return ServiceEndpoint::at(public).map_err(|cause| ConfigError::rejected(name, cause));
    };
    if url.scheme() != "https" && environment.is_production() {
        return Err(ConfigError::contradicts(
            name,
            "is not https in production, which sends accounts' tokens unencrypted",
        ));
    }
    ServiceEndpoint::at(url.as_str()).map_err(|cause| ConfigError::rejected(name, cause))
}

/// The data class `name` holds, `internal` when unset: `public`,
/// `internal`, `confidential` or `restricted`.
pub(super) fn data_ceiling(vars: &Env, name: &str) -> Read<DataClassLevel> {
    vars.choice(
        name,
        DataClassLevel::Internal,
        &[
            ("public", DataClassLevel::Public),
            ("internal", DataClassLevel::Internal),
            ("confidential", DataClassLevel::Confidential),
            ("restricted", DataClassLevel::Restricted),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing set reaches the public APIs, holding Internal data at most.
    #[test]
    fn nothing_set_reaches_the_public_apis() {
        let config = IntegrationsConfig::read(&Env::of([]), Environment::Production).unwrap();

        assert_eq!(config.github.endpoint.base().as_str(), GITHUB_PUBLIC_API);
        assert_eq!(config.slack.endpoint.base().as_str(), SLACK_PUBLIC_API);
        assert_eq!(config.github.ceiling, DataClassLevel::Internal);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    /// No app set leaves GitHub with pasted tokens only; an app's id and
    /// secret sign people in at GitHub's own addresses.
    #[test]
    fn a_github_app_signs_in_at_githubs_addresses() {
        let none = IntegrationsConfig::read(&Env::of([]), Environment::Production).unwrap();
        let app = Env::of([
            ("GITHUB_CLIENT_ID", "the app"),
            ("GITHUB_CLIENT_SECRET", "the app's secret words"),
        ]);

        let config = IntegrationsConfig::read(&app, Environment::Production).unwrap();

        assert!(none.github.sign_in.is_none());
        let sign_in = config.github.sign_in.unwrap();
        assert_eq!(sign_in.app.client_id, "the app");
        assert_eq!(sign_in.authorize.base().as_str(), GITHUB_SIGN_IN.authorize);
        assert_eq!(sign_in.token.base().as_str(), GITHUB_SIGN_IN.token);
    }

    /// A GitHub app ID without its secret is refused, naming the
    /// conflicting client ID setting.
    #[test]
    fn an_app_id_without_its_secret_is_refused() {
        let vars = Env::of([("GITHUB_CLIENT_ID", "the app")]);

        let refused = IntegrationsConfig::read(&vars, Environment::Production);

        assert!(
            matches!(refused, Err(ConfigError::Contradicts { name, .. }) if name == "GITHUB_CLIENT_ID")
        );
    }

    /// A stand-in on a plain address is taken outside production.
    #[test]
    fn a_plain_stand_in_is_taken_outside_production() {
        let vars = Env::of([("GITHUB_API_URL", "http://127.0.0.1:4000/")]);

        let config = IntegrationsConfig::read(&vars, Environment::Development).unwrap();

        assert_eq!(
            config.github.endpoint.base().as_str(),
            "http://127.0.0.1:4000/"
        );
    }

    /// Production integration configuration refuses an HTTP Slack API
    /// address, naming its URL setting.
    #[test]
    fn a_plain_address_is_refused_in_production() {
        let vars = Env::of([("SLACK_API_URL", "http://slack.internal/api/")]);

        let refused = IntegrationsConfig::read(&vars, Environment::Production);

        assert!(
            matches!(refused, Err(ConfigError::Contradicts { name, .. }) if name == "SLACK_API_URL")
        );
    }

    /// A site listed with its port is taken outside production and refused
    /// in production, naming the setting.
    #[test]
    fn a_site_with_a_port_is_taken_only_outside_production() {
        let vars = Env::of([("JIRA_SITES", "jira.acme.example:8443")]);

        let development = IntegrationsConfig::read(&vars, Environment::Development).unwrap();
        let production = IntegrationsConfig::read(&vars, Environment::Production);

        assert_eq!(development.jira.sites, ["jira.acme.example:8443"]);
        assert!(
            matches!(production, Err(ConfigError::Contradicts { name, .. }) if name == "JIRA_SITES")
        );
    }

    /// Nothing set allows every Jira Cloud site and reaches Azure DevOps
    /// at its public address; a company's own Jira server can be allowed.
    #[test]
    fn jira_sites_default_to_the_cloud_and_may_name_a_companys_own() {
        let defaults = IntegrationsConfig::read(&Env::of([]), Environment::Production).unwrap();
        let own = Env::of([("JIRA_SITES", "jira.acme.example, .atlassian.net")]);

        let named = IntegrationsConfig::read(&own, Environment::Production).unwrap();

        assert_eq!(defaults.jira.sites, [".atlassian.net"]);
        assert_eq!(
            defaults.azure_devops.endpoint.base().as_str(),
            AZURE_DEVOPS_PUBLIC_API
        );
        assert_eq!(named.jira.sites, ["jira.acme.example", ".atlassian.net"]);
    }

    /// Nothing set reaches both Mailgun regions, Twilio and Google at their
    /// public addresses; a stand-in may take the EU region's place.
    #[test]
    fn mail_texts_and_calendars_default_to_the_public_addresses() {
        let defaults = IntegrationsConfig::read(&Env::of([]), Environment::Production).unwrap();
        let europe = Env::of([("MAILGUN_EU_API_URL", "http://127.0.0.1:4001/")]);

        let named = IntegrationsConfig::read(&europe, Environment::Development).unwrap();

        assert_eq!(defaults.mailgun.us.base().as_str(), MAILGUN_PUBLIC_API);
        assert_eq!(defaults.mailgun.eu.base().as_str(), MAILGUN_PUBLIC_EU_API);
        assert_eq!(defaults.twilio.endpoint.base().as_str(), TWILIO_PUBLIC_API);
        assert_eq!(
            defaults.google_calendar.endpoint.base().as_str(),
            GOOGLE_CALENDAR_PUBLIC_API
        );
        assert_eq!(
            defaults.google_calendar.token.base().as_str(),
            GOOGLE_PUBLIC_TOKEN
        );
        assert_eq!(named.mailgun.eu.base().as_str(), "http://127.0.0.1:4001/");
        assert_eq!(named.mailgun.us.base().as_str(), MAILGUN_PUBLIC_API);
    }

    /// Nothing set reaches every work and chat service at its public
    /// address; a company's own GitLab server can be named instead.
    #[test]
    fn work_and_chat_services_default_to_the_public_addresses() {
        let defaults = IntegrationsConfig::read(&Env::of([]), Environment::Production).unwrap();
        let own = Env::of([("GITLAB_API_URL", "https://gitlab.acme.example/api/v4/")]);

        let named = IntegrationsConfig::read(&own, Environment::Production).unwrap();

        assert_public_services(&defaults);
        assert_eq!(defaults.teams.endpoint.base().as_str(), TEAMS_PUBLIC_API);
        assert_eq!(defaults.teams.token.base().as_str(), MICROSOFT_PUBLIC_TOKEN);
        assert_eq!(
            defaults.google_sheets.endpoint.base().as_str(),
            GOOGLE_SHEETS_PUBLIC_API
        );
        assert_eq!(defaults.gmail.endpoint.base().as_str(), GMAIL_PUBLIC_API);
        assert_eq!(defaults.salesforce.sites, [SALESFORCE_DOMAINS]);
        assert_eq!(
            defaults.salesforce.token.base().as_str(),
            SALESFORCE_PUBLIC_TOKEN
        );
        assert_eq!(defaults.gitlab.endpoint.base().as_str(), GITLAB_PUBLIC_API);
        assert!(defaults.gitlab.sign_in.is_none());
        assert_eq!(
            named.gitlab.endpoint.base().as_str(),
            "https://gitlab.acme.example/api/v4/"
        );
    }

    /// Checks the default endpoint and ceiling of services using direct tokens.
    fn assert_public_services(defaults: &IntegrationsConfig) {
        let reached = [
            (&defaults.linear, LINEAR_PUBLIC_API),
            (&defaults.asana, ASANA_PUBLIC_API),
            (&defaults.trello, TRELLO_PUBLIC_API),
            (&defaults.clickup, CLICKUP_PUBLIC_API),
            (&defaults.discord, DISCORD_PUBLIC_API),
            (&defaults.pagerduty, PAGERDUTY_PUBLIC_API),
            (&defaults.notion, NOTION_PUBLIC_API),
            (&defaults.airtable, AIRTABLE_PUBLIC_API),
            (&defaults.hubspot, HUBSPOT_PUBLIC_API),
            (&defaults.stripe, STRIPE_PUBLIC_API),
            (&defaults.telegram, TELEGRAM_PUBLIC_API),
        ];
        for (settings, public) in reached {
            assert_eq!(settings.endpoint.base().as_str(), public);
            assert_eq!(settings.ceiling, DataClassLevel::Internal);
        }
    }

    /// Production integration configuration refuses an HTTP Google token
    /// address, naming its URL setting.
    #[test]
    fn a_plain_token_address_is_refused_in_production() {
        let vars = Env::of([("GOOGLE_TOKEN_URL", "http://tokens.internal/token")]);

        let refused = IntegrationsConfig::read(&vars, Environment::Production);

        assert!(
            matches!(refused, Err(ConfigError::Contradicts { name, .. }) if name == "GOOGLE_TOKEN_URL")
        );
    }

    /// A Jira site suffix covering an entire top-level domain is refused,
    /// naming the invalid site setting.
    #[test]
    fn a_jira_suffix_as_wide_as_a_top_level_domain_is_refused() {
        let vars = Env::of([("JIRA_SITES", ".net")]);

        let refused = IntegrationsConfig::read(&vars, Environment::Production);

        assert!(matches!(refused, Err(ConfigError::Invalid { name, .. }) if name == "JIRA_SITES"));
    }
}
