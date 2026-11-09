//! The outside services workflow steps call, each a crate of its own under
//! `integrations/` behind a feature of the same name, set up at the API its
//! settings name.

use std::sync::Arc;

use ianua_integration::rest::service::RestService;
use ianua_integration::{Integration, ServiceReach};

use crate::config::Config;
use crate::error::PlatformError;

/// The outside services this build includes, set up as
/// `config.integrations` says, each calling through `reach`.
///
/// # Errors
///
/// [`PlatformError`] when a service's client cannot be built.
pub(super) fn outside_services(
    config: &Config,
    reach: &ServiceReach,
) -> Result<Vec<Arc<dyn Integration>>, PlatformError> {
    rest_services(config)?
        .into_iter()
        .map(|service| {
            let reached = service
                .reaching(reach)
                .map_err(PlatformError::of("an outside service's client"))?;
            Ok(Arc::new(reached) as Arc<dyn Integration>)
        })
        .collect()
}

/// Every REST integration this build includes.
///
/// # Errors
///
/// [`PlatformError`] when a service's client cannot be built.
/// The exhaustive feature-gated list keeps integration order visible without splitting registration.
#[allow(clippy::too_many_lines)]
fn rest_services(config: &Config) -> Result<Vec<RestService>, PlatformError> {
    Ok(vec![
        #[cfg(feature = "github")]
        github(config)?,
        #[cfg(feature = "slack")]
        slack(config)?,
        #[cfg(feature = "jira")]
        jira(config)?,
        #[cfg(feature = "azure-devops")]
        azure_devops(config)?,
        #[cfg(feature = "mailgun")]
        mailgun(config)?,
        #[cfg(feature = "twilio")]
        twilio(config)?,
        #[cfg(feature = "google-calendar")]
        google_calendar(config)?,
        #[cfg(feature = "google-sheets")]
        google_sheets(config)?,
        #[cfg(feature = "gmail")]
        gmail(config)?,
        #[cfg(feature = "gitlab")]
        gitlab(config)?,
        #[cfg(feature = "linear")]
        linear(config)?,
        #[cfg(feature = "asana")]
        asana(config)?,
        #[cfg(feature = "trello")]
        trello(config)?,
        #[cfg(feature = "clickup")]
        clickup(config)?,
        #[cfg(feature = "teams")]
        teams(config)?,
        #[cfg(feature = "discord")]
        discord(config)?,
        #[cfg(feature = "pagerduty")]
        pagerduty(config)?,
        #[cfg(feature = "notion")]
        notion(config)?,
        #[cfg(feature = "airtable")]
        airtable(config)?,
        #[cfg(feature = "hubspot")]
        hubspot(config)?,
        #[cfg(feature = "stripe")]
        stripe(config)?,
        #[cfg(feature = "salesforce")]
        salesforce(config)?,
        #[cfg(feature = "telegram")]
        telegram(config)?,
    ])
}

/// Mailgun, in its US region at `MAILGUN_API_URL` and its EU region at
/// `MAILGUN_EU_API_URL`.
#[cfg(feature = "mailgun")]
fn mailgun(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.mailgun;
    ianua_integration_mailgun::integration(ianua_integration_mailgun::MailgunSettings {
        us: settings.us.clone(),
        eu: settings.eu.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Mailgun integration"))
}

/// Twilio, at `TWILIO_API_URL`.
#[cfg(feature = "twilio")]
fn twilio(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.twilio;
    ianua_integration_twilio::integration(&ianua_integration_twilio::TwilioSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Twilio integration"))
}

/// Google Calendar, at `GOOGLE_CALENDAR_API_URL`, exchanging grants at
/// `GOOGLE_TOKEN_URL`.
#[cfg(feature = "google-calendar")]
fn google_calendar(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.google_calendar;
    ianua_integration_google_calendar::integration(
        ianua_integration_google_calendar::GoogleCalendarSettings {
            endpoint: settings.endpoint.clone(),
            token: settings.token.clone(),
            timeout: config.integrations.timeout,
            ceiling: settings.ceiling,
            sign_in: settings.sign_in.clone(),
        },
    )
    .map_err(PlatformError::of("the Google Calendar integration"))
}

/// Google Sheets, at `GOOGLE_SHEETS_API_URL`, exchanging grants at
/// `GOOGLE_TOKEN_URL`.
#[cfg(feature = "google-sheets")]
fn google_sheets(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.google_sheets;
    ianua_integration_google_sheets::integration(
        ianua_integration_google_sheets::GoogleSheetsSettings {
            endpoint: settings.endpoint.clone(),
            token: settings.token.clone(),
            timeout: config.integrations.timeout,
            ceiling: settings.ceiling,
            sign_in: settings.sign_in.clone(),
        },
    )
    .map_err(PlatformError::of("the Google Sheets integration"))
}

/// Gmail, at `GMAIL_API_URL`, exchanging grants at `GOOGLE_TOKEN_URL`.
#[cfg(feature = "gmail")]
fn gmail(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.gmail;
    ianua_integration_gmail::integration(ianua_integration_gmail::GmailSettings {
        endpoint: settings.endpoint.clone(),
        token: settings.token.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
        sign_in: settings.sign_in.clone(),
    })
    .map_err(PlatformError::of("the Gmail integration"))
}

/// Jira, for the sites `JIRA_SITES` allows.
#[cfg(feature = "jira")]
fn jira(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.jira;
    ianua_integration_jira::integration(ianua_integration_jira::JiraSettings {
        sites: ianua_integration::rest::access::AllowedSites::new(settings.sites.iter().cloned()),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
        sign_in: settings.sign_in.clone(),
        gateway: settings.gateway.clone(),
    })
    .map_err(PlatformError::of("the Jira integration"))
}

/// Azure DevOps, at `AZURE_DEVOPS_API_URL`.
#[cfg(feature = "azure-devops")]
fn azure_devops(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.azure_devops;
    ianua_integration_azure_devops::integration(
        ianua_integration_azure_devops::AzureDevOpsSettings {
            endpoint: settings.endpoint.clone(),
            timeout: config.integrations.timeout,
            ceiling: settings.ceiling,
            sign_in: settings.sign_in.clone(),
        },
    )
    .map_err(PlatformError::of("the Azure DevOps integration"))
}

/// GitHub, at `GITHUB_API_URL`, signing people in through
/// `GITHUB_CLIENT_ID`'s app when one is set.
#[cfg(feature = "github")]
fn github(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.github;
    ianua_integration_github::integration(ianua_integration_github::GitHubSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
        sign_in: settings.sign_in.clone(),
    })
    .map_err(PlatformError::of("the GitHub integration"))
}

/// Slack, at `SLACK_API_URL`, signing people in through
/// `SLACK_CLIENT_ID`'s app and offering its events with
/// `SLACK_SIGNING_SECRET`, when they are set.
#[cfg(feature = "slack")]
fn slack(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.slack;
    ianua_integration_slack::integration(ianua_integration_slack::SlackSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
        sign_in: settings.sign_in.clone(),
        signing_secret: settings.signing_secret.clone(),
    })
    .map_err(PlatformError::of("the Slack integration"))
}

/// GitLab, at `GITLAB_API_URL`.
#[cfg(feature = "gitlab")]
fn gitlab(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.gitlab;
    ianua_integration_gitlab::integration(ianua_integration_gitlab::GitLabSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
        sign_in: settings.sign_in.clone(),
    })
    .map_err(PlatformError::of("the GitLab integration"))
}

/// Linear, at `LINEAR_API_URL`.
#[cfg(feature = "linear")]
fn linear(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.linear;
    ianua_integration_linear::integration(ianua_integration_linear::LinearSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Linear integration"))
}

/// Asana, at `ASANA_API_URL`.
#[cfg(feature = "asana")]
fn asana(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.asana;
    ianua_integration_asana::integration(ianua_integration_asana::AsanaSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Asana integration"))
}

/// Trello, at `TRELLO_API_URL`.
#[cfg(feature = "trello")]
fn trello(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.trello;
    ianua_integration_trello::integration(ianua_integration_trello::TrelloSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Trello integration"))
}

/// ClickUp, at `CLICKUP_API_URL`.
#[cfg(feature = "clickup")]
fn clickup(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.clickup;
    ianua_integration_clickup::integration(ianua_integration_clickup::ClickUpSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the ClickUp integration"))
}

/// Microsoft Teams, through Microsoft Graph at `TEAMS_API_URL`, exchanging
/// grants at `MICROSOFT_TOKEN_URL`.
#[cfg(feature = "teams")]
fn teams(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.teams;
    ianua_integration_teams::integration(ianua_integration_teams::TeamsSettings {
        endpoint: settings.endpoint.clone(),
        token: settings.token.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Microsoft Teams integration"))
}

/// Discord, at `DISCORD_API_URL`.
#[cfg(feature = "discord")]
fn discord(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.discord;
    ianua_integration_discord::integration(ianua_integration_discord::DiscordSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Discord integration"))
}

/// PagerDuty, at `PAGERDUTY_API_URL`.
#[cfg(feature = "pagerduty")]
fn pagerduty(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.pagerduty;
    ianua_integration_pagerduty::integration(ianua_integration_pagerduty::PagerDutySettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the PagerDuty integration"))
}

/// Notion, at `NOTION_API_URL`.
#[cfg(feature = "notion")]
fn notion(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.notion;
    ianua_integration_notion::integration(ianua_integration_notion::NotionSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Notion integration"))
}

/// Airtable, at `AIRTABLE_API_URL`.
#[cfg(feature = "airtable")]
fn airtable(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.airtable;
    ianua_integration_airtable::integration(ianua_integration_airtable::AirtableSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Airtable integration"))
}

/// HubSpot, at `HUBSPOT_API_URL`.
#[cfg(feature = "hubspot")]
fn hubspot(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.hubspot;
    ianua_integration_hubspot::integration(ianua_integration_hubspot::HubSpotSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the HubSpot integration"))
}

/// Stripe, at `STRIPE_API_URL`.
#[cfg(feature = "stripe")]
fn stripe(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.stripe;
    ianua_integration_stripe::integration(ianua_integration_stripe::StripeSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Stripe integration"))
}

/// Salesforce, for the domains `SALESFORCE_SITES` allows, exchanging grants
/// at `SALESFORCE_TOKEN_URL`.
#[cfg(feature = "salesforce")]
fn salesforce(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.salesforce;
    ianua_integration_salesforce::integration(ianua_integration_salesforce::SalesforceSettings {
        sites: ianua_integration::rest::access::AllowedSites::new(settings.sites.iter().cloned()),
        token: settings.token.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Salesforce integration"))
}

/// Telegram, at `TELEGRAM_API_URL`.
#[cfg(feature = "telegram")]
fn telegram(config: &Config) -> Result<RestService, PlatformError> {
    let settings = &config.integrations.telegram;
    ianua_integration_telegram::integration(ianua_integration_telegram::TelegramSettings {
        endpoint: settings.endpoint.clone(),
        timeout: config.integrations.timeout,
        ceiling: settings.ceiling,
    })
    .map_err(PlatformError::of("the Telegram integration"))
}
