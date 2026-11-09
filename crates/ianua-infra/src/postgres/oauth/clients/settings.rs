//! What a client is set up with beyond its redirects, grants and scopes, in
//! the shape its `settings` column keeps.

use ianua_domain::domains::oauth::clients::lifetimes::{
    ClientTokenLifetimes, RefreshLifetimes, TokenTerms,
};
use ianua_domain::domains::oauth::clients::settings::{
    AccessTokenFormat, ChannelLogout, ClientLinks, ClientLogout, ClientSettings, ClientUri,
    ConsentPrompt, SessionRequired,
};
use ianua_domain::domains::oauth::grants::token_binding::SenderConstraint;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HttpsUrl, Lifetime};
use serde::{Deserialize, Serialize};

use crate::postgres::oauth::clients::record::CLIENT;

/// A client's settings as they are stored.
#[derive(Serialize, Deserialize)]
pub(super) struct StoredSettings {
    /// The client's own token terms, or none for the platform's.
    lifetimes: Option<StoredTerms>,
    logo_uri: Option<HttpsUrl>,
    policy_uri: Option<HttpsUrl>,
    tos_uri: Option<HttpsUrl>,
    consent: StoredConsent,
    token_format: StoredFormat,
    back_channel_logout: Option<StoredChannel>,
    front_channel_logout: Option<StoredChannel>,
    sender_constraint: StoredConstraint,
}

/// A client's own token terms, each in whole seconds.
#[derive(Serialize, Deserialize)]
struct StoredTerms {
    access_secs: i64,
    id_token_secs: i64,
    refresh_idle_secs: i64,
    refresh_family_secs: i64,
}

/// Whether people are asked to consent.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredConsent {
    AskPerson,
    FirstParty,
}

/// The form of the client's access tokens.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredFormat {
    Opaque,
    Jwt,
}

/// Where the client is told of a sign-out on one channel.
#[derive(Serialize, Deserialize)]
struct StoredChannel {
    uri: HttpsUrl,
    session: StoredSession,
}

/// Whether the client wants the session named.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredSession {
    Required,
    NotRequired,
}

/// What the client's tokens are bound to.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredConstraint {
    BearerAllowed,
    DpopRequired,
    CertificateRequired,
}

impl From<&ClientSettings> for StoredSettings {
    fn from(settings: &ClientSettings) -> Self {
        Self {
            lifetimes: terms_of(settings.lifetimes),
            logo_uri: uri_of(&settings.links.logo),
            policy_uri: uri_of(&settings.links.policy),
            tos_uri: uri_of(&settings.links.terms),
            consent: match settings.consent {
                ConsentPrompt::AskPerson => StoredConsent::AskPerson,
                ConsentPrompt::FirstParty => StoredConsent::FirstParty,
            },
            token_format: match settings.token_format {
                AccessTokenFormat::Opaque => StoredFormat::Opaque,
                AccessTokenFormat::Jwt => StoredFormat::Jwt,
            },
            back_channel_logout: channel_of(&settings.logout.back_channel),
            front_channel_logout: channel_of(&settings.logout.front_channel),
            sender_constraint: match settings.sender_constraint {
                SenderConstraint::BearerAllowed => StoredConstraint::BearerAllowed,
                SenderConstraint::DpopRequired => StoredConstraint::DpopRequired,
                SenderConstraint::CertificateRequired => StoredConstraint::CertificateRequired,
            },
        }
    }
}

impl TryFrom<StoredSettings> for ClientSettings {
    type Error = DomainError;

    fn try_from(stored: StoredSettings) -> Result<Self, DomainError> {
        Ok(Self {
            lifetimes: lifetimes_from(stored.lifetimes)?,
            links: ClientLinks {
                logo: given(stored.logo_uri),
                policy: given(stored.policy_uri),
                terms: given(stored.tos_uri),
            },
            consent: match stored.consent {
                StoredConsent::AskPerson => ConsentPrompt::AskPerson,
                StoredConsent::FirstParty => ConsentPrompt::FirstParty,
            },
            token_format: match stored.token_format {
                StoredFormat::Opaque => AccessTokenFormat::Opaque,
                StoredFormat::Jwt => AccessTokenFormat::Jwt,
            },
            logout: ClientLogout {
                back_channel: registered(stored.back_channel_logout),
                front_channel: registered(stored.front_channel_logout),
            },
            sender_constraint: match stored.sender_constraint {
                StoredConstraint::BearerAllowed => SenderConstraint::BearerAllowed,
                StoredConstraint::DpopRequired => SenderConstraint::DpopRequired,
                StoredConstraint::CertificateRequired => SenderConstraint::CertificateRequired,
            },
        })
    }
}

/// The client's own terms, as stored: none for the platform's.
fn terms_of(lifetimes: ClientTokenLifetimes) -> Option<StoredTerms> {
    let ClientTokenLifetimes::Own(terms) = lifetimes else {
        return None;
    };
    Some(StoredTerms {
        access_secs: terms.access().whole_seconds(),
        id_token_secs: terms.id_token().whole_seconds(),
        refresh_idle_secs: terms.refresh().idle().whole_seconds(),
        refresh_family_secs: terms.refresh().family().whole_seconds(),
    })
}

/// The terms a stored column holds, read back through their bounds.
fn lifetimes_from(stored: Option<StoredTerms>) -> Result<ClientTokenLifetimes, DomainError> {
    let Some(terms) = stored else {
        return Ok(ClientTokenLifetimes::PlatformDefault);
    };
    let lifetime =
        |what: &'static str, seconds: i64| CLIENT.value(what, Lifetime::seconds(seconds));
    let refresh = RefreshLifetimes::new(
        lifetime("refresh idle time", terms.refresh_idle_secs)?,
        lifetime("refresh family lifetime", terms.refresh_family_secs)?,
    )
    .map_err(|_| DomainError::corrupt_row(CLIENT.0, "refresh terms out of bounds"))?;
    let own = TokenTerms::new(
        lifetime("access token lifetime", terms.access_secs)?,
        lifetime("ID token lifetime", terms.id_token_secs)?,
        refresh,
    )
    .map_err(|_| DomainError::corrupt_row(CLIENT.0, "token terms out of bounds"))?;
    Ok(ClientTokenLifetimes::Own(own))
}

fn uri_of(uri: &ClientUri) -> Option<HttpsUrl> {
    match uri {
        ClientUri::NotGiven => None,
        ClientUri::At(url) => Some(url.clone()),
    }
}

fn given(stored: Option<HttpsUrl>) -> ClientUri {
    stored.map_or(ClientUri::NotGiven, ClientUri::At)
}

fn channel_of(channel: &ChannelLogout) -> Option<StoredChannel> {
    let ChannelLogout::At { uri, session } = channel else {
        return None;
    };
    Some(StoredChannel {
        uri: uri.clone(),
        session: match session {
            SessionRequired::Required => StoredSession::Required,
            SessionRequired::NotRequired => StoredSession::NotRequired,
        },
    })
}

fn registered(stored: Option<StoredChannel>) -> ChannelLogout {
    let Some(channel) = stored else {
        return ChannelLogout::NotRegistered;
    };
    ChannelLogout::At {
        uri: channel.uri,
        session: match channel.session {
            StoredSession::Required => SessionRequired::Required,
            StoredSession::NotRequired => SessionRequired::NotRequired,
        },
    }
}
