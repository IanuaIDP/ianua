//! What a client is set up with beyond where it sends codes and what it may
//! ask for: how long its tokens last, the pages shown about it, whether
//! people are asked to consent, the form of its access tokens, how it hears
//! about sign-outs, and what its tokens are bound to.

use crate::domains::oauth::clients::lifetimes::ClientTokenLifetimes;
use crate::domains::oauth::grants::authorization_request::ConsentStanding;
use crate::domains::oauth::grants::token_binding::SenderConstraint;
use crate::types::HttpsUrl;

/// An address a client gave for a page about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientUri {
    /// None was given.
    NotGiven,
    /// The HTTPS page supplied for display on the consent screen.
    At(HttpsUrl),
}

/// The pages a consent screen shows about a client (RFC 7591 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientLinks {
    /// Its logo (`logo_uri`).
    pub logo: ClientUri,
    /// How it treats people's data (`policy_uri`).
    pub policy: ClientUri,
    /// Its terms of service (`tos_uri`).
    pub terms: ClientUri,
}

impl ClientLinks {
    /// No page given.
    #[must_use]
    pub fn none() -> Self {
        Self {
            logo: ClientUri::NotGiven,
            policy: ClientUri::NotGiven,
            terms: ClientUri::NotGiven,
        }
    }
}

/// Whether people are asked to consent to a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentPrompt {
    /// They are, the first time it asks for a scope.
    AskPerson,
    /// They are not: the tenant's own app, which the tenant vouches for.
    /// Only an admin sets it, never a client registering itself.
    FirstParty,
}

impl ConsentPrompt {
    /// Whether the person's consent covers a request, given what they
    /// `recorded`: a first-party client is covered without asking.
    #[must_use]
    pub fn standing(self, recorded: ConsentStanding) -> ConsentStanding {
        match self {
            Self::AskPerson => recorded,
            Self::FirstParty => ConsentStanding::Covers,
        }
    }
}

/// The form a client's access tokens take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessTokenFormat {
    /// A random string, checked by introspection.
    Opaque,
    /// A signed JWT a resource server checks on its own (RFC 9068).
    Jwt,
}

/// Whether a client wants the session named when it is told of a sign-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRequired {
    /// It does: the notice carries the issuer and `sid`.
    Required,
    /// It does not.
    NotRequired,
}

/// Where a client is told that a person signed out, on one channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelLogout {
    /// It is not told on this channel.
    NotRegistered,
    /// At this address.
    At {
        /// The address.
        uri: HttpsUrl,
        /// Whether it wants the session named.
        session: SessionRequired,
    },
}

/// How a client hears that a person signed out (OpenID Connect Back-Channel
/// and Front-Channel Logout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientLogout {
    /// A logout token posted to its server.
    pub back_channel: ChannelLogout,
    /// A page loaded in the person's browser.
    pub front_channel: ChannelLogout,
}

impl ClientLogout {
    /// Told on neither channel.
    #[must_use]
    pub fn none() -> Self {
        Self {
            back_channel: ChannelLogout::NotRegistered,
            front_channel: ChannelLogout::NotRegistered,
        }
    }
}

/// What a client is set up with beyond its redirects, grants and scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSettings {
    /// How long its tokens last.
    pub lifetimes: ClientTokenLifetimes,
    /// The pages shown about it.
    pub links: ClientLinks,
    /// Whether people are asked to consent.
    pub consent: ConsentPrompt,
    /// The form of its access tokens.
    pub token_format: AccessTokenFormat,
    /// How it hears about sign-outs.
    pub logout: ClientLogout,
    /// What its tokens are bound to.
    pub sender_constraint: SenderConstraint,
}

impl ClientSettings {
    /// The platform's terms, no pages, consent asked, opaque bearer tokens
    /// and no sign-out notices.
    #[must_use]
    pub fn platform_defaults() -> Self {
        Self {
            lifetimes: ClientTokenLifetimes::PlatformDefault,
            links: ClientLinks::none(),
            consent: ConsentPrompt::AskPerson,
            token_format: AccessTokenFormat::Opaque,
            logout: ClientLogout::none(),
            sender_constraint: SenderConstraint::BearerAllowed,
        }
    }

    /// Makes `change`, once the client found the caller allowed to.
    pub(crate) fn apply(&mut self, change: SettingsChange) {
        match change {
            SettingsChange::Lifetimes(lifetimes) => self.lifetimes = lifetimes,
            SettingsChange::Links(links) => self.links = links,
            SettingsChange::Consent(consent) => self.consent = consent,
            SettingsChange::TokenFormat(format) => self.token_format = format,
            SettingsChange::Logout(logout) => self.logout = logout,
            SettingsChange::SenderConstraint(constraint) => self.sender_constraint = constraint,
        }
    }
}

/// One change to a client's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsChange {
    /// How long its tokens last.
    Lifetimes(ClientTokenLifetimes),
    /// The pages shown about it.
    Links(ClientLinks),
    /// Whether people are asked to consent. Only an admin makes a client
    /// first-party.
    Consent(ConsentPrompt),
    /// The form of its access tokens.
    TokenFormat(AccessTokenFormat),
    /// How it hears that a person signed out.
    Logout(ClientLogout),
    /// What its tokens are bound to.
    SenderConstraint(SenderConstraint),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ann never agreed to the tenant's own portal. As a first-party app,
    /// it is covered without asking her; a third-party app still asks.
    #[test]
    fn a_first_party_client_skips_consent() {
        let missing = ConsentStanding::Missing;

        assert_eq!(
            ConsentPrompt::FirstParty.standing(missing),
            ConsentStanding::Covers
        );
        assert_eq!(
            ConsentPrompt::AskPerson.standing(missing),
            ConsentStanding::Missing
        );
    }

    /// A new client asks for consent, holds opaque bearer tokens and gets
    /// no sign-out notices.
    #[test]
    fn the_platform_defaults_ask_consent_and_bind_nothing() {
        let settings = ClientSettings::platform_defaults();

        assert_eq!(settings.consent, ConsentPrompt::AskPerson);
        assert_eq!(settings.token_format, AccessTokenFormat::Opaque);
        assert_eq!(settings.sender_constraint, SenderConstraint::BearerAllowed);
        assert_eq!(settings.logout, ClientLogout::none());
    }
}
