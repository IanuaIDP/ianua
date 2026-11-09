//! Where a destination posts: a Slack or Teams channel, or a webhook.
//!
//! A Slack or Teams incoming-webhook address is itself the key that posts
//! to the channel. Anyone who reads it can write to that channel as the
//! organization. So it is kept sealed, never shown and never put in a
//! record. Its host is checked while it is still plain, before the caller
//! seals it, so an address that only claims to be Slack's is never kept.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::UrlHost;
use crate::types::{PublicHttpsUrl, SealedSecret};

/// The one host Slack's incoming webhooks are served from.
const SLACK_HOST: &str = "hooks.slack.com";

/// The hosts Microsoft serves Teams webhooks under: the connector hosts
/// and the Power Automate workflow hosts that replace them.
const TEAMS_SUFFIXES: [&str; 2] = [".webhook.office.com", ".logic.azure.com"];

/// What kind of place a destination posts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationKind {
    /// A Slack channel, through its incoming webhook.
    Slack,
    /// A Microsoft Teams channel, through its webhook.
    Teams,
    /// An HTTPS endpoint of the organization's own, signed by a shared
    /// secret.
    Webhook,
}

impl DestinationKind {
    /// The stable name a record and storage carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Slack => "slack",
            Self::Teams => "teams",
            Self::Webhook => "webhook",
        }
    }

    /// The kind with this stored name, if there is one.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "slack" => Some(Self::Slack),
            "teams" => Some(Self::Teams),
            "webhook" => Some(Self::Webhook),
            _ => None,
        }
    }
}

/// Where a destination posts, with what it posts with.
///
/// Its parts are private, so a Slack or Teams address is only kept after
/// its host was checked. `Debug` shows the sealed parts as redacted and a
/// webhook's URL by its origin only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationEndpoint(Target);

/// The place behind a [`DestinationEndpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Slack(SealedSecret),
    Teams(SealedSecret),
    Webhook {
        url: PublicHttpsUrl,
        signing_secret: SealedSecret,
    },
}

/// A destination's endpoint as storage holds it, read back through
/// [`NotificationDestination::reconstitute`](crate::domains::notifications::destination::NotificationDestination::reconstitute).
pub enum DestinationEndpointRow {
    /// A Slack channel's sealed incoming-webhook address.
    Slack {
        /// The sealed address.
        hook: SealedSecret,
    },
    /// A Teams channel's sealed webhook address.
    Teams {
        /// The sealed address.
        hook: SealedSecret,
    },
    /// An HTTPS endpoint and the sealed secret its posts are signed with.
    Webhook {
        /// Where it posts.
        url: PublicHttpsUrl,
        /// The sealed signing secret.
        signing_secret: SealedSecret,
    },
}

/// What the delivery adapter needs to post to a destination.
#[derive(Debug, Clone, Copy)]
pub enum EndpointDelivery<'a> {
    /// Post to Slack: unseal this address and post to it.
    Slack(&'a SealedSecret),
    /// Post to Teams: unseal this address and post to it.
    Teams(&'a SealedSecret),
    /// Post to `url`, signed with the unsealed `signing_secret`.
    Webhook {
        /// Where to post.
        url: &'a PublicHttpsUrl,
        /// The sealed signing secret.
        signing_secret: &'a SealedSecret,
    },
}

impl DestinationEndpoint {
    /// A Slack channel, reached through the incoming-webhook address `url`,
    /// kept as `sealed`, the same address after the caller sealed it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `url` is not on `hooks.slack.com`.
    pub fn slack(url: &PublicHttpsUrl, sealed: SealedSecret) -> Result<Self, DomainError> {
        if !is_slack_host(url.host()) {
            return Err(DomainError::invalid(message!(
                "notifications-a-slack-destination-posts-only-to",
                "a Slack destination posts only to hooks.slack.com"
            )));
        }
        Ok(Self(Target::Slack(sealed)))
    }

    /// A Teams channel, reached through the webhook address `url`, kept as
    /// `sealed`, the same address after the caller sealed it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `url` is not under a Microsoft
    ///   webhook host.
    pub fn teams(url: &PublicHttpsUrl, sealed: SealedSecret) -> Result<Self, DomainError> {
        if !is_teams_host(url.host()) {
            return Err(DomainError::invalid(message!(
                "notifications-a-teams-destination-posts-only-to",
                "a Teams destination posts only to a Microsoft webhook host"
            )));
        }
        Ok(Self(Target::Teams(sealed)))
    }

    /// An HTTPS endpoint on the public internet, whose posts are signed with
    /// `signing_secret`, already sealed.
    #[must_use]
    pub fn webhook(url: PublicHttpsUrl, signing_secret: SealedSecret) -> Self {
        Self(Target::Webhook {
            url,
            signing_secret,
        })
    }

    /// Rebuilds an endpoint from storage. Its host was checked when it was
    /// first kept, and a sealed address cannot be checked again.
    pub(super) fn from_row(row: DestinationEndpointRow) -> Self {
        match row {
            DestinationEndpointRow::Slack { hook } => Self(Target::Slack(hook)),
            DestinationEndpointRow::Teams { hook } => Self(Target::Teams(hook)),
            DestinationEndpointRow::Webhook {
                url,
                signing_secret,
            } => Self(Target::Webhook {
                url,
                signing_secret,
            }),
        }
    }

    /// What kind of place it posts to.
    #[must_use]
    pub fn kind(&self) -> DestinationKind {
        match self.0 {
            Target::Slack(_) => DestinationKind::Slack,
            Target::Teams(_) => DestinationKind::Teams,
            Target::Webhook { .. } => DestinationKind::Webhook,
        }
    }

    /// What the delivery adapter posts with.
    #[must_use]
    pub fn delivery(&self) -> EndpointDelivery<'_> {
        match &self.0 {
            Target::Slack(hook) => EndpointDelivery::Slack(hook),
            Target::Teams(hook) => EndpointDelivery::Teams(hook),
            Target::Webhook {
                url,
                signing_secret,
            } => EndpointDelivery::Webhook {
                url,
                signing_secret,
            },
        }
    }
}

/// Whether `host` is Slack's incoming-webhook host.
fn is_slack_host(host: UrlHost<'_>) -> bool {
    match host {
        UrlHost::Name(name) => bare(name) == SLACK_HOST,
        UrlHost::Address(_) => false,
    }
}

/// Whether `host` is under one of Microsoft's webhook hosts.
fn is_teams_host(host: UrlHost<'_>) -> bool {
    match host {
        UrlHost::Name(name) => {
            let name = bare(name);
            TEAMS_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
        }
        UrlHost::Address(_) => false,
    }
}

/// `name` in lower case, without a trailing dot.
fn bare(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `value` as a public HTTPS URL.
    fn url(value: &str) -> PublicHttpsUrl {
        PublicHttpsUrl::new(value).unwrap()
    }

    /// A sealed value standing for whatever the caller sealed.
    fn sealed() -> SealedSecret {
        SealedSecret::new("v1.c2VhbGVk").unwrap()
    }

    /// Ann pastes Acme's Slack incoming-webhook address. It is kept, as a
    /// Slack destination.
    #[test]
    fn a_slack_hook_on_slacks_host_is_kept() {
        let endpoint =
            DestinationEndpoint::slack(&url("https://hooks.slack.com/services/T0/B0/x"), sealed())
                .unwrap();

        assert_eq!(endpoint.kind(), DestinationKind::Slack);
    }

    /// A server outside Slack and a host using Slack's name as a prefix
    /// are both refused as Slack destinations.
    #[test]
    fn a_slack_destination_on_another_host_is_refused() {
        for address in [
            "https://mallory.example/services/T0/B0/x",
            "https://hooks.slack.com.mallory.example/services/x",
        ] {
            let result = DestinationEndpoint::slack(&url(address), sealed());

            assert!(
                matches!(result, Err(DomainError::Validation(_))),
                "{address}"
            );
        }
    }

    /// Ann pastes a Teams connector address and a Power Automate workflow
    /// address. Both are kept as Teams destinations.
    #[test]
    fn a_teams_hook_under_microsofts_hosts_is_kept() {
        for address in [
            "https://acme.webhook.office.com/webhookb2/abc",
            "https://prod-01.westeurope.logic.azure.com/workflows/abc",
        ] {
            let endpoint = DestinationEndpoint::teams(&url(address), sealed()).unwrap();

            assert_eq!(endpoint.kind(), DestinationKind::Teams, "{address}");
        }
    }

    /// A host using Microsoft's webhook name as a prefix is refused as a
    /// Teams destination.
    #[test]
    fn a_teams_destination_on_another_host_is_refused() {
        let result = DestinationEndpoint::teams(
            &url("https://webhook.office.com.mallory.example/x"),
            sealed(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Debug output hides the sealed Slack address and the secret carried
    /// in a webhook URL's path.
    #[test]
    fn debug_shows_no_secret_and_no_path() {
        let slack = DestinationEndpoint::slack(
            &url("https://hooks.slack.com/services/T0/B0/topsecret"),
            sealed(),
        )
        .unwrap();
        let webhook =
            DestinationEndpoint::webhook(url("https://acme.example/hooks/topsecret"), sealed());

        for printed in [format!("{slack:?}"), format!("{webhook:?}")] {
            assert!(!printed.contains("c2VhbGVk"), "{printed}");
            assert!(!printed.contains("topsecret"), "{printed}");
        }
    }

    /// A webhook hands the delivery adapter its URL and sealed secret.
    #[test]
    fn a_webhook_delivers_to_its_url_with_its_secret() {
        let endpoint = DestinationEndpoint::webhook(url("https://acme.example/hooks"), sealed());

        let EndpointDelivery::Webhook {
            url: target,
            signing_secret,
        } = endpoint.delivery()
        else {
            panic!("a webhook delivers as a webhook");
        };
        assert_eq!(target.as_str(), "https://acme.example/hooks");
        assert_eq!(signing_secret, &sealed());
    }

    /// Each kind's stored name reads back as the same kind, and `email` is
    /// no kind.
    #[test]
    fn a_kind_parses_back_from_its_stored_name() {
        for kind in [
            DestinationKind::Slack,
            DestinationKind::Teams,
            DestinationKind::Webhook,
        ] {
            assert_eq!(DestinationKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(DestinationKind::parse("email"), None);
    }
}
