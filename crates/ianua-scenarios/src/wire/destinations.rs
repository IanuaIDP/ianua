//! Where outside the app a company's notifications are posted: a Slack
//! or Teams channel, or a webhook of its own.

use serde::{Deserialize, Serialize};

/// A destination's form: `POST` to add one, `PUT` to replace one whole.
/// Holds the address, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct DestinationForm {
    /// What the company calls it.
    pub name: String,
    /// Where it posts.
    pub target: DestinationTarget,
    /// The categories it receives, such as `Pipeline`.
    pub categories: Vec<String>,
    /// The least severity it receives: `Info`, `Warning` or `Critical`.
    pub minimum_severity: String,
}

/// Where a destination posts. Holds its address, so it has no `Debug`.
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DestinationTarget {
    /// A Slack channel, through its incoming-webhook address.
    Slack {
        /// The address on `hooks.slack.com`.
        url: String,
    },
    /// An HTTPS endpoint of the company's own, whose posts are signed.
    Webhook {
        /// Where the posts go, an `https` address.
        url: String,
    },
}

/// `POST …/destinations`: the id made, and a webhook's signing secret.
/// Holds the secret, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct DestinationAdded {
    /// The destination's id.
    pub id: String,
    /// A webhook's signing secret, in this answer and never again.
    #[serde(default)]
    pub signing_secret: Option<String>,
}

/// `PUT …/destinations/{id}`: a webhook's new signing secret. Holds the
/// secret, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct DestinationChanged {
    /// The new signing secret, in this answer and never again.
    #[serde(default)]
    pub signing_secret: Option<String>,
}

/// One destination as the list shows it, its address and secret never
/// among what is read.
#[derive(Debug, Clone, Deserialize)]
pub struct Destination {
    /// The destination's id.
    pub id: String,
    /// What the company calls it.
    pub name: String,
    /// `slack`, `teams` or `webhook`.
    pub kind: String,
    /// The categories it receives.
    pub categories: Vec<String>,
    /// The least severity it receives.
    pub minimum_severity: String,
    /// `active` or `paused`.
    pub state: String,
}
