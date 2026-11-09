//! A company's own cloud accounts: the connection it begins, the
//! credential it hands over, and whose account that opened.

use serde::{Deserialize, Serialize};

/// One connection, as the company's cloud accounts list it. Never holds
/// a credential.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudAccount {
    /// The cloud, in its URL spelling, such as `kubernetes`.
    pub provider: String,
    /// `awaiting_credential`, `awaiting_verification`, `verified` or
    /// `failed`.
    pub state: String,
    /// Whether it can be used to provision now.
    pub usable: bool,
    /// Whose account the credential opened, once proved.
    #[serde(default)]
    pub account: Option<String>,
    /// When it was last proved.
    #[serde(default)]
    pub verified_at: Option<String>,
    /// Why the cloud refused it, when it did.
    #[serde(default)]
    pub failure_reason: Option<String>,
    /// Whether the customer can withdraw the grant at their own end.
    pub revocable_by_you: bool,
}

/// `POST …/cloud-accounts/{provider}`: what the customer does next.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionInstructions {
    /// The cloud being connected, in its URL spelling.
    pub provider: String,
    /// The value for a role's trust policy, for a cloud that uses one.
    #[serde(default)]
    pub external_id: Option<String>,
    /// The steps to follow, in order.
    pub steps: Vec<String>,
}

/// `PUT …/credential`: the grant the customer made.
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudGrant {
    /// A DigitalOcean API token.
    DigitalOceanToken {
        /// What the cluster takes as proof, kept sealed.
        token: String,
    },
    /// A Kubernetes cluster's service account.
    KubernetesServiceAccount {
        /// The API server's `https` address.
        server: String,
        /// The cluster's CA certificate, PEM encoded.
        ca_certificate: String,
        /// The service account's bearer token.
        token: String,
    },
}

/// One network a database could be placed in.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudNetwork {
    /// The opaque handle for placing a tenant.
    pub handle: String,
    /// The name the customer knows it by.
    pub name: String,
    /// The cloud region the network lives in, such as `eu-west-1`.
    pub region: String,
}
