//! Bodies for connecting an organization's own cloud account.
//!
//! Credentials travel in through these types and never travel back out.
//! [`CloudAccountResponse`] has no field that could carry one: a response
//! type that merely omits a secret today is one line away from including
//! it, whereas a type with nowhere to put it cannot.

use ianua_app::error::AppError;
use ianua_app::use_cases::organization::cloud_accounts::{
    AttachCloudCredentialRequest, ConnectionInstructions,
};
use ianua_domain::domains::organization::cloud::account::{CloudAccount, ConnectionState};
use ianua_domain::domains::organization::cloud::credential::{
    CloudCredential, CloudIdentifier, CloudSecret, ExternalId, GcpKeyFacts, GcpKeyParts,
    GcpServiceAccountKey, KubernetesApiServer, RoleArn,
};
use ianua_domain::domains::tenant::provisioning::infrastructure::{CloudNetwork, CloudProvider};
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::CertificatePem;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::ApiError;

/// What the customer must do to grant us access.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConnectionInstructionsResponse {
    /// The cloud being connected, in its URL spelling.
    pub provider: String,
    /// The shared secret to place in the grant, where the grant has a place
    /// for one.
    ///
    /// Present for AWS, where it goes in the role's trust policy and stops
    /// another customer naming your role ARN and having us assume it for
    /// them. Absent for every other cloud, whose grant has nowhere to put
    /// it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// A ready-made link that opens the customer's own cloud console with
    /// our template loaded. Absent where there is nothing to click through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_url: Option<String>,
    /// What to do, in the order to do it.
    pub steps: Vec<String>,
}

impl ConnectionInstructionsResponse {
    /// What the customer is shown for `instructions`: the external id their
    /// grant needs, if it has a place for one, a console link built from the
    /// deployment's `console_template`, and the steps to follow.
    #[must_use]
    pub(crate) fn of(
        instructions: &ConnectionInstructions,
        console_template: Option<&str>,
    ) -> Self {
        let provider = instructions.provider;
        let external_id = instructions.external_id.as_str();
        Self {
            provider: provider_slug(provider).to_owned(),
            console_url: console_url(console_template, provider, external_id),
            external_id: external_id_for(provider, external_id),
            steps: steps(provider),
        }
    }
}

/// The credential a customer grants us.
///
/// Tagged by cloud rather than carrying a provider field beside a bag of
/// optional secrets: an AWS connection cannot be handed a client secret,
/// because there is no shape in which both appear.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CredentialBody {
    /// A role in your AWS account that trusts ours.
    AwsAssumeRole {
        /// `arn:aws:iam::<account-id>:role/<name>`.
        role_arn: String,
    },
    /// A Google Cloud service account key, as downloaded from the console.
    GcpServiceAccount {
        /// The service account's email address.
        client_email: String,
        /// The key JSON, verbatim.
        key: String,
    },
    /// The Entra application identity and secret used to access the customer's Azure account.
    AzureServicePrincipal {
        /// The Entra directory the principal lives in.
        directory_id: String,
        /// The application id.
        client_id: String,
        /// The client secret.
        secret: String,
    },
    /// A DigitalOcean personal access token. DigitalOcean tokens cannot be
    /// scoped: this grants full control of your account.
    DigitalOceanToken {
        /// The bearer credential granting access to the customer's DigitalOcean account.
        token: String,
    },
    /// A service account in your own Kubernetes cluster, bounded to one
    /// namespace by a role you write and revoked by deleting the account.
    KubernetesServiceAccount {
        /// The API server, as `https://host:port`.
        server: String,
        /// The cluster's CA certificate, PEM-encoded.
        ca_certificate: String,
        /// The service account's bearer token.
        token: String,
    },
}

impl CredentialBody {
    /// Maps a submitted credential after the connection's external id has
    /// been read, refusing an account whose connection has not begun.
    pub(crate) fn attachment(
        self,
        provider: CloudProvider,
        external_id: Option<ExternalId>,
    ) -> Result<AttachCloudCredentialRequest, ApiError> {
        let external_id = external_id.ok_or_else(|| {
            ApiError(AppError::NotFound(message!(
                "api-start-the-connection-before-submitting-a",
                "start the connection before submitting a credential"
            )))
        })?;
        Ok(AttachCloudCredentialRequest {
            credential: self.credential_for(provider, external_id)?,
            now: clock::now(),
        })
    }

    /// Which cloud this body is for.
    #[must_use]
    pub(crate) fn provider(&self) -> CloudProvider {
        match self {
            Self::AwsAssumeRole { .. } => CloudProvider::Aws,
            Self::GcpServiceAccount { .. } => CloudProvider::Gcp,
            Self::AzureServicePrincipal { .. } => CloudProvider::Azure,
            Self::DigitalOceanToken { .. } => CloudProvider::DigitalOcean,
            Self::KubernetesServiceAccount { .. } => CloudProvider::Kubernetes,
        }
    }

    /// The domain's credential for the `provider` connection, guarded by
    /// `external_id`.
    ///
    /// The external id is ours rather than the request's: we generated it,
    /// the customer put it in their trust policy, and letting a request name
    /// another would let a caller ask us to assume a role under a secret we
    /// never issued.
    ///
    /// # Errors
    ///
    /// `422` when the body is for another cloud than `provider`, or a field
    /// is malformed.
    pub(crate) fn credential_for(
        self,
        provider: CloudProvider,
        external_id: ExternalId,
    ) -> Result<CloudCredential, ApiError> {
        if self.provider() != provider {
            return Err(ApiError::validation(message!(
                "api-this-is-the-connection-but-the",
                format!(
                    "this is the {} connection, but the credential is for {}",
                    provider_slug(provider),
                    provider_slug(self.provider())
                )
            )));
        }
        self.resolved(external_id)
    }

    /// The cloud credential this body describes, bound to the external id,
    /// refused when one of its values is not valid.
    fn resolved(self, external_id: ExternalId) -> Result<CloudCredential, ApiError> {
        match self {
            Self::AwsAssumeRole { role_arn } => Ok(CloudCredential::AwsAssumeRole {
                role_arn: RoleArn::new(role_arn).map_err(ApiError::validation)?,
                external_id,
            }),
            Self::GcpServiceAccount { client_email, key } => gcp(client_email, &key),
            Self::AzureServicePrincipal {
                directory_id,
                client_id,
                secret,
            } => Ok(CloudCredential::AzureServicePrincipal {
                directory_id: CloudIdentifier::new(directory_id).map_err(ApiError::validation)?,
                client_id: CloudIdentifier::new(client_id).map_err(ApiError::validation)?,
                secret: CloudSecret::new(secret).map_err(ApiError::validation)?,
            }),
            Self::DigitalOceanToken { token } => Ok(CloudCredential::DigitalOceanToken {
                token: CloudSecret::new(token).map_err(ApiError::validation)?,
            }),
            Self::KubernetesServiceAccount {
                server,
                ca_certificate,
                token,
            } => Ok(CloudCredential::KubernetesServiceAccount {
                server: KubernetesApiServer::new(server).map_err(ApiError::validation)?,
                ca_certificate: CertificatePem::new(ca_certificate)
                    .map_err(ApiError::validation)?,
                token: CloudSecret::new(token).map_err(ApiError::validation)?,
            }),
        }
    }
}

/// The parts of a Google key file the domain decides on. Only these are
/// read; nothing else the customer wrote is kept.
#[derive(Deserialize)]
struct GcpKeyFile {
    #[serde(rename = "type")]
    key_type: String,
    client_email: String,
    token_uri: String,
    #[serde(default)]
    universe_domain: Option<String>,
    project_id: String,
    client_id: String,
    private_key_id: String,
    private_key: String,
}

/// The GCP credential for `client_email` from the key file `key`.
fn gcp(client_email: String, key: &str) -> Result<CloudCredential, ApiError> {
    let file: GcpKeyFile = serde_json::from_str(key).map_err(|_| {
        ApiError::validation(message!(
            "api-the-key-is-not-a-google",
            "the key is not a Google service account key file"
        ))
    })?;
    let client_email = CloudIdentifier::new(client_email).map_err(ApiError::validation)?;
    let parts = GcpKeyParts {
        project_id: CloudIdentifier::new(file.project_id).map_err(ApiError::validation)?,
        client_id: CloudIdentifier::new(file.client_id).map_err(ApiError::validation)?,
        private_key_id: CloudIdentifier::new(file.private_key_id).map_err(ApiError::validation)?,
        private_key: CloudSecret::new(file.private_key).map_err(ApiError::validation)?,
    };
    let facts = GcpKeyFacts {
        key_type: &file.key_type,
        client_email: &file.client_email,
        token_uri: &file.token_uri,
        universe_domain: file.universe_domain.as_deref(),
    };
    let key =
        GcpServiceAccountKey::new(parts, &facts, &client_email).map_err(ApiError::validation)?;
    Ok(CloudCredential::GcpServiceAccount { client_email, key })
}

/// One of an organization's cloud connections.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CloudAccountResponse {
    /// The cloud, in its URL spelling.
    pub provider: String,
    /// Where the connection is: `awaiting_credential`,
    /// `awaiting_verification`, `verified` or `failed`.
    pub state: String,
    /// Whether this connection can be used to provision right now. The
    /// single field a caller should branch on.
    pub usable: bool,
    /// Whose account the credential opened, read back from the cloud.
    /// Present only once verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// When it was last proved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    /// Why it failed, in terms the customer can act on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// Whether the customer can revoke this grant without our help: true
    /// for a role or service account they can delete, false for a bearer
    /// token, which stays valid until we delete our copy.
    pub revocable_by_you: bool,
    /// When the connection was begun.
    pub created_at: String,
}

impl From<&CloudAccount> for CloudAccountResponse {
    fn from(account: &CloudAccount) -> Self {
        let (verified_at, failure_reason, identity) = match account.state() {
            ConnectionState::Verified { at, identity, .. } => {
                (Some(iso(*at)), None, Some(identity.as_str().to_owned()))
            }
            ConnectionState::Failed { at, reason, .. } => {
                (Some(iso(*at)), Some(reason.as_str().to_owned()), None)
            }
            ConnectionState::AwaitingCredential | ConnectionState::AwaitingVerification { .. } => {
                (None, None, None)
            }
        };
        Self {
            provider: provider_slug(account.provider()).to_owned(),
            state: snake_case(account.state().as_str()),
            usable: account.is_usable(),
            account: identity,
            verified_at,
            failure_reason,
            revocable_by_you: account
                .credential()
                .is_some_and(CloudCredential::is_revocable_by_customer),
            created_at: iso(account.created_at()),
        }
    }
}

/// A network the customer can deploy into.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CloudNetworkResponse {
    /// The opaque handle to send back when creating a tenant. Meaningful
    /// only to the cloud that produced it.
    pub handle: String,
    /// The name the customer knows this network by.
    pub name: String,
    /// The deployment location in URL spelling, such as `eu-west-1`.
    pub region: String,
}

impl From<&CloudNetwork> for CloudNetworkResponse {
    fn from(network: &CloudNetwork) -> Self {
        Self {
            handle: network.handle().as_str().to_owned(),
            name: network.display_name().as_str().to_owned(),
            region: network.region().code().to_owned(),
        }
    }
}

/// The URL spelling of a cloud.
fn provider_slug(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "aws",
        CloudProvider::Gcp => "gcp",
        CloudProvider::Azure => "azure",
        CloudProvider::DigitalOcean => "digitalocean",
        CloudProvider::Kubernetes => "kubernetes",
    }
}

/// A timestamp the way every other response writes one.
fn iso(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

/// A domain state name in the wire's snake case.
fn snake_case(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for (index, ch) in value.char_indices() {
        if ch.is_ascii_uppercase() && index > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

/// The link that opens the grant in the customer's cloud console, built
/// from the deployment's template. Only AWS has one to click through.
fn console_url(
    template: Option<&str>,
    provider: CloudProvider,
    external_id: &str,
) -> Option<String> {
    let template = template?;
    match provider {
        CloudProvider::Aws => Some(
            template
                .replace("{external_id}", external_id)
                .replace("{provider}", provider_slug(provider)),
        ),
        CloudProvider::Gcp
        | CloudProvider::Azure
        | CloudProvider::DigitalOcean
        | CloudProvider::Kubernetes => None,
    }
}

/// The external id, for the clouds whose grant has somewhere to put it.
fn external_id_for(provider: CloudProvider, external_id: &str) -> Option<String> {
    match provider {
        CloudProvider::Aws => Some(external_id.to_owned()),
        CloudProvider::Gcp
        | CloudProvider::Azure
        | CloudProvider::DigitalOcean
        | CloudProvider::Kubernetes => None,
    }
}

/// What the customer has to do, per cloud.
fn steps(provider: CloudProvider) -> Vec<String> {
    let steps = match provider {
        CloudProvider::Aws => AWS_STEPS,
        CloudProvider::Gcp => GCP_STEPS,
        CloudProvider::Azure => AZURE_STEPS,
        CloudProvider::Kubernetes => KUBERNETES_STEPS,
        CloudProvider::DigitalOcean => DIGITALOCEAN_STEPS,
    };
    steps.iter().map(|step| (*step).to_owned()).collect()
}

/// Instructions for granting access through an AWS role.
const AWS_STEPS: &[&str] = &[
    "Open the linked CloudFormation template in your AWS account.",
    "Confirm the external id shown here appears in the role's trust policy.",
    "Create the stack, then paste the role ARN it outputs back here.",
];

/// Instructions for supplying a Google service account key.
const GCP_STEPS: &[&str] = &[
    "Create a service account in the Google Cloud project you want the database in.",
    "Grant it the Cloud SQL Admin and Compute Network Viewer roles.",
    "Download a JSON key and paste it here with the account's email address.",
];

/// Instructions for granting access through an Entra service principal.
const AZURE_STEPS: &[&str] = &[
    "Register an application in your Entra directory and create a client secret.",
    "Give its service principal the Contributor role on the subscription.",
    "Paste the directory id, application id and secret here.",
];

/// Instructions for granting access to a Kubernetes namespace.
const KUBERNETES_STEPS: &[&str] = &[
    "Create a namespace for us in your cluster, and a service account in it.",
    "Bind that account to a role covering CloudNativePG clusters and secrets in that \
             namespace, and nothing outside it.",
    "Paste the API server address, the cluster's CA certificate, and the account's \
             token here.",
];

/// Instructions describing the scope of a DigitalOcean personal token.
const DIGITALOCEAN_STEPS: &[&str] = &[
    "Create a personal access token with read and write scope.",
    "Note that DigitalOcean tokens cannot be limited to databases: this grants full \
             control of your account, and you revoke it by deleting the token.",
    "Paste the token here.",
];
