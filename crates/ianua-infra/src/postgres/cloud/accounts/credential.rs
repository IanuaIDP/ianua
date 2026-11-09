//! A cloud credential in the shape it is sealed in: plain text parts, each
//! read back through the domain's own constructor, so a stored credential
//! that no longer passes its rules is refused rather than used.
//!
//! The shape holds secrets in clear, so it never prints and lives only
//! between being opened and being rebuilt, or being built and sealed.

use ianua_domain::domains::organization::cloud::credential::{
    CloudCredential, CloudIdentifier, CloudSecret, ExternalId, GcpKeyFacts, GcpKeyParts,
    GcpServiceAccountKey, KubernetesApiServer, RoleArn,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::CertificatePem;
use serde::{Deserialize, Serialize};

use crate::postgres::foundation::stored::Stored;

const CLOUD_CREDENTIAL: Stored = Stored("cloud credential");

/// The kind of a Google key, as Google writes it in a key file.
const SERVICE_ACCOUNT: &str = "service_account";

/// A credential as it is sealed, one case per cloud.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum StoredCredential {
    /// An AWS role assumed under the connection's external id.
    AwsAssumeRole {
        role_arn: String,
        external_id: String,
    },
    /// A Google service account and its key.
    GcpServiceAccount {
        client_email: String,
        project_id: String,
        client_id: String,
        private_key_id: String,
        private_key: String,
    },
    /// An Azure service principal and its secret.
    AzureServicePrincipal {
        directory_id: String,
        client_id: String,
        secret: String,
    },
    /// A DigitalOcean token.
    DigitalOceanToken { token: String },
    /// A Kubernetes service account's token, and the API server it opens.
    KubernetesServiceAccount {
        server: String,
        ca_certificate: String,
        token: String,
    },
}

impl StoredCredential {
    /// The shape `credential` is sealed in.
    pub(super) fn of(credential: &CloudCredential) -> Self {
        match credential {
            CloudCredential::AwsAssumeRole {
                role_arn,
                external_id,
            } => Self::aws(role_arn, external_id),
            CloudCredential::GcpServiceAccount { client_email, key } => {
                Self::gcp(client_email, key)
            }
            CloudCredential::AzureServicePrincipal {
                directory_id,
                client_id,
                secret,
            } => Self::AzureServicePrincipal {
                directory_id: directory_id.as_str().to_owned(),
                client_id: client_id.as_str().to_owned(),
                secret: secret.expose().to_owned(),
            },
            CloudCredential::DigitalOceanToken { token } => Self::DigitalOceanToken {
                token: token.expose().to_owned(),
            },
            CloudCredential::KubernetesServiceAccount {
                server,
                ca_certificate,
                token,
            } => Self::KubernetesServiceAccount {
                server: server.as_str().to_owned(),
                ca_certificate: ca_certificate.as_str().to_owned(),
                token: token.expose().to_owned(),
            },
        }
    }

    /// Copies the assumed role and its external binding into the sealed representation.
    fn aws(role_arn: &RoleArn, external_id: &ExternalId) -> Self {
        Self::AwsAssumeRole {
            role_arn: role_arn.as_str().to_owned(),
            external_id: external_id.as_str().to_owned(),
        }
    }

    /// Keeps the Google account identity and all private-key fields together for sealing.
    fn gcp(client_email: &CloudIdentifier, key: &GcpServiceAccountKey) -> Self {
        Self::GcpServiceAccount {
            client_email: client_email.as_str().to_owned(),
            project_id: key.project_id().as_str().to_owned(),
            client_id: key.client_id().as_str().to_owned(),
            private_key_id: key.private_key_id().as_str().to_owned(),
            private_key: key.private_key().expose().to_owned(),
        }
    }

    /// The credential this shape holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a part no longer passes
    /// its rules.
    pub(super) fn into_credential(self) -> Result<CloudCredential, DomainError> {
        match self {
            Self::AwsAssumeRole {
                role_arn,
                external_id,
            } => aws_from(role_arn, external_id),
            Self::GcpServiceAccount {
                client_email,
                project_id,
                client_id,
                private_key_id,
                private_key,
            } => gcp_from(
                client_email,
                key_parts(project_id, client_id, private_key_id, private_key)?,
            ),
            Self::AzureServicePrincipal {
                directory_id,
                client_id,
                secret: client_secret,
            } => azure_from(directory_id, client_id, client_secret),
            Self::DigitalOceanToken { token } => Ok(CloudCredential::DigitalOceanToken {
                token: secret(token)?,
            }),
            Self::KubernetesServiceAccount {
                server,
                ca_certificate,
                token,
            } => kubernetes_from(server, ca_certificate, token),
        }
    }
}

/// Validates the role and external identifier before rebuilding an AWS credential.
fn aws_from(role_arn: String, external_id: String) -> Result<CloudCredential, DomainError> {
    Ok(CloudCredential::AwsAssumeRole {
        role_arn: CLOUD_CREDENTIAL.value("role", RoleArn::new(role_arn))?,
        external_id: CLOUD_CREDENTIAL.value("external id", ExternalId::new(external_id))?,
    })
}

/// Validates the identifiers and key material read from a stored Google key.
fn key_parts(
    project_id: String,
    client_id: String,
    private_key_id: String,
    private_key: String,
) -> Result<GcpKeyParts, DomainError> {
    Ok(GcpKeyParts {
        project_id: identifier("project", project_id)?,
        client_id: identifier("client", client_id)?,
        private_key_id: identifier("private key id", private_key_id)?,
        private_key: secret(private_key)?,
    })
}

/// Validates the tenant, application and secret of a stored Azure principal.
fn azure_from(
    directory_id: String,
    client_id: String,
    client_secret: String,
) -> Result<CloudCredential, DomainError> {
    Ok(CloudCredential::AzureServicePrincipal {
        directory_id: identifier("directory", directory_id)?,
        client_id: identifier("client", client_id)?,
        secret: secret(client_secret)?,
    })
}

/// Validates the cluster address, trust certificate and service-account token.
fn kubernetes_from(
    server: String,
    ca_certificate: String,
    token: String,
) -> Result<CloudCredential, DomainError> {
    Ok(CloudCredential::KubernetesServiceAccount {
        server: CLOUD_CREDENTIAL.value("API server", KubernetesApiServer::new(server))?,
        ca_certificate: CLOUD_CREDENTIAL
            .value("CA certificate", CertificatePem::new(ca_certificate))?,
        token: secret(token)?,
    })
}

/// A Google service account `client_email` signs in as with the key
/// `parts`, at Google's own endpoints.
fn gcp_from(client_email: String, parts: GcpKeyParts) -> Result<CloudCredential, DomainError> {
    let client_email = identifier("client email", client_email)?;
    let facts = GcpKeyFacts {
        key_type: SERVICE_ACCOUNT,
        client_email: client_email.as_str(),
        token_uri: GcpServiceAccountKey::TOKEN_URI,
        universe_domain: None,
    };
    let key =
        GcpServiceAccountKey::new(parts, &facts, &client_email).map_err(DomainError::infra)?;
    Ok(CloudCredential::GcpServiceAccount { client_email, key })
}

/// A stored identifier, read back through its rules.
fn identifier(what: &'static str, stored: String) -> Result<CloudIdentifier, DomainError> {
    CLOUD_CREDENTIAL.value(what, CloudIdentifier::new(stored))
}

/// A stored secret, read back through its rules.
fn secret(stored: String) -> Result<CloudSecret, DomainError> {
    CLOUD_CREDENTIAL.value("secret", CloudSecret::new(stored))
}
