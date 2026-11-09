//! Directory bodies: LDAP client certificates, and the service accounts
//! applications bind to the directory as.

use ianua_app::use_cases::directory::certificates::{IssueLdapRequest, IssuedCertificate};
use ianua_app::use_cases::directory::service_accounts::{
    ChangeScopeRequest, CreateRequest, CreatedServiceAccount,
};
use ianua_domain::domains::authentication::directory_service::account::{
    DirectoryServiceAccount, ServiceAccountStatus,
};
use ianua_domain::domains::authentication::directory_service::scope::{
    BaseDn, DirectoryAccess, ServiceAccountName, ServiceAccountScope,
};
use ianua_domain::domains::authentication::ldap_certificate::LdapClientCertificate;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DirectoryServiceAccountId, Label};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::tenant::proof::FreshProofBody;
use crate::error::ApiError;

/// Request body for issuing an LDAP client certificate.
///
/// `csr_pem` is a PEM-encoded PKCS#10 signing request made on the device;
/// the private key is never sent.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct IssueLdapCertificateBody {
    /// The signing request, PEM-encoded.
    pub csr_pem: String,
    /// A name for the device, such as "MacBook, VPN client".
    pub device_label: String,
    /// What the person gives again to prove it is them.
    pub proof: FreshProofBody,
}

impl TryFrom<IssueLdapCertificateBody> for IssueLdapRequest {
    type Error = ApiError;

    fn try_from(body: IssueLdapCertificateBody) -> Result<Self, Self::Error> {
        Ok(Self {
            csr_pem: body.csr_pem,
            device_label: Label::new("device_label", &body.device_label)
                .map_err(ApiError::validation)?,
            proof: body.proof.try_into()?,
        })
    }
}

/// A certificate just issued, the only time its PEM is shown.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct IssuedLdapCertificateResponse {
    /// The certificate's id.
    pub certificate_id: String,
    /// The signed certificate, PEM-encoded.
    pub certificate_pem: String,
    /// When it stops being valid.
    pub expires_at: String,
}

impl From<IssuedCertificate> for IssuedLdapCertificateResponse {
    fn from(issued: IssuedCertificate) -> Self {
        Self {
            certificate_id: issued.certificate_id.to_string(),
            certificate_pem: issued.certificate_pem.as_str().to_owned(),
            expires_at: issued.expires_at.to_string(),
        }
    }
}

/// A person's LDAP client certificates.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LdapCertificateListResponse {
    /// Each certificate, without its PEM.
    pub certificates: Vec<LdapCertificateEntry>,
}

impl From<Vec<LdapClientCertificate<ResolvedTenant>>> for LdapCertificateListResponse {
    fn from(certificates: Vec<LdapClientCertificate<ResolvedTenant>>) -> Self {
        Self {
            certificates: certificates
                .iter()
                .map(LdapCertificateEntry::from)
                .collect(),
        }
    }
}

/// One certificate, as recorded when it was issued.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LdapCertificateEntry {
    /// The certificate's id.
    pub id: String,
    /// The device's name.
    pub device_label: String,
    /// When it was issued.
    pub issued_at: String,
    /// When it stops being valid.
    pub expires_at: String,
    /// Whether it was revoked.
    pub revoked: bool,
}

impl From<&LdapClientCertificate<ResolvedTenant>> for LdapCertificateEntry {
    fn from(certificate: &LdapClientCertificate<ResolvedTenant>) -> Self {
        Self {
            id: certificate.id().to_string(),
            device_label: certificate.device_label().as_str().to_owned(),
            issued_at: certificate.issued_at().to_string(),
            expires_at: certificate.expires_at().to_string(),
            revoked: certificate.revoked_at().is_some(),
        }
    }
}

/// What a service account may reach: whether it may write, and under which
/// parts of the directory.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ServiceAccountScopeBody {
    /// Always `ReadOnly`: a service account never writes the directory.
    #[schema(schema_with = crate::dto::schemas::directory_access)]
    pub access: DirectoryAccess,
    /// The base DNs it may read under, such as `ou=people,dc=acme,dc=com`;
    /// one to sixteen.
    pub base_dns: Vec<String>,
}

impl TryFrom<ServiceAccountScopeBody> for ServiceAccountScope {
    type Error = ApiError;

    fn try_from(body: ServiceAccountScopeBody) -> Result<Self, ApiError> {
        let base_dns = body
            .base_dns
            .into_iter()
            .map(|dn| BaseDn::new(dn).map_err(ApiError::validation))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(body.access, base_dns).map_err(ApiError::validation)
    }
}

/// Request body for making a service account.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateServiceAccountBody {
    /// The name it binds as, lowercase letters, digits and hyphens, such as
    /// `jira`.
    pub name: String,
    /// What it may reach.
    pub scope: ServiceAccountScopeBody,
}

impl TryFrom<CreateServiceAccountBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateServiceAccountBody) -> Result<Self, ApiError> {
        Ok(Self {
            name: ServiceAccountName::new(body.name).map_err(ApiError::validation)?,
            scope: body.scope.try_into()?,
        })
    }
}

impl ServiceAccountScopeBody {
    /// The change of `id`'s scope to this one.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when a base DN is malformed or repeated,
    ///   or there are none or more than sixteen.
    pub(crate) fn change_of(
        self,
        id: DirectoryServiceAccountId,
    ) -> Result<ChangeScopeRequest, ApiError> {
        Ok(ChangeScopeRequest {
            id,
            scope: self.try_into()?,
        })
    }
}

/// A service account, without its secret, which only its hash is kept of.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ServiceAccountResponse {
    /// The account's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: DirectoryServiceAccountId,
    /// The name it binds as.
    pub name: String,
    /// Always `ReadOnly`: a service account never writes the directory.
    #[schema(schema_with = crate::dto::schemas::directory_access)]
    pub access: DirectoryAccess,
    /// The base DNs it may read under.
    pub base_dns: Vec<String>,
    /// `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::service_account_status)]
    pub status: ServiceAccountStatus,
    /// When it was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When its secret last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub secret_changed_at: OffsetDateTime,
}

impl From<&DirectoryServiceAccount<ResolvedTenant>> for ServiceAccountResponse {
    fn from(account: &DirectoryServiceAccount<ResolvedTenant>) -> Self {
        Self {
            id: *account.id(),
            name: account.name().as_str().to_owned(),
            access: account.scope().access(),
            base_dns: account
                .scope()
                .base_dns()
                .iter()
                .map(|dn| dn.as_str().to_owned())
                .collect(),
            status: account.status(),
            created_at: account.created_at(),
            secret_changed_at: account.secret_changed_at(),
        }
    }
}

/// The tenant's service accounts.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ServiceAccountListResponse {
    /// Each account, by name.
    pub service_accounts: Vec<ServiceAccountResponse>,
}

impl From<Vec<DirectoryServiceAccount<ResolvedTenant>>> for ServiceAccountListResponse {
    fn from(accounts: Vec<DirectoryServiceAccount<ResolvedTenant>>) -> Self {
        Self {
            service_accounts: accounts.iter().map(ServiceAccountResponse::from).collect(),
        }
    }
}

/// A service account just made, the only time its secret is shown.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreatedServiceAccountResponse {
    /// The new account's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: DirectoryServiceAccountId,
    /// The secret it binds with. Store it now: it is not shown again.
    pub secret: String,
}

impl From<CreatedServiceAccount> for CreatedServiceAccountResponse {
    fn from(created: CreatedServiceAccount) -> Self {
        Self {
            id: created.id,
            secret: created.secret.expose().to_owned(),
        }
    }
}

/// A service account's new secret, the only time it is shown.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ServiceAccountSecretResponse {
    /// The secret it binds with from now on. Store it now: it is not shown
    /// again.
    pub secret: String,
}

impl From<Secret> for ServiceAccountSecretResponse {
    fn from(secret: Secret) -> Self {
        Self {
            secret: secret.expose().to_owned(),
        }
    }
}
