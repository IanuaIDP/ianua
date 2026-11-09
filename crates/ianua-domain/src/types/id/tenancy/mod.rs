//! Ids of organizations, their members and tenants, and the domains tenants own.

/// Id of a TLS certificate bundle.
pub(crate) mod certificate;
/// Id of a domain a tenant registered.
pub(crate) mod domain;
/// Id of an organization API key.
pub(crate) mod org_api_key;
/// Id of an invitation to join an organization.
pub(crate) mod org_invitation;
/// Id of an org-level user.
pub(crate) mod org_user;
/// Id of an organization.
pub(crate) mod organization;
/// Id of a tenant.
pub(crate) mod tenant;
/// Id of a copy of one tenant's setup into another.
pub(crate) mod tenant_clone;

pub use certificate::CertificateId;
pub use domain::DomainId;
pub use org_api_key::OrgApiKeyId;
pub use org_invitation::OrgInvitationId;
pub use org_user::OrgUserId;
pub use organization::OrganizationId;
pub use tenant::TenantId;
pub use tenant_clone::TenantCloneId;
