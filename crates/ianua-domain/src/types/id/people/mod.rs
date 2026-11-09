//! Ids of a tenant's people and what they ask for: invitations, devices, exports, erasure.

/// Id of a tenant's declared user attribute.
pub(crate) mod attribute_definition;
/// Id of a recorded consent.
pub(crate) mod consent;
/// Id of a request for a copy of a person's data.
pub(crate) mod data_export;
/// Id of a request to erase a person's data.
pub(crate) mod erasure_request;
/// Id of an invitation to join a tenant.
pub(crate) mod invitation;
/// Id of a group of one person's linked accounts.
pub(crate) mod linked_identity;
/// Id of a password reset request.
pub(crate) mod password_reset;
/// Id of an authenticating entity, tenant user or org user.
pub(crate) mod principal;
/// Id of a tenant admin's request to act as one of the tenant's people.
pub(crate) mod support_impersonation;
/// Id of a device a person marked as trusted.
pub(crate) mod trusted_device;
/// Id of a tenant user.
pub(crate) mod user;
/// Id of one import of accounts from another system.
pub(crate) mod user_import;

pub use attribute_definition::AttributeDefinitionId;
pub use consent::ConsentId;
pub use data_export::DataExportId;
pub use erasure_request::ErasureRequestId;
pub use invitation::InvitationId;
pub use linked_identity::LinkedIdentityId;
pub use password_reset::PasswordResetId;
pub use principal::PrincipalId;
pub use support_impersonation::SupportImpersonationId;
pub use trusted_device::TrustedDeviceId;
pub use user::UserId;
pub use user_import::UserImportId;
