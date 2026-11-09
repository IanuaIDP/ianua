/// The audience a token is meant for.
pub mod audience;
/// A tenant's human-readable name.
pub mod display_name;
/// A domain name owned by a tenant.
pub mod domain_name;
/// A validated email address.
pub mod email;
/// What an event calls the thing it is about.
pub mod event_label;
pub mod field_path;
/// The issuer a token or assertion is held to.
pub mod issuer;
/// Short, validated user-supplied names.
pub mod label;
pub mod nonce;
/// A permission as a token carries it.
pub mod permission_name;
pub mod saml_entity_id;
/// The format of a SAML `NameID`.
pub mod saml_name_id_format;
/// OAuth and API key scopes.
pub mod scope;
/// The URL-safe slug that names a tenant.
pub mod tenant_slug;
/// Longer validated free-form text.
pub mod text;
/// Text recorded because it is not trusted, made safe to store.
pub mod untrusted_text;

pub use audience::Audience;
pub use display_name::DisplayName;
pub use domain_name::DomainName;
pub use email::Email;
pub use issuer::Issuer;
pub use nonce::Nonce;
pub use permission_name::PermissionName;
pub use saml_entity_id::SamlEntityId;
pub use saml_name_id_format::SamlNameIdFormat;
pub use scope::Scope;
pub use tenant_slug::TenantSlug;
