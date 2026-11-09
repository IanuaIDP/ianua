pub mod account_privilege;
pub mod admission;
/// Connections to external identity providers over SAML or OIDC.
pub mod connection;
/// Federated identity-provider connection status: active or disabled.
pub mod connection_status;
pub mod control;
mod directory_profile;
/// Domain events for the federation bounded context.
pub mod events;
pub mod link;
/// OpenID Connect: the identity a provider vouches for.
pub mod oidc;
/// The values a provider sends under a claim or an attribute.
pub mod provider_values;
/// SAML: requests, assertions and metadata.
pub mod saml;
/// SCIM provisioning endpoints and what SCIM changes do to accounts.
pub mod scim;
pub mod scope_token;
/// SAML apps: outside services a tenant's people sign in to, with this
/// platform as the identity provider.
pub mod service_provider;
/// A sign-in sent to a connection's provider, as it is recorded.
pub mod sign_in_start;
pub mod vouched_identity;

#[cfg(test)]
pub(crate) mod fixtures;
