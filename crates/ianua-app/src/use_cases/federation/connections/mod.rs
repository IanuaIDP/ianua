//! Federation connections: setting one up, changing it, switching it on and
//! off, the keys its SAML provider signs and seals with, and the groups its
//! provider's people bring.

pub(crate) mod discover;
/// Mapping a provider's groups to the tenant's roles and groups.
pub(crate) mod groups;
/// A connection added, changed, switched and removed.
pub(crate) mod lifecycle;
/// SAML specifics: certificates, encrypted assertions, metadata.
pub(crate) mod saml;
/// What a connection is set up with, as read and stored.
pub(crate) mod settings;

pub use discover::{DiscoverPorts, DiscoverUseCase, HomeRealm};
pub use groups::{
    GroupRuleRequest, MapProviderGroupsPorts, MapProviderGroupsRequest, MapProviderGroupsUseCase,
    StopMappingGroupsPorts, StopMappingGroupsUseCase,
};
pub use lifecycle::{
    AccountProvisioning, ActivatePorts, ActivateUseCase, ConnectionFilter, CreatePorts,
    CreateRequest, CreateUseCase, DeletePorts, DeleteUseCase, DisablePorts, DisableUseCase,
    GetPorts, GetUseCase, ListPorts, ListRequest, ListUseCase, UpdatePorts, UpdateRequest,
    UpdateUseCase,
};
pub use saml::{
    AcceptReadableAssertionsPorts, AcceptReadableAssertionsUseCase, RefreshMetadataPorts,
    RefreshMetadataUseCase, RequireEncryptedAssertionsPorts, RequireEncryptedAssertionsRequest,
    RequireEncryptedAssertionsUseCase, RollOverCertificatePorts, RollOverCertificateUseCase,
    SpKeySource, SpMetadataPorts, SpMetadataRequest, SpMetadataUseCase,
};
pub use settings::{OidcProviderConfig, ProviderConfig, SamlProviderConfig};
