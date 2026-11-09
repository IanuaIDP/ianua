//! Ids of what the gateway serves and who calls through it.

/// Id of a private-network connector a tenant runs for the gateway.
pub(crate) mod connector;
/// Id of a tenant consumer (a machine identity).
pub(crate) mod consumer;
/// Id of an account an application binds to the LDAP directory as.
pub(crate) mod directory_service_account;
/// Id of a service's outbound allowlist.
pub(crate) mod egress_policy;
/// Id of a client certificate for the LDAP gateway.
pub(crate) mod ldap_certificate;
/// Id of a place a tenant's request records are shipped to.
pub(crate) mod log_shipping_target;
/// Id of a proxy pipeline.
pub(crate) mod pipeline;
/// Id of a tenant route.
pub(crate) mod route;
/// Id of a gateway service.
pub(crate) mod service;
/// Id of a stage in a proxy pipeline.
pub(crate) mod stage;
/// Id of a stream route.
pub(crate) mod stream_route;

pub use connector::ConnectorId;
pub use consumer::ConsumerId;
pub use directory_service_account::DirectoryServiceAccountId;
pub use egress_policy::EgressPolicyId;
pub use ldap_certificate::LdapCertificateId;
pub use log_shipping_target::LogShippingTargetId;
pub use pipeline::PipelineId;
pub use route::RouteId;
pub use service::ServiceId;
pub use stage::StageId;
pub use stream_route::StreamRouteId;
