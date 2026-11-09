//! Tenant domain events.

/// Events about who a tenant lets in: sign-in and mutual TLS settings.
pub mod access;
/// Events about streaming a tenant's audit records to its SIEM.
pub mod audit_streams;
/// Events about copying one tenant's setup into another.
pub mod clone;
/// Events about a tenant's own domains, their certificates and DNS records.
pub mod custom_domains;
/// Events about a tenant's life: provisioning, status, settings and deletion.
pub mod lifecycle;
