/// Who a tenant lets in at all, before any credential is checked.
pub mod access;
/// Streaming a tenant's audit records to the SIEM it runs.
pub mod audit_streams;
/// Copying one tenant's setup into another of the same organization.
pub mod clone;
/// A tenant's compliance posture: data residency, audit retention and
/// operator impersonation.
pub mod compliance;
/// What a deployment allows a tenant's compliance posture to be.
pub mod compliance_limits;
pub mod control;
/// A tenant's own domains: registration, proof, certificates and DNS.
pub mod custom_domains;
pub mod environment;
/// Domain events about tenants.
pub mod events;
pub mod hosts;
pub mod lifecycle;
/// Where a tenant's data lives and how its infrastructure comes up.
pub mod provisioning;
/// A new tenant's setup: the steps that make it usable.
pub mod setup;
/// Tenant lifecycle, from provisioning to deletion.
pub mod status;
/// A deleted tenant's teardown: the steps that remove what it held.
pub mod teardown;

#[cfg(test)]
pub(crate) mod fixtures;
