//! Proofs a caller presents of what it is: a workload agent's platform
//! attestation, and a person's passkey; and the proofs the runner beside
//! an agent's sandbox makes for it.
//!
//! Each adapter checks one kind of proof against what the deployment
//! trusts, with the algorithm taken from the trusted key and never from
//! the proof, and refuses anything missing, unreadable or failing. Names
//! lead with the platform or standard the proof follows.

mod attestation;
mod passkeys;
pub(crate) mod runner;

pub(crate) use attestation::{
    AttestationBinding, KeyCache, MOST_KEY_SET_BYTES, Wanted, key_set_in,
};
pub use attestation::{
    AwsAgentAttestor, DiscoveredIssuerKeys, FixedIssuerKeys, GcpAgentAttestor, IssuerKeys,
    JwksWorkloadTokenVerifier, KeyKeeping, MethodAgentAttestor, SpiffeAgentAttestor,
    SpiffeTrustBundle, TpmAgentAttestor, service_named_by,
};
pub use passkeys::{PasskeySettings, SubdomainOrigins, WebauthnPasskeyVerifier};
pub use runner::{JwsRunnerProofs, MountedRunnerKeys};
