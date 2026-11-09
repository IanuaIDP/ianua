//! Agent credentials: the keys an agent signs in with, signing in with
//! them, exchanging a sign-in for a task token, and attestation.

pub(crate) mod exchange_token_for;
pub(in crate::use_cases::agents) mod key_enrolment;
pub(crate) mod list;
pub(crate) mod mint;
pub(crate) mod request_attestation_challenge;
pub(crate) mod require_reattestation;
pub(crate) mod revoke;
pub(crate) mod rotate;
pub(crate) mod set_attestation_policy;
mod token_ceiling;

pub use exchange_token_for::{
    ExchangeTokenForAgentRequest, ExchangeTokenForAgentUseCase, ExchangeTokenPorts, ExchangedToken,
};
pub use list::{ListPorts, ListUseCase};
pub use mint::{MintPorts, MintRequest, MintUseCase};
pub use request_attestation_challenge::{
    RequestAttestationChallengePorts, RequestAttestationChallengeUseCase,
};
pub use require_reattestation::{RequireReattestationPorts, RequireReattestationUseCase};
pub use revoke::{RevokePorts, RevokeRequest, RevokeUseCase};
pub use rotate::{RotatePorts, RotateRequest, RotateUseCase};
pub use set_attestation_policy::{
    SetAttestationPolicyPorts, SetAttestationPolicyRequest, SetAttestationPolicyUseCase,
};
