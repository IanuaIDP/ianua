//! Ianua as the identity provider: holding the sign-in requests the
//! tenant's SAML apps send, answering them, and its metadata.

pub(crate) mod build_saml_response;
pub(crate) mod get_metadata;
mod held_names;
pub(in crate::use_cases::federation) mod lookup;
pub(crate) mod receive_sign_in;
mod signed_answer;

pub use build_saml_response::{
    BuildSamlResponsePorts, BuildSamlResponseRequest, BuildSamlResponseUseCase, SamlClaimPorts,
    SamlProviderPorts, SamlResponseOutput, SamlSignInTrigger, SamlSigningPorts,
};
pub use get_metadata::{GetMetadataPorts, GetMetadataRequest, GetMetadataUseCase};
pub use receive_sign_in::{ReceiveSignInPorts, ReceiveSignInRequest, ReceiveSignInUseCase};
