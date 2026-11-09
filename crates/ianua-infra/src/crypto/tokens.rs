//! The JWTs the platform signs and the ones it checks: its own access
//! tokens and ID token hints, the proofs clients and agents sign, task
//! tokens, app sessions, run passes, message provenance and the identity
//! assertions the gateway hands upstreams, and the credentials a
//! request presents at the gateway, the tenant's tokens and consumers'
//! own. Workload tokens, which prove where an agent runs, are checked with
//! the other attestations in `proofs::attestation`, reading the shared
//! claims from here.
//!
//! Every check pins the algorithm to the key it checks against, refuses
//! `none`, and holds a token to its times with one allowed clock skew.

mod agents;
mod app_sessions;
mod assertions;
mod claims;
mod clients;
mod consumers;
mod dpop;
mod oauth;
mod presented;
mod provenance;
mod signatures;
mod tasks;

pub use self::agents::Pkcs8AgentAssertionVerifier;
pub use self::app_sessions::Pkcs8AppSessionTokens;
pub use self::assertions::{Pkcs8AssertionSigner, Pkcs8AssertionVerifier};
pub(crate) use self::claims::{Audiences, Times};
pub use self::clients::{JwkClientAssertionVerifier, PublishedKeys};
pub use self::consumers::JwkConsumerTokenVerifier;
pub use self::dpop::JwkDpopProofVerifier;
pub use self::oauth::{Pkcs8AccessTokenJwtVerifier, Pkcs8IdTokenHintVerifier, Pkcs8JwtSigner};
pub use self::presented::{Pkcs8PresentedTokens, Pkcs8RunPasses};
pub use self::provenance::{Pkcs8MessageProvenanceSigner, Pkcs8MessageProvenanceVerifier};
pub use self::signatures::AssertionKeyMessageSigner;
pub use self::tasks::{Pkcs8TaskTokenIssuer, Pkcs8TaskTokenVerifier};
