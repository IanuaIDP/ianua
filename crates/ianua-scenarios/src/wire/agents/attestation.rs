//! An agent bootstrapping from a platform attestation: the challenge the
//! platform issues, and the proof bound to it and to the key enrolled.

use serde::{Deserialize, Serialize};

use super::identity::EnrolledKey;

/// The single-use challenge a bootstrap's proof is bound to.
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    /// The nonce to bind.
    pub nonce: String,
}

/// `POST …/agents/{id}/bootstrap`: the key the workload made and the
/// attestation vouching for it. Holds the proof, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct Bootstrap {
    /// The key to enrol.
    #[serde(flatten)]
    pub key: EnrolledKey,
    /// Platform proof binding this workload to the enrolled key.
    pub attestation: Attestation,
}

/// A platform attestation bound to a challenge and a key. Holds the proof,
/// so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct Attestation {
    /// The method, such as `spiffe`.
    pub method: String,
    /// What the platform vouches with, such as the SVID chain as PEM.
    pub material: String,
    /// The challenge's nonce.
    pub nonce: String,
    /// The workload key's signature over the binding, base64url.
    pub signature: String,
}
