//! An agent and the keys it signs in with.

use serde::{Deserialize, Serialize};

use super::Principal;

/// A public key an agent enrols: its algorithm and its SPKI PEM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledKey {
    /// `ES256`, `RS256` or `EdDSA`.
    pub algorithm: String,
    /// The public key as SPKI PEM.
    pub public_key: String,
}

/// `POST …/agents`: a new agent, with its first key enrolled or with the
/// platform attestations it proves itself by.
#[derive(Debug, Clone, Default, Serialize)]
pub struct NewAgent {
    /// Label shown to people selecting or reviewing the workload.
    pub name: String,
    /// What it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The attestation methods it proves itself by, such as `spiffe`;
    /// given with `re_attest_every`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_methods: Option<Vec<String>>,
    /// The most seconds between two attestations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub re_attest_every: Option<u32>,
    /// Where an attested workload may run, such as
    /// `spiffe://<trust domain>/<path>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origins: Option<Vec<String>>,
    /// The key it signs in with, for an agent that holds one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<EnrolledKey>,
}

/// The agent a creation made, and the credential of the key it enrolled.
#[derive(Debug, Clone, Deserialize)]
pub struct CreatedAgent {
    /// The agent's id.
    pub id: String,
    /// The credential made of the enrolled key, when one was enrolled.
    #[serde(default)]
    pub credential: Option<Credential>,
}

/// An agent as its readers see it.
#[derive(Debug, Clone, Deserialize)]
pub struct Agent {
    /// Handle used in agent routes and delegation requests.
    pub id: String,
    /// Label shown to people selecting or reviewing the workload.
    pub name: String,
    /// Who owns it.
    pub owner: Principal,
    /// `Active`, `Suspended` or `Revoked`.
    pub status: String,
    /// Whether it may act right now: `Active`, `MustReattest`, `Suspended`
    /// or `Revoked`.
    pub standing: String,
    /// The attestation methods it proves itself by, when it attests.
    #[serde(default)]
    pub trusted_methods: Option<Vec<String>>,
}

/// What containing an agent tore down.
#[derive(Debug, Clone, Deserialize)]
pub struct Contained {
    /// How many delegations fell: the agent's own and every one cut from
    /// them.
    pub revoked_count: u32,
}

/// What stopping every agent in a tenant came to.
#[derive(Debug, Clone, Deserialize)]
pub struct SuspendedAll {
    /// How many active agents were suspended.
    pub suspended_count: u32,
}

/// One of an agent's keys, as the platform keeps it: the id an assertion
/// names it by, and its standing.
#[derive(Debug, Clone, Deserialize)]
pub struct Credential {
    /// The credential's id.
    pub id: String,
    /// The agent it signs in.
    pub agent_id: String,
    /// The key id an assertion's header names.
    pub kid: String,
    /// Signature scheme accepted for assertions using this key.
    pub algorithm: String,
    /// `active`, `rotated` or `revoked`.
    pub status: String,
    /// Its public key as SPKI PEM.
    pub public_key: String,
    /// The attestation it was issued against, for a bootstrapped key.
    #[serde(default)]
    pub attestation: Option<CredentialAttestation>,
}

/// What a bootstrapped key was attested by.
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialAttestation {
    /// The method, such as `spiffe`.
    pub method: String,
    /// Who the attestation named, such as a SPIFFE ID.
    pub subject: String,
}
