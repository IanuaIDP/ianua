//! Who an agent is: its identity, how it proves it, and whether it may act.

pub mod acting;
pub mod agent;
pub mod attestation;
pub mod challenge;
pub mod control;
pub mod credential;
pub mod exposure_reset;
pub mod fleet_suspension;
pub mod sighting;
pub mod standing;
/// Where an agent identity stands: active, suspended or revoked.
pub mod status;
pub mod token_attack;
