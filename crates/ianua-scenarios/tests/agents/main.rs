//! Agents, as the platform meets them: external agents an LLM SDK runs,
//! holding their own keys and calling the agent API in their own name, and
//! agents the platform runs with a tenant's model provider. Every scenario
//! reads the audit trail for what it recorded, and tries its endpoints as
//! the whole cast.
//!
//! - `life`: Reporter from the key it enrols to the key Ann revokes: Ann's
//!   grant, its own tokens, the relay, passing authority on to Helper,
//!   waiting on Tess, spending the relay's allowance, and the revocation.
//! - `misbehaviour`: each misstep Reporter or Helper can make, refused:
//!   a replayed assertion, another agent's name or token, a token or a
//!   hand-on wider than the grant, and a misspelt field.
//! - `sdk`: Reporter's loop, scripted in both providers' formats, and
//!   free under whichever model `IANUA_SCENARIO_MODEL` chooses.
//! - `attestation`: Reporter proving where it runs with no standing key,
//!   and every false attestation refused.
//! - `platform_runs`: Triage, run by the platform, reading a ticket that
//!   plants an instruction to delete everything, which the run refuses.
//! - `spending`: Triage pauses once it spent what Ann lets it spend
//!   unasked, and goes on only when she resumes it.
//! - `oversight`: agents kept in check at the tenant's apps behind the
//!   gateway: MCP tools held to their grant, suspension, the kill switch
//!   and a stolen token, request budgets, calls held for a person, the
//!   chain of authority back to Ann, and agents watching agents.

#![cfg(test)]

mod attestation;
mod life;
mod misbehaviour;
mod oversight;
mod platform_runs;
mod sdk;
mod spending;
mod support;
