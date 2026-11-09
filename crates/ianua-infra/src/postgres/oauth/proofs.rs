//! The ledgers of signed proofs already used, so a copied one never works
//! twice: the replay guards of `ports/oauth/proofs.rs`. Checking a proof's
//! signature is the crypto adapters' work, not a store's.

mod assertions;
mod dpop;

pub use assertions::PgAssertionReplayGuard;
pub use dpop::PgDpopReplayGuard;
