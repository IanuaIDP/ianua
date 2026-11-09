//! People in a tenant, as the platform meets them: Pat is invited by
//! Tess, joins, signs in in every way the platform offers, and the whole
//! cast tries each step's protected reads; and the passkey answers the
//! platform refuses.
//!
//! - `life`: Pat, from the invitation to a password reset by mail.
//! - `passkeys`: a relayed passkey answer and a copied key, refused.

#![cfg(test)]

mod life;
mod passkeys;
mod support;
