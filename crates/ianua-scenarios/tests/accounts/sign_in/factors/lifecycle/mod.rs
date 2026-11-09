//! What becomes of Max's sign-ins when his factor changes hands: a setup
//! he gives up, a factor he turns off or that Acme's policy keeps on, and
//! a lost factor that Ann resets or that a printed code recovers. Each
//! refused step is followed by the sign-in that still works, and each
//! accepted one by the sign-in it changed.
//!
//! - `turning_off`: a setup given up starts over and its old secret
//!   confirms nothing; turning a factor off needs a fresh code, and a
//!   required factor stays on even with one.
//! - `replacing`: Ann's reset of a lost factor ends Max's access and lets
//!   a new phone in; a recovery code under a required factor opens nothing
//!   until a new phone is confirmed.

mod replacing;
mod turning_off;

use ianua_scenarios::wire::sign_in::{MemberFactorSetup, MemberProof};

/// Max's `password` typed again, as a signed-in member proves themselves
/// to begin or give up a setup.
fn setup(password: &str) -> MemberFactorSetup {
    MemberFactorSetup {
        proof: MemberProof {
            password: password.to_owned(),
            code: None,
        },
    }
}
