//! A stored session's progress can be read but never reused: a new session
//! starts only from a way in proved for its account, not from progress
//! copied out of another session.

use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgress;
use ianua_domain::isolation::scope::ResolvedTenant;

struct Copied {
    progress: SignInProgress,
}

fn reuse(stored: &Session<ResolvedTenant>, mut copied: Copied) -> Copied {
    copied.progress = *stored.progress();
    copied
}

fn main() {}
