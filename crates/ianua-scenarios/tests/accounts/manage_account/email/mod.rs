//! A move to another mailbox, on both planes. The platform mails a link
//! to the new mailbox, which confirms the move, and one to the old, which
//! calls it off; until the new link is followed nothing changes, and
//! afterwards only the new address signs in.
//!
//! - `tenant`: Pat moves, the old mailbox calls a move off, a move is
//!   confirmed only by its own link in its own tenant, and an expired
//!   move is renewed to the same mailbox.
//! - `guarded`: a wrong password or Uma's address moves nobody, a
//!   password change kills a pending move, and Pat with an authenticator
//!   moves only with a fresh code.
//! - `member`: Max moves his mailbox and signs in from it as himself, and
//!   calls a move off, which no tenant link could confirm.

mod guarded;
mod member;
mod tenant;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::people;
use ianua_scenarios::world::World;

use crate::support::{device, still_signed_in};

/// `original`, signing in on a fresh device at `address`, the mailbox they
/// moved to, with the password they had: the same account, under the new
/// address, proved, reaching what it reached before.
///
/// # Panics
///
/// When the sign-in is refused, or reads another account.
pub(super) async fn signs_in_at_new_address(world: &World<'_>, original: &Person, address: &str) {
    let mut account = original.account().clone();
    account.email = address.to_owned();
    let mut moved = Person::new(
        device(world.stack(), "Pat at her new mailbox"),
        account,
        original.password(),
    );
    moved.record_invitation(original.id());
    moved.sign_in(world.stack()).await;
    let own = people::me(world.tenant()).send(moved.client()).await.ok();
    assert_eq!(
        own.id,
        original.id(),
        "the new address signs in to the same account"
    );
    assert_eq!(own.email, address, "the account carries its new address");
    assert!(own.email_verified, "the new mailbox counts as proved");
    still_signed_in(world, &moved).await;
}
