//! Rows of the shared ports: email address changes.

use ianua_domain::domains::identity::account::email_change::{ChangeState, EmailChangeRow};
use ianua_domain::types::{Email, PrincipalId, TokenHash};

use crate::test_support::rows::at;

/// The hash a change row keeps for the link `raw`.
#[must_use]
pub fn link_hash(raw: &str) -> TokenHash {
    TokenHash::from_stored(format!("hash:{raw}"))
}

/// A change `principal` asked for at the fixed moment, from
/// `ann@acme.example` to `to`, waiting on the link `raw` for an hour, its
/// cancel link `cancel-<raw>`.
///
/// # Panics
///
/// When `to` is not an address, which is a mistake in the test.
#[must_use]
pub fn email_change_row(principal: PrincipalId, to: &str, raw: &str) -> EmailChangeRow {
    EmailChangeRow {
        principal_id: principal,
        from_email: Email::new("ann@acme.example").expect("a valid address"),
        new_email: Email::new(to).expect("a valid address"),
        token_hash: link_hash(raw),
        cancel_token_hash: link_hash(&format!("cancel-{raw}")),
        created_at: at(0),
        expires_at: at(3600),
        state: ChangeState::Waiting,
    }
}
