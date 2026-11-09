//! An emailed link is spent against the account it was sent to, never on its
//! own.

use ianua_domain::domains::identity::tokens::purpose::TenantLinkPurpose;
use ianua_domain::domains::identity::tokens::secure::SecureToken;
use ianua_domain::isolation::scope::TenantScope;
use time::OffsetDateTime;

fn spend<T: TenantScope, Purpose: TenantLinkPurpose>(token: &mut SecureToken<T, Purpose>, now: OffsetDateTime) {
    let _ = token.redeem(now);
}

fn main() {}
