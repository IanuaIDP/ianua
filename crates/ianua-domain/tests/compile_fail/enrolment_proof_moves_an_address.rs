//! A sign-in waiting for its person to set up a second factor lets them set
//! that factor up and nothing else: its proof is no fresh proof of the
//! person, so it never moves the account's address.

use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::identity::account::email_change::{CreateEmailChangeParams, PendingEmailChange};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;

fn readdress(waiting: &Session<ResolvedTenant>, account: &User<ResolvedTenant>, params: CreateEmailChangeParams) {
    let Some(proof) = waiting.enrolment_proof(time::OffsetDateTime::now_utc()) else {
        return;
    };
    let _ = PendingEmailChange::create(account.into(), params, &proof);
}

fn main() {}
