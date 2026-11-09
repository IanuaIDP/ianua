//! What a person acting on their own account comes with: the account, the
//! proof they signed in, and the session or bind behind it.

use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignedIn;
use ianua_domain::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;

/// A person signed in to their own tenant session, with their account as it
/// is now, the session they came with and the tenant's timeouts it was
/// checked against.
///
/// A use case that works on the session itself, or checks it again for the
/// domain, takes it from here rather than loading it a second time.
pub struct SignedInAccount {
    /// The account, loaded fresh.
    pub account: User<ResolvedTenant>,
    /// The proof they signed in to it.
    pub signed_in: SignedIn<ResolvedTenant>,
    /// The session they came with, as stored.
    pub session: Session<ResolvedTenant>,
    /// The tenant's session timeouts the session was checked against.
    pub timeout: SessionTimeoutPolicy,
}

/// The holder of an account, as the credential they came with proves them
/// now.
pub enum AccountHolder {
    /// Signed in to their own session.
    Session(Box<SignedInAccount>),
    /// Bound to the directory over a certificate still in force for the
    /// account, loaded fresh. A bind opens no session.
    Directory(Box<User<ResolvedTenant>>),
}

impl AccountHolder {
    /// The account, loaded fresh.
    #[must_use]
    pub fn account(&self) -> &User<ResolvedTenant> {
        match self {
            Self::Session(person) => &person.account,
            Self::Directory(account) => account,
        }
    }

    /// The account, to record a change on.
    pub fn account_mut(&mut self) -> &mut User<ResolvedTenant> {
        match self {
            Self::Session(person) => &mut person.account,
            Self::Directory(account) => account,
        }
    }
}
