//! The session and fresh proof a test caller changes protected tenant
//! settings with.

use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::risk_engine::rate_limit::LoginAttemptTracker;
use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::{
    FreshSignIn, PasswordCheck, WithFactor,
};
use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
use ianua_domain::domains::authentication::sessions::session::{
    Session, SessionOrigin, SessionRow,
};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::test_support::fakes::FakeHasher;
use ianua_domain::types::{CredentialChange, Fact, PrincipalId, TokenHash, UserId};

use crate::context::CallerIdentity;
use crate::test_support::{test_ctx, test_session_id};

/// The password every test caller proves themselves with.
const CALLER_PASSWORD: &str = "correct horse battery staple";

/// The session [`test_ctx`] signed in with by password, as the session
/// store keeps it.
///
/// # Panics
///
/// Never: the test caller is a tenant user and the row is consistent.
#[must_use]
pub fn caller_session() -> Session<ResolvedTenant> {
    let now = clock::now();
    Session::reconstitute(SessionRow {
        id: test_session_id(),
        user_id: caller_user(),
        refresh_token_hash: TokenHash::from_stored("refresh".to_owned()),
        parent_id: SessionOrigin::SignIn,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        signed_in_from: Fact::Unknown,
        progress: SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::NotOwed,
        },
        status: SessionStatus::Active,
        channel: SessionChannel::Dashboard,
        signed_in_at: now,
        created_at: now,
        last_active_at: now,
        expires_at: now + time::Duration::hours(8),
        kept_through: CredentialChange::Never,
        last_use: Fact::Unknown,
    })
    .expect("a fresh, finished session is a consistent row")
}

/// A proof that [`test_ctx`]'s caller typed their password again just now.
#[must_use]
pub fn caller_fresh_proof() -> FreshSignIn {
    fresh_proof_of(caller_user().into())
}

/// A proof that the holder of `account` typed their password again just
/// now.
///
/// # Panics
///
/// Never: the password checked is the one hashed here.
#[must_use]
pub fn fresh_proof_of(account: PrincipalId) -> FreshSignIn {
    let stored = FakeHasher
        .hash(CALLER_PASSWORD)
        .expect("the fake hasher always hashes");
    let mut tracker = LoginAttemptTracker::new();
    let check = PasswordCheck {
        raw: CALLER_PASSWORD,
        stored: &stored,
        hasher: &FakeHasher,
        tracker: &mut tracker,
    };
    FreshSignIn::by_password(account, check, WithFactor::NoneOnFile)
        .expect("the right password proves the account")
}

fn caller_user() -> UserId {
    match test_ctx().identity() {
        CallerIdentity::TenantUser(user) => *user,
        CallerIdentity::OrgUser(_) | CallerIdentity::Operator(_) => {
            unreachable!("the test caller is a tenant user")
        }
    }
}
