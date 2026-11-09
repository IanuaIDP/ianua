//! Rows of the operator context.

use ianua_domain::domains::operator::api_key::OperatorApiKeyRow;
use ianua_domain::domains::operator::identity::{Operator, OperatorRow};
use ianua_domain::domains::operator::impersonation::ImpersonationGrantRow;
use ianua_domain::domains::operator::status::OperatorStatus;
use ianua_domain::shared::clock;
use ianua_domain::types::{
    Email, Expiry, ImpersonationGrantId, KeyPrefix, OperatorId, PasswordHash, Revocation, TenantId,
    Text, TokenHash, UserId,
};
use time::Duration;

use crate::test_support::rows::at;

/// An operator at `email` standing at `status`, made at the fixed moment.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn operator_row(email: &str, status: OperatorStatus) -> OperatorRow {
    OperatorRow {
        id: OperatorId::new(),
        email: Email::new(email).expect("a valid address"),
        password_hash: PasswordHash::from_stored(format!("hash of {email}")),
        status,
        created_at: at(0),
    }
}

/// An active operator at `email`.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn active_operator(email: &str) -> Operator {
    Operator::reconstitute(operator_row(email, OperatorStatus::Active))
        .expect("an operator row reads back")
}

/// A working key of `operator`'s shown as `prefix`, made at the fixed
/// moment, that never expires.
///
/// # Panics
///
/// When `prefix` is not a valid key prefix, which is a mistake in the test.
#[must_use]
pub fn operator_key_row(operator: OperatorId, prefix: &str) -> OperatorApiKeyRow {
    OperatorApiKeyRow {
        operator_id: operator,
        key_prefix: KeyPrefix::new(prefix).expect("a valid key prefix"),
        key_hash: TokenHash::from_stored(format!("hash of {prefix}")),
        expires_at: Expiry::Never,
        revocation: Revocation::InForce,
        created_at: at(0),
    }
}

/// A grant letting `operator` act as `user` of `tenant`, made this second
/// for an hour, and not revoked. A grant is judged against the clock, so it
/// is dated from now, in whole seconds as Postgres keeps them.
///
/// # Panics
///
/// Never: the reason is a valid text and a whole second is a real time.
#[must_use]
pub fn grant_row(operator: OperatorId, tenant: TenantId, user: UserId) -> ImpersonationGrantRow {
    let now = clock::now()
        .replace_nanosecond(0)
        .expect("a whole second is a real time");
    ImpersonationGrantRow {
        id: ImpersonationGrantId::new(),
        operator_id: operator,
        tenant_id: tenant,
        user_id: user,
        reason: Text::new("reason", "Support ticket 42").expect("a valid reason"),
        expires_at: now.saturating_add(Duration::hours(1)),
        revocation: Revocation::InForce,
        created_at: now,
    }
}
