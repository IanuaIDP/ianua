//! The platform's operators, as they act on the operator plane: signing
//! in with a password for a short-lived key, other operators' accounts,
//! the grants that let an operator act as a tenant user, and the jobs the
//! platform gave up on.

use serde::{Deserialize, Serialize};

/// `POST /api/v1/operators/sign-in`. Holds the password, so it has no
/// `Debug`.
#[derive(Clone, Serialize)]
pub struct OperatorSignIn {
    /// The address the operator signs in with.
    pub email: String,
    /// Account secret exchanged for a short-lived operator key.
    pub password: String,
}

/// `POST /api/v1/operators`: another operator's account, made by an
/// operator. Holds the first password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct NewOperator {
    /// The address the new operator signs in with.
    pub email: String,
    /// The password they sign in with until they change it.
    pub password: String,
}

/// The operator just made.
#[derive(Debug, Clone, Deserialize)]
pub struct OperatorMade {
    /// The id the new operator is disabled and looked up by.
    pub id: String,
}

/// A key just made, shown once. Holds it, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct OperatorKeyMade {
    /// The whole key, sent as `Authorization: Bearer`.
    pub raw_key: String,
    /// The visible start the key is found and revoked by.
    pub key_prefix: String,
}

/// An operator's account, from `GET /api/v1/operators/{id}`.
#[derive(Debug, Clone, Deserialize)]
pub struct OperatorAccount {
    /// Handle used to inspect or disable this platform account.
    pub id: String,
    /// The address they sign in with.
    pub email: String,
    /// `Active` or `Disabled`.
    pub status: String,
}

/// `POST /api/v1/operators/{id}/grants`: the user an operator asks to act
/// as, and why.
#[derive(Debug, Clone, Serialize)]
pub struct GrantImpersonation {
    /// The tenant the user belongs to.
    pub tenant_id: String,
    /// The user to act as.
    pub user_id: String,
    /// Why, kept in the audit trail.
    pub reason: String,
    /// When the grant ends, RFC 3339, at most a day ahead.
    pub expires_at: String,
}

/// The grant just made.
#[derive(Debug, Clone, Deserialize)]
pub struct GrantMade {
    /// Its id, named in the operator-impersonation header of every
    /// request made as the user.
    pub id: String,
}

/// A job that used up its tries, from `GET /api/v1/operators/dead-jobs`.
#[derive(Debug, Clone, Deserialize)]
pub struct DeadJob {
    /// Handle used to retry work after its attempts were exhausted.
    pub id: String,
    /// What kind of work it was, such as `mail.deliver`.
    pub job_type: String,
    /// The tenant it worked for, or none for the platform's own work.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// How many times it ran.
    pub attempts: u32,
    /// Why its last run failed.
    pub reason: String,
}
