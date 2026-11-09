//! Joining what exists: a tenant's public form and what it advertises,
//! and a verified member founding another company.

use serde::{Deserialize, Serialize};

/// `POST …/auth/sign-up`: a tenant's public form. Holds a password, so it
/// has no `Debug`.
#[derive(Clone, Serialize)]
pub struct TenantSignup {
    /// The address the mailbox proof goes to.
    pub email: String,
    /// The name the person chose.
    pub display_name: String,
    /// The password, held to the tenant's policy.
    pub password: String,
}

/// What the tenant's public form advertises, from `GET …/auth/sign-up`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignupRules {
    /// Whether the tenant takes password registrations.
    pub open: bool,
    /// The password rules, only when the form is open.
    pub password_policy: Option<serde_json::Value>,
}

/// `POST /api/v1/organizations`: a signed-in member's new company, with a
/// password of its own. Holds the password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct AnotherCompany {
    /// The company's name, which its slug is made from.
    pub company_name: String,
    /// The first tenant's name.
    pub tenant_name: String,
    /// The new account's password, apart from the existing one.
    pub password: String,
}
