//! Signing up for an organization: whether the deployment takes sign-ups,
//! asking for one, founding it from the mailed link, and the first owner
//! of a self-hosted installation confirmed from the installer's proof.

use serde::{Deserialize, Serialize};

/// `POST /api/v1/signup`: asking for an organization. Holds a password,
/// so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct Signup {
    /// The company's name, which the organization's slug is made from.
    pub company_name: String,
    /// The first tenant's name.
    pub tenant_name: String,
    /// The owner's address, where the link goes.
    pub admin_email: String,
    /// The owner's name.
    pub admin_display_name: String,
    /// The owner's password.
    pub admin_password: String,
}

/// The answer to a sign-up, the same whether or not the address has an
/// account.
#[derive(Debug, Clone, Deserialize)]
pub struct SignupAccepted {
    /// Always `check_inbox`.
    pub status: String,
}

/// `POST /api/v1/signup/confirm`: the token from the mailed link. Holds
/// the token, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ConfirmSignup {
    /// The token from the link.
    pub token: String,
}

/// The organization a confirmed sign-up founded.
#[derive(Debug, Clone, Deserialize)]
pub struct Founded {
    /// The organization's id.
    pub organization_id: String,
    /// The organization's slug.
    pub org_slug: String,
    /// The first tenant's id.
    pub tenant_id: String,
    /// The first tenant's slug.
    pub tenant_slug: String,
    /// The owner's id.
    pub admin_user_id: String,
    /// Always `provisioning`: the tenant's setup runs on.
    pub status: String,
}

/// Whether the deployment takes sign-ups, from `GET /api/v1/signup`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignupAvailability {
    /// `false` on a self-hosted installation, which has only the
    /// organization it made for itself.
    pub open: bool,
}

/// `POST /api/v1/users/confirm-installer`: the one-time proof the
/// installer printed for the first owner. Holds the token, so it has no
/// `Debug`.
#[derive(Clone, Serialize)]
pub struct ConfirmInstaller {
    /// The token the installer printed.
    pub token: String,
}

/// The first owner an installer's proof confirmed.
#[derive(Debug, Clone, Deserialize)]
pub struct InstallerConfirmed {
    /// The owner's id.
    pub id: String,
}
