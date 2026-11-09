//! Signing up for an organization: whether the deployment takes sign-ups,
//! asking for one, founding it from the mailed link, and the first owner
//! of a self-hosted installation confirmed from the installer's proof.

use super::Request;
use crate::net::Call;
use crate::wire::onboarding::{
    ConfirmInstaller, ConfirmSignup, Founded, InstallerConfirmed, Signup, SignupAccepted,
    SignupAvailability,
};

/// `POST /api/v1/signup`: asks for an organization; the link is mailed.
#[must_use]
pub fn sign_up(signup: &Signup) -> Request<SignupAccepted> {
    Request::of(Call::post("/api/v1/signup").json(signup))
}

/// `POST /api/v1/signup/confirm`: founds the organization from the link.
#[must_use]
pub fn confirm(confirm: &ConfirmSignup) -> Request<Founded> {
    Request::of(Call::post("/api/v1/signup/confirm").json(confirm))
}

/// `GET /api/v1/signup`: whether this deployment takes sign-ups.
#[must_use]
pub fn availability() -> Request<SignupAvailability> {
    Request::of(Call::get("/api/v1/signup"))
}

/// `POST /api/v1/users/confirm-installer`: confirms the first owner of a
/// self-hosted installation from the proof the installer printed.
#[must_use]
pub fn confirm_installer(confirm: &ConfirmInstaller) -> Request<InstallerConfirmed> {
    Request::of(Call::post("/api/v1/users/confirm-installer").json(confirm))
}
