//! Onboarding: how an organization, its first tenant and its owner come to
//! exist: by public signup on the hosted service, by a signed-in member
//! founding another, or by an installation creating its own on first start.

pub(crate) mod another_organization;
pub(crate) mod confirm_signup;
pub mod founding;
pub(crate) mod install;
pub(crate) mod signup;
pub(crate) mod signup_open;

pub use another_organization::{
    AnotherOrganizationPorts, AnotherOrganizationRequest, FoundAnotherOrganizationUseCase,
};
pub use confirm_signup::{ConfirmSignupPorts, ConfirmSignupUseCase};
pub use install::{InstallRequest, InstallUseCase, Installation};
pub use signup::{
    Enrollment, SelfServiceFounding, SignupLinks, SignupPorts, SignupRequest, SignupUseCase,
};
pub use signup_open::SignupOpenUseCase;
