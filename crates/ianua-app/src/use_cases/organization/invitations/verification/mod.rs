//! Proving a new owner's address before the organization opens.

pub(crate) mod confirm_installer;
pub(crate) mod confirm_org;
pub(crate) mod mail;
pub(crate) mod org_status;
pub(crate) mod resend_org;
pub(crate) mod resend_org_by_email;
pub(crate) mod resend_org_from_link;

pub use confirm_installer::{ConfirmInstallerPorts, ConfirmInstallerUseCase};
pub use confirm_org::{ConfirmOrgVerificationPorts, ConfirmOrgVerificationUseCase};
pub use mail::OrgVerificationMail;
pub use org_status::{OrgVerificationStatusPorts, OrgVerificationStatusUseCase};
pub use resend_org::{ResendOrgVerificationRequest, ResendOrgVerificationUseCase};
pub use resend_org_by_email::ResendOrgVerificationByEmailUseCase;
pub use resend_org_from_link::ResendOrgVerificationFromLinkUseCase;
