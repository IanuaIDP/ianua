//! Signing in by a link sent to the member's mailbox.

pub(crate) mod confirm_by_email;
pub(crate) mod confirmation_mail;
pub(crate) mod magic_link;
pub(crate) mod magic_link_request;

pub use confirm_by_email::{OrgConfirmPorts, OrgConfirmRequest, OrgConfirmUseCase, OrgConfirmed};
pub use confirmation_mail::OrgConfirmationMailPorts;
pub use magic_link::{OrgMagicLinkPorts, OrgMagicLinkRequest, OrgMagicLinkUseCase};
pub use magic_link_request::{
    OrgMagicLinkPolicy, RequestOrgMagicLinkPorts, RequestOrgMagicLinkUseCase,
};
