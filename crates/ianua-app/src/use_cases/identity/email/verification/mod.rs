//! Proving an account's address.

pub(crate) mod links;
pub(crate) mod resend;
pub(crate) mod send;
pub(crate) mod status;
pub(crate) mod verify;

pub(crate) use links::LinkMailed;
pub use links::{VerificationLinkStores, VerificationLinks, VerificationPolicy};
pub use resend::{ResendVerificationPorts, ResendVerificationRequest, ResendVerificationUseCase};
pub use send::{SendVerificationPorts, SendVerificationRequest, SendVerificationUseCase};
pub use status::{VerificationStatusPorts, VerificationStatusUseCase};
pub use verify::{VerifyPorts, VerifyUseCase};
