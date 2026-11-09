//! What a person agreed to, and withdrawing it.

pub(crate) mod grant;
pub(crate) mod history;
pub(crate) mod revoke;

pub use grant::{GrantConsentPorts, GrantConsentUseCase};
pub use history::{ConsentHistoryPorts, ConsentHistoryUseCase};
pub use revoke::{RevokeConsentPorts, RevokeConsentRequest, RevokeConsentUseCase};
