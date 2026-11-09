//! Signing in with a password, and what follows it.

pub(super) mod admission;
pub(crate) mod confirmation;
pub(crate) mod due;
pub(crate) mod due_change;
pub(crate) mod email_confirmation;
pub(super) mod flood;
mod kept;
pub(crate) mod login;
pub(crate) mod login_security;
mod owed_change;
pub(crate) mod puzzle;
pub(super) mod settlement;
pub(crate) mod tenant_change_due;
pub(crate) mod tenant_login;

pub use confirmation::{ConfirmationLinkPolicy, ConfirmationMailPorts};
pub use due::{ChangeToken, DuePorts, PasswordChangeOwed};
pub use due_change::{ChangeDuePorts, ChangeDueUseCase, DueChangeRequest};
pub use email_confirmation::{
    ConfirmSignInByEmailPorts, ConfirmSignInByEmailUseCase, ConfirmSignInRequest, ConfirmedSignIn,
};
pub use login::{
    LoginOutcome, LoginPorts, LoginRequest, LoginSettings, LoginSuccess, LoginUseCase,
};
pub use login_security::{LoginSecurityPorts, SecurityRules};
pub use puzzle::{IssueSignInPuzzlePorts, IssueSignInPuzzleUseCase};
pub use tenant_change_due::{TenantChangeDueRequest, TenantChangeDueUseCase};
pub use tenant_login::{
    LoginAttempt, LoginTenant, TenantLoginOutcome, TenantLoginPorts, TenantLoginRequest,
    TenantLoginSuccess, TenantLoginUseCase,
};
