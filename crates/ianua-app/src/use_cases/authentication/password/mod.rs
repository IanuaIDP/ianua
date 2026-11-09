//! Signing in with a password or an emailed link, confirming a sign-in by
//! email, and changing or resetting a password.

pub(crate) mod change;
/// Signing in by a link instead of a password.
pub(crate) mod magic_link;
mod new;
/// Resetting a forgotten password by a mailed link.
pub(crate) mod reset;
/// Signing in with a password, and what follows it.
pub(crate) mod sign_in;

pub use change::{ChangePolicy, ChangePorts, ChangeRequest, ChangeUseCase};
pub use magic_link::{
    ConsumeMagicLinkPorts, ConsumeMagicLinkRequest, ConsumeMagicLinkUseCase, MagicLinkLoginSuccess,
    MagicLinkPolicy, RequestMagicLinkPorts, RequestMagicLinkRequest, RequestMagicLinkUseCase,
};
pub use new::ReplacementPorts;
pub use reset::{
    ResendResetPorts, ResendResetRequest, ResendResetUseCase, ResetCodePorts, ResetCodeUseCase,
    ResetConfirmPorts, ResetConfirmRequest, ResetConfirmUseCase, ResetMailRequest,
    ResetRequestPorts, ResetRequestUseCase, ResetStatusPorts, ResetStatusUseCase,
};
pub use sign_in::{
    ChangeDuePorts, ChangeDueUseCase, ChangeToken, ConfirmSignInByEmailPorts,
    ConfirmSignInByEmailUseCase, ConfirmSignInRequest, ConfirmationLinkPolicy,
    ConfirmationMailPorts, ConfirmedSignIn, DueChangeRequest, DuePorts, IssueSignInPuzzlePorts,
    IssueSignInPuzzleUseCase, LoginAttempt, LoginOutcome, LoginPorts, LoginRequest,
    LoginSecurityPorts, LoginSettings, LoginSuccess, LoginTenant, LoginUseCase, PasswordChangeOwed,
    SecurityRules, TenantChangeDueRequest, TenantChangeDueUseCase, TenantLoginOutcome,
    TenantLoginPorts, TenantLoginRequest, TenantLoginSuccess, TenantLoginUseCase,
};
