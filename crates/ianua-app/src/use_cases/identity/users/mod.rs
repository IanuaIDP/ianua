//! Creating, reading, changing and removing a tenant's users.

/// Passwords and second factors, set and reset.
pub(crate) mod credentials;
/// How accounts come to be: registered by an admin or signed up.
pub(crate) mod joining;
/// What an account holds and how it is read and edited.
pub(crate) mod records;
/// A person's sessions and the sign-ins that opened them.
pub(crate) mod sessions;
/// Whether an account may sign in: its status, deactivation and deletion.
pub(crate) mod standing;

pub use credentials::{
    FactorsCleared, PasswordMaker, ResetFactorsPorts, ResetFactorsUseCase, ResetPasswordPorts,
    ResetPasswordRequest, ResetPasswordResult, ResetPasswordUseCase, SendResetLinkPorts,
    SendResetLinkRequest, SendResetLinkUseCase,
};
pub use joining::{
    New, RegisterPorts, RegisterResult, RegisterUseCase, SignUp, SignUpOutcome, SignUpPorts,
    SignUpRequest, SignUpRulesPorts, SignUpRulesUseCase, SignUpUseCase,
};
pub use records::{
    AttributeCondition, GetMePorts, GetMeUseCase, GetPorts, GetUseCase, ListOrder, ListPorts,
    ListRequest, ListUseCase, ListedUser, OpenInvitation, Preferences, RenamePorts, RenameRequest,
    RenameUseCase, UpdateDetailsPorts, UpdateDetailsRequest, UpdateDetailsUseCase,
    UpdatePreferencesPorts, UpdatePreferencesUseCase, UpdateRecordsPorts, UpdateRecordsRequest,
    UpdateRecordsUseCase, UserCriteria,
};
pub use sessions::{
    ListSessionsPorts, ListSessionsUseCase, ListSignInsPorts, ListSignInsRequest,
    ListSignInsUseCase, RevokeSessionPorts, RevokeSessionRequest, RevokeSessionUseCase,
    SignOutOtherSessionsPorts, SignOutOtherSessionsUseCase, StandingRemoval,
};
pub use standing::{
    DeactivatePorts, DeactivateUseCase, DeletePorts, DeleteUseCase, UpdateStatusPorts,
    UpdateStatusRequest, UpdateStatusUseCase,
};
