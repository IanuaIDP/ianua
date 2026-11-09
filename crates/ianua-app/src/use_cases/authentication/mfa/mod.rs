//! Second factors: setting up an authenticator app or codes mailed or
//! texted, sending those codes, answering a session's second factor,
//! resuming a suspended session, recovery codes in its place and their
//! regeneration, and what a person may set up.

/// Codes sent and checked for a second factor.
pub(crate) mod codes;
/// Setting up a second factor, and taking it away.
pub(crate) mod enrollment;
mod lookup;
/// Recovery codes: signing in with one, making new ones.
pub(crate) mod recovery;
/// A session held until its second factor is answered.
pub(crate) mod sessions;
pub(crate) mod status;

pub use codes::{
    CodeSent, FactorCodePorts, FactorOptions, FactorOptionsPorts, FactorOptionsUseCase, HeldFactor,
    SendFactorCodePorts, SendFactorCodeUseCase, SentCodePolicy, SentCodePorts, VerificationPorts,
    VerificationRequest, VerificationUseCase,
};
pub use enrollment::{
    AbandonPorts, AbandonUseCase, BeginPorts, BeginUseCase, CodeFactorBeginPorts,
    CodeFactorBeginUseCase, CodeFactorRequest, ConfirmPorts, ConfirmRequest, ConfirmUseCase,
    DisablePorts, DisableRequest, DisableUseCase, EnrollmentConfirmed, EnrollmentQr, FactorSetter,
    SentFactorChoice, SetterPorts, SetupProof,
};
pub use recovery::{
    RecoveryCodeLoginPorts, RecoveryCodeLoginRequest, RecoveryCodeLoginUseCase,
    RegenerateRecoveryCodesPorts, RegenerateRecoveryCodesUseCase, RegeneratedRecoveryCodes,
};
pub use sessions::{PendingSignIn, ResumeSessionPorts, ResumeSessionRequest, ResumeSessionUseCase};
pub use status::{GetStatusPorts, GetStatusUseCase, Status};
