//! The identity use cases other use cases are composed from, each built over
//! its neutral ports, so a ports struct holding one fills in through
//! `fakes()` like any other port.

use std::sync::Arc;

use crate::test_support::Fake;
use crate::use_cases::identity::email::ChangeUseCase;
use crate::use_cases::identity::users::credentials::new_password::PasswordMaker;
use crate::use_cases::identity::users::{
    DeleteUseCase, RegisterUseCase, RenameUseCase, ResetPasswordUseCase,
};

/// Passwords hashed by the fake hasher and drawn from a fixed sequence.
impl Fake for Arc<PasswordMaker> {
    fn fake() -> Self {
        Arc::new(PasswordMaker::new(Fake::fake(), Fake::fake()))
    }
}

impl Fake for Arc<ChangeUseCase> {
    fn fake() -> Self {
        Arc::new(ChangeUseCase::new(Fake::fake()))
    }
}

impl Fake for Arc<DeleteUseCase> {
    fn fake() -> Self {
        Arc::new(DeleteUseCase::new(Fake::fake()))
    }
}

impl Fake for Arc<RenameUseCase> {
    fn fake() -> Self {
        Arc::new(RenameUseCase::new(Fake::fake()))
    }
}

impl Fake for Arc<RegisterUseCase> {
    fn fake() -> Self {
        Arc::new(RegisterUseCase::new(Fake::fake()))
    }
}

impl Fake for Arc<ResetPasswordUseCase> {
    fn fake() -> Self {
        Arc::new(ResetPasswordUseCase::new(Fake::fake()))
    }
}
