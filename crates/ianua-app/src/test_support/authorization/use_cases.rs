//! The group use cases other use cases are composed from, each built over
//! its neutral ports, so a ports struct holding one fills in through
//! `fakes()` like any other port.

use std::sync::Arc;

use crate::test_support::Fake;
use crate::use_cases::authorization::groups::{
    AddMemberUseCase, CreateUseCase, DeleteUseCase, RemoveMemberUseCase, RenameUseCase,
};

impl Fake for Arc<AddMemberUseCase> {
    fn fake() -> Self {
        Arc::new(AddMemberUseCase::new(Fake::fake()))
    }
}

impl Fake for Arc<CreateUseCase> {
    fn fake() -> Self {
        Arc::new(CreateUseCase::new(Fake::fake()))
    }
}

impl Fake for Arc<DeleteUseCase> {
    fn fake() -> Self {
        Arc::new(DeleteUseCase::new(Fake::fake()))
    }
}

impl Fake for Arc<RemoveMemberUseCase> {
    fn fake() -> Self {
        Arc::new(RemoveMemberUseCase::new(Fake::fake()))
    }
}

impl Fake for Arc<RenameUseCase> {
    fn fake() -> Self {
        Arc::new(RenameUseCase::new(Fake::fake()))
    }
}
