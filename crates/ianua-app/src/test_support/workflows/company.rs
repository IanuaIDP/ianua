//! A stand-in for the company's own steps, keeping who each was made as.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::types::UntrustedText;

use crate::context::CallerContext;
use crate::ports::workflows::{CompanyCall, CompanySteps};
use crate::test_support::Fake;

/// One company step as the stand-in was handed it.
#[derive(Clone)]
pub struct MadeCompanyStep {
    /// Who it was made as.
    pub caller: CallerContext,
    /// What its records would say.
    pub audit: AuditContext,
    /// The requested operation and its supplied arguments.
    pub call: ActionCall,
}

/// Company steps answering every call with one outcome, keeping each.
pub struct FakeCompanySteps {
    outcome: ActionOutcome,
    made: Mutex<Vec<MadeCompanyStep>>,
}

impl FakeCompanySteps {
    /// Steps whose every call comes to `outcome`.
    #[must_use]
    pub fn answering(outcome: ActionOutcome) -> Self {
        Self {
            outcome,
            made: Mutex::new(Vec::new()),
        }
    }

    /// Every step made, in order.
    ///
    /// # Panics
    ///
    /// Panics if a previous call panicked holding the lock.
    #[must_use]
    pub fn made(&self) -> Vec<MadeCompanyStep> {
        self.made.lock().unwrap().clone()
    }
}

#[async_trait]
impl CompanySteps for FakeCompanySteps {
    async fn run(&self, call: CompanyCall<'_>) -> ActionOutcome {
        self.made.lock().unwrap().push(MadeCompanyStep {
            caller: call.caller.clone(),
            audit: call.auditor.context().clone(),
            call: call.call.clone(),
        });
        self.outcome.clone()
    }
}

impl Fake for Arc<dyn CompanySteps> {
    fn fake() -> Self {
        Arc::new(FakeCompanySteps::answering(ActionOutcome::Failed(
            UntrustedText::record("no company steps are set up"),
        )))
    }
}
