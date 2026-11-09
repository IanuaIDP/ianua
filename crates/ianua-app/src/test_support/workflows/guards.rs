//! Change guards that decide every change one way, for the use cases that
//! ask one before they save.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::triggers::before::{GuardedChange, Verdict};
use ianua_domain::shared::errors::DomainError;

use crate::auditor::RequestAuditor;
use crate::ports::workflows::ChangeGuard;
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// A guard that lets every change happen, and notes each one it was asked.
#[derive(Default)]
pub struct AllowingGuard {
    /// The changes it was asked about, in order.
    pub asked: Mutex<Vec<GuardedChange>>,
}

#[async_trait]
impl ChangeGuard for AllowingGuard {
    async fn decide(
        &self,
        _: &ScopedTenant,
        _: &RequestAuditor,
        change: GuardedChange,
        _: FlowData,
    ) -> Result<Verdict, DomainError> {
        self.asked.lock().unwrap().push(change);
        Ok(Verdict::Allow)
    }
}

/// A guard whose company rule refuses every change.
pub struct RefusingGuard;

#[async_trait]
impl ChangeGuard for RefusingGuard {
    async fn decide(
        &self,
        _: &ScopedTenant,
        _: &RequestAuditor,
        _: GuardedChange,
        _: FlowData,
    ) -> Result<Verdict, DomainError> {
        Ok(Verdict::Refuse)
    }
}

impl Fake for Arc<dyn ChangeGuard> {
    fn fake() -> Self {
        Arc::new(AllowingGuard::default())
    }
}
