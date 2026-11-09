//! The pages of a loop's items each person opened, kept in memory.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::execution::{ItemsSeen, SeenPage};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::ports::TenantScoped;
use crate::ports::workflows::{ApprovalPages, ItemsViewer};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// Opened pages, per tenant and viewer, the first opening of each kept.
#[derive(Default)]
pub struct FakeApprovalPages {
    pages: Mutex<Vec<(TenantId, ItemsViewer, SeenPage)>>,
}

impl FakeApprovalPages {
    /// No page opened yet.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Every page kept, in the order they were first opened.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned.
    #[must_use]
    pub fn all(&self) -> Vec<SeenPage> {
        self.pages
            .lock()
            .expect("pages lock")
            .iter()
            .map(|(_, _, page)| *page)
            .collect()
    }
}

impl TenantScoped for FakeApprovalPages {}

#[async_trait]
impl ApprovalPages for FakeApprovalPages {
    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        viewer: &ItemsViewer,
        page: &SeenPage,
    ) -> Result<(), DomainError> {
        let mut pages = self.pages.lock().expect("pages lock");
        let kept = pages.iter().any(|(tenant, seen_by, seen)| {
            *tenant == **tenant_id
                && seen_by == viewer
                && seen.opening == page.opening
                && seen.first == page.first
                && seen.count == page.count
        });
        if !kept {
            pages.push((**tenant_id, viewer.clone(), *page));
        }
        Ok(())
    }

    async fn seen_by(
        &self,
        tenant_id: &ScopedTenant,
        viewer: &ItemsViewer,
    ) -> Result<ItemsSeen, DomainError> {
        let pages = self.pages.lock().expect("pages lock");
        let seen = pages
            .iter()
            .filter(|(tenant, seen_by, _)| *tenant == **tenant_id && seen_by == viewer)
            .map(|(_, _, page)| *page)
            .collect();
        Ok(ItemsSeen::new(seen))
    }
}

impl Fake for Arc<dyn ApprovalPages> {
    fn fake() -> Self {
        Arc::new(FakeApprovalPages::none())
    }
}
