//! A fake for drawing pages.

use std::sync::Arc;

use ianua_domain::shared::errors::DomainError;

use crate::ports::pages::{DrawnPage, ErrorPage, PageRenderer, SignInPage};
use crate::test_support::Fake;

/// Draws a page as a line naming what it is: the sign-in step and the
/// workspace, or the error's code and reference.
pub struct FakePageRenderer;

impl PageRenderer for FakePageRenderer {
    fn sign_in_page(&self, page: &SignInPage) -> Result<DrawnPage, DomainError> {
        Ok(DrawnPage::new(format!(
            "<p>{:?} on {}</p>",
            page.action, page.workspace
        )))
    }

    fn error_page(&self, page: &ErrorPage) -> Result<DrawnPage, DomainError> {
        Ok(DrawnPage::new(format!(
            "<p>{} ({})</p>",
            page.kind.code(),
            page.reference
        )))
    }
}

impl Fake for Arc<dyn PageRenderer> {
    fn fake() -> Self {
        Arc::new(FakePageRenderer)
    }
}
