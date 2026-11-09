//! A refusal wording that words nothing, so every refusal reads in English.

use std::sync::Arc;

use ianua_domain::shared::errors::Refusal;

use crate::ports::shared::{PreferredLanguages, RefusalWording};
use crate::test_support::Fake;

/// Words no refusal: callers read each refusal's own English text.
#[derive(Debug, Default)]
pub struct EnglishOnlyWording;

impl RefusalWording for EnglishOnlyWording {
    fn worded(&self, _refusal: &Refusal, _languages: &PreferredLanguages) -> Option<String> {
        None
    }
}

impl Fake for Arc<dyn RefusalWording> {
    fn fake() -> Self {
        Arc::new(EnglishOnlyWording)
    }
}
