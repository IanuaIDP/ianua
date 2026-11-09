//! An in-memory store for sign-ups waiting for their link.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::organization::signup::PendingSignup;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HttpsUrl, Lifetime, TokenHash};

use crate::ports::organization::PendingSignupStore;
use crate::test_support::Fake;
use crate::use_cases::onboarding::SignupLinks;

/// In-memory store for pending sign-ups, handing each out once.
#[derive(Default)]
pub struct FakePendingSignupStore {
    signups: Mutex<Vec<PendingSignup>>,
}

impl FakePendingSignupStore {
    /// A store holding no sign-up.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `signup`.
    #[must_use]
    pub fn holding(signup: PendingSignup) -> Self {
        Self {
            signups: Mutex::new(vec![signup]),
        }
    }

    /// How many sign-ups are waiting.
    #[must_use]
    pub fn count(&self) -> usize {
        self.signups.lock().unwrap().len()
    }
}

#[async_trait]
impl PendingSignupStore for FakePendingSignupStore {
    async fn save(&self, signup: &PendingSignup) -> Result<(), DomainError> {
        let copy = PendingSignup::reconstitute(signup.to_row())?;
        self.signups.lock().unwrap().push(copy);
        Ok(())
    }

    async fn take(&self, hash: &TokenHash) -> Result<Option<PendingSignup>, DomainError> {
        let mut signups = self.signups.lock().unwrap();
        let Some(position) = signups.iter().position(|held| held.token_hash() == hash) else {
            return Ok(None);
        };
        Ok(Some(signups.remove(position)))
    }
}

impl Fake for Arc<dyn PendingSignupStore> {
    fn fake() -> Self {
        Arc::new(FakePendingSignupStore::empty())
    }
}

impl Fake for SignupLinks {
    fn fake() -> Self {
        SignupLinks {
            lifetime: Lifetime::seconds(86_400).expect("a day is a valid lifetime"),
            base_url: HttpsUrl::new("https://app.ianua.test").expect("a valid address"),
        }
    }
}
