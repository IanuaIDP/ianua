//! Fake for the one-time codes a federated sign-in hands back to the browser
//! that started it.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::sessions::sign_in_code::{SignInCode, SignInCodeRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TenantId, TokenHash, Usage};

use crate::ports::TenantScoped;
use crate::ports::authentication::SignInCodeStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// In-memory sign-in code store: a code is taken once, and only in its own
/// tenant.
#[derive(Default)]
pub struct FakeSignInCodes {
    codes: Mutex<Vec<(TenantId, SignInCode<ResolvedTenant>)>>,
}

impl TenantScoped for FakeSignInCodes {}

impl FakeSignInCodes {
    /// A store holding no code.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many codes wait to be taken, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.codes.lock().unwrap().len()
    }
}

#[async_trait]
impl SignInCodeStore for FakeSignInCodes {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        code: &SignInCode<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_code(code)?;
        self.codes.lock().unwrap().push((**tenant_id, copy));
        Ok(())
    }

    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<SignInCode<ResolvedTenant>>, DomainError> {
        let mut codes = self.codes.lock().unwrap();
        let found = codes
            .iter()
            .position(|(tenant, code)| tenant == &**tenant_id && code.token_hash() == token_hash);
        Ok(found.map(|index| codes.remove(index).1))
    }
}

impl Fake for Arc<dyn SignInCodeStore> {
    fn fake() -> Self {
        Arc::new(FakeSignInCodes::empty())
    }
}

/// `code` written out and read back, as storage would return it.
fn copy_code(code: &SignInCode<ResolvedTenant>) -> Result<SignInCode<ResolvedTenant>, DomainError> {
    SignInCode::reconstitute(SignInCodeRow {
        token_hash: code.token_hash().clone(),
        dashboard_hash: code.dashboard_hash().clone(),
        session_id: *code.session_id(),
        expires_at: code.expires_at(),
        usage: Usage::from_stored(code.consumed_at()),
    })
}
