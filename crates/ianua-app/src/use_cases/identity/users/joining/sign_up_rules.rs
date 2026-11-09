//! Sign-up rules: whether a tenant takes sign-ups, and the password rules a
//! sign-up is held to.

use std::sync::Arc;

use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::PasswordPolicy;

use crate::error::AppError;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// The ports [`SignUpRulesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SignUpRulesPorts {
    /// Reads whether the tenant takes sign-ups, and its password rules.
    pub tenant_store: Arc<dyn TenantStore>,
}

/// Reports whether a tenant takes sign-ups, before anyone fills in the form.
pub struct SignUpRulesUseCase {
    ports: SignUpRulesPorts,
}

impl SignUpRulesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: SignUpRulesPorts) -> Self {
        Self { ports }
    }
}

impl Query for SignUpRulesUseCase {
    type Caller = ScopedTenant;
    type Input = ();
    type Output = Result<Option<PasswordPolicy>, AppError>;

    /// The password rules a sign-up to `tenant` is held to, or `None` when
    /// the tenant takes no sign-ups: it has not turned them on, is not open,
    /// or signs nobody in with a password. It answers as a sign-up would be
    /// answered, so the form never offers what the submit refuses.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant no longer exists.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        (): (),
    ) -> Result<Option<PasswordPolicy>, AppError> {
        let found = existing_tenant(self.ports.tenant_store.as_ref(), tenant).await?;
        let scope = ResolvedTenant::new(*found.id(), found.slug().clone());
        if found.admits_self_sign_up(&scope).is_err() {
            return Ok(None);
        }
        Ok(found.auth_config().new_password_policy().cloned())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::tenant::access::auth_config::{
        SelfRegistration, TenantAuthSettings,
    };

    use super::*;
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{block_on, test_ctx};

    fn rules_of(
        registration: SelfRegistration,
        methods: Vec<AuthMethod>,
    ) -> Option<PasswordPolicy> {
        let use_case = SignUpRulesUseCase::new(SignUpRulesPorts {
            tenant_store: tenant_store_signing_in_with(TenantAuthSettings {
                self_registration: registration,
                enabled_methods: methods,
                ..TenantAuthSettings::default()
            }),
        });

        block_on(use_case.execute(&test_ctx().tenant(), ())).unwrap()
    }

    /// A tenant that takes sign-ups with a password tells the form its
    /// password rules.
    #[test]
    fn an_open_tenant_answers_its_password_rules() {
        assert!(rules_of(SelfRegistration::Open, vec![AuthMethod::Password]).is_some());
    }

    /// A tenant that only invites says it takes no sign-ups.
    #[test]
    fn a_tenant_that_has_not_turned_sign_up_on_answers_none() {
        assert!(rules_of(SelfRegistration::Closed, vec![AuthMethod::Password]).is_none());
    }

    /// A tenant that signs people in only with passkeys takes no sign-up
    /// with a password.
    #[test]
    fn a_tenant_without_password_sign_in_answers_none() {
        assert!(rules_of(SelfRegistration::Open, vec![AuthMethod::Passkey]).is_none());
    }
}
