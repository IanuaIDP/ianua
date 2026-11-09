//! What a password reset link is worth, told without spending it.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::shared::clock;
use ianua_domain::types::{PasswordLinkStatus, TokenStatus};

use crate::error::AppError;
use crate::ports::authentication::ResetRequestStore;
use crate::ports::identity::UserStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::password_rules;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::authentication::password::reset::lookup::ResetLinks;

/// The ports [`ResetStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetStatusPorts {
    /// Finds reset requests.
    pub reset_store: Arc<dyn ResetRequestStore>,
    /// Loads the account a reset was mailed for.
    pub user_store: Arc<dyn UserStore>,
    /// Hashes the link's token the way it was stored.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// The tenant, for its password rules.
    pub tenant_store: Arc<dyn TenantStore>,
}

/// Reports what a password reset link is worth without spending it.
pub struct ResetStatusUseCase {
    ports: ResetStatusPorts,
}

impl ResetStatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ResetStatusPorts) -> Self {
        Self { ports }
    }

    /// What the link `raw_token` would do for the account it was mailed
    /// for. A link nobody issued, or whose account is gone, is invalid.
    async fn token_status(
        &self,
        tenant: &ScopedTenant,
        raw_token: &str,
    ) -> Result<TokenStatus, AppError> {
        let links = ResetLinks {
            resets: self.ports.reset_store.as_ref(),
            users: self.ports.user_store.as_ref(),
            hasher: self.ports.token_generator.as_ref(),
        };
        let now = clock::now();
        Ok(links
            .followed(tenant, raw_token)
            .await?
            .map_or(TokenStatus::Invalid, |followed| {
                followed.reset.state_for(&followed.holder, now).into()
            }))
    }
}

impl Query for ResetStatusUseCase {
    type Caller = ScopedTenant;
    type Input = String;
    type Output = Result<PasswordLinkStatus, AppError>;

    /// What the reset link `raw_token` is worth, without spending it.
    ///
    /// The page a link lands on chooses between a password form, "this link
    /// has expired" and "your password was already changed" before the
    /// reader types anything. An unknown link answers invalid rather than
    /// failing. A usable link carries the tenant's rules for new passwords,
    /// the ones the reset enforces, since the reader is signed out and has
    /// no other way to learn them; in a tenant that takes no passwords it
    /// says there is none to choose.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the token is malformed.
    /// - `AppError::NotFound` when the link is usable but its tenant is gone.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        raw_token: String,
    ) -> Result<PasswordLinkStatus, AppError> {
        let status = self.token_status(tenant, &raw_token).await?;
        if let Some(answer) = PasswordLinkStatus::without_form(status) {
            return Ok(answer);
        }
        let tenants = self.ports.tenant_store.as_ref();
        let policy = password_rules::for_new_tenant_password(tenants, tenant).await?;
        Ok(policy.map_or(
            PasswordLinkStatus::ValidWithoutPassword,
            PasswordLinkStatus::Valid,
        ))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::recovery::reset::{
        CreateResetParams, PasswordResetRequest, ResetInitiator, ResetStatus,
    };
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{Lifetime, PasswordPolicy, UserId};

    use super::*;
    use crate::test_support::authentication::FakeResetRequestStore;
    use crate::test_support::identity::{FakeUserStore, hash_of_link, stored_user};
    use crate::test_support::tenant::{
        tenant_store_with_password_policy, tenant_store_without_password_login,
    };
    use crate::test_support::{block_on, test_ctx};

    const ADDRESS: &str = "alice@acme.com";
    const LINK: &str = "fake_refresh_0";

    fn pending(ann: UserId) -> PasswordResetRequest {
        PasswordResetRequest::create(
            &stored_user(ann, ADDRESS, UserStatus::Active),
            CreateResetParams {
                initiator: ResetInitiator::User,
                token_hash: hash_of_link(LINK),
                lifetime: Lifetime::seconds(3600).unwrap(),
            },
        )
        .unwrap()
    }

    fn status_of(resets: Arc<FakeResetRequestStore>, users: FakeUserStore) -> PasswordLinkStatus {
        let use_case = ResetStatusUseCase::new(ResetStatusPorts {
            reset_store: resets,
            user_store: Arc::new(users),
            tenant_store: tenant_store_with_password_policy(PasswordPolicy::relaxed()),
            ..ResetStatusPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx().tenant(), LINK.to_owned())).unwrap()
    }

    /// Ann's link lands on the reset page. It reads as valid, and asking
    /// does not spend it.
    #[test]
    fn a_usable_link_reads_as_valid_without_being_spent() {
        let ann = UserId::new();
        let resets = Arc::new(FakeResetRequestStore::with_request(&pending(ann)));

        let status = status_of(resets.clone(), FakeUserStore::with_user(ann, ADDRESS));

        assert_eq!(status.token_status(), TokenStatus::Valid);
        assert_eq!(resets.status(), Some(ResetStatus::Pending));
    }

    /// Ann is signed out, so her link is the only place the form learns the
    /// workspace's rules. They are the rules the reset enforces.
    #[test]
    fn a_usable_link_carries_the_tenants_own_password_policy() {
        let ann = UserId::new();
        let resets = Arc::new(FakeResetRequestStore::with_request(&pending(ann)));

        let status = status_of(resets, FakeUserStore::with_user(ann, ADDRESS));

        assert_eq!(status, PasswordLinkStatus::Valid(PasswordPolicy::relaxed()));
    }

    /// Ann already used her link. The page says the password was changed
    /// rather than offering the form again.
    #[test]
    fn a_spent_link_reads_as_already_used() {
        let ann = UserId::new();
        let holder = stored_user(ann, ADDRESS, UserStatus::Active);
        let mut request = pending(ann);
        request.complete(&holder, clock::now()).unwrap();
        let resets = Arc::new(FakeResetRequestStore::with_request(&request));

        let status = status_of(resets, FakeUserStore::with_user(ann, ADDRESS));

        assert_eq!(status, PasswordLinkStatus::AlreadyUsed);
    }

    /// A reset mailed before Ann changed her address reports expired.
    #[test]
    fn a_link_to_an_address_the_account_left_reads_as_expired() {
        let ann = UserId::new();
        let resets = Arc::new(FakeResetRequestStore::with_request(&pending(ann)));

        let status = status_of(resets, FakeUserStore::with_user(ann, "ann@new.example"));

        assert_eq!(status, PasswordLinkStatus::Expired);
    }

    /// Ann's workspace signs people in by passkey only. Her usable link
    /// offers no password to choose.
    #[test]
    fn a_usable_link_in_a_tenant_without_passwords_offers_no_form() {
        let ann = UserId::new();
        let resets = Arc::new(FakeResetRequestStore::with_request(&pending(ann)));
        let use_case = ResetStatusUseCase::new(ResetStatusPorts {
            reset_store: resets,
            user_store: Arc::new(FakeUserStore::with_user(ann, ADDRESS)),
            tenant_store: tenant_store_without_password_login(),
            ..ResetStatusPorts::fakes()
        });

        let status = block_on(use_case.execute(&test_ctx().tenant(), LINK.to_owned())).unwrap();

        assert_eq!(status, PasswordLinkStatus::ValidWithoutPassword);
    }

    /// A link nobody issued reads as invalid, not as an error.
    #[test]
    fn an_unknown_link_reads_as_invalid() {
        let status = status_of(
            Arc::new(FakeResetRequestStore::empty()),
            FakeUserStore::empty(),
        );

        assert_eq!(status, PasswordLinkStatus::Invalid);
    }

    /// A reset whose account is absent reports an invalid link.
    #[test]
    fn a_link_whose_account_is_gone_reads_as_invalid() {
        let resets = Arc::new(FakeResetRequestStore::with_request(&pending(UserId::new())));

        let status = status_of(resets, FakeUserStore::empty());

        assert_eq!(status, PasswordLinkStatus::Invalid);
    }
}
