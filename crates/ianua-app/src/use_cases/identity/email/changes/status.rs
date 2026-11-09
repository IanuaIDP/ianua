//! Email change status: what a tenant user's confirmation link is worth,
//! without spending it.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::email_change::ChangingAccount;
use ianua_domain::shared::clock;
use ianua_domain::types::TokenStatus;

use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::shared::TenantEmailChangeStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::identity::email::changes::tenant::changing_user;

/// The ports [`ChangeStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeStatusPorts {
    /// Loads pending email changes.
    pub change_store: Arc<dyn TenantEmailChangeStore>,
    /// Loads the account a change was asked for.
    pub user_store: Arc<dyn UserStore>,
    /// Hashes the link being read.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Reads what an email change link is worth before its page acts on it.
pub struct ChangeStatusUseCase {
    ports: ChangeStatusPorts,
}

impl ChangeStatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ChangeStatusPorts) -> Self {
        Self { ports }
    }
}

impl Query for ChangeStatusUseCase {
    type Caller = ScopedTenant;
    type Input = String;
    type Output = Result<TokenStatus, AppError>;

    /// What following `raw_token` would do for the account its change was
    /// asked for, without spending it. A link nobody sent, or whose account
    /// is gone, reads as invalid.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        raw_token: String,
    ) -> Result<TokenStatus, AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let token_hash = self.ports.token_generator.hash_raw(&raw_token);
        let Some(change) = self
            .ports
            .change_store
            .find_by_token_hash(tenant, &token_hash)
            .await
            .or_internal()?
        else {
            return Ok(TokenStatus::Invalid);
        };
        let user = match changing_user(self.ports.user_store.as_ref(), tenant, &change).await {
            Ok(user) => user,
            Err(AppError::NotFound(_)) => return Ok(TokenStatus::Invalid),
            Err(other) => return Err(other),
        };
        Ok(change
            .state_for(ChangingAccount::from(&user), clock::now())
            .into())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::identity::{FakeEmailChangeStore, FakeUserStore, stored_change};
    use crate::test_support::{block_on, test_ctx};

    const LINK: &str = "ann-change";

    fn status_of(link_until: OffsetDateTime, raw: &str) -> TokenStatus {
        let ann = UserId::new();
        let changes = FakeEmailChangeStore::empty();
        let pending = stored_change(
            ann.into(),
            ("ann@acme.com", "new@acme.com"),
            LINK,
            link_until,
        );
        block_on(TenantEmailChangeStore::save(
            &changes,
            &test_ctx().tenant(),
            &pending,
        ))
        .unwrap();
        let use_case = ChangeStatusUseCase::new(ChangeStatusPorts {
            change_store: Arc::new(changes),
            user_store: Arc::new(FakeUserStore::with_user(ann, "ann@acme.com")),
            ..ChangeStatusPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx().tenant(), raw.to_owned())).unwrap()
    }

    /// Ann opens her page with a live link. It reads as valid.
    #[test]
    fn a_live_link_is_valid() {
        let status = status_of(clock::now() + time::Duration::hours(1), LINK);

        assert_eq!(status, TokenStatus::Valid);
    }

    /// Ann opens her page a day late. The link reads as expired.
    #[test]
    fn a_link_that_ran_out_reads_as_expired() {
        let status = status_of(clock::now() - time::Duration::minutes(1), LINK);

        assert_eq!(status, TokenStatus::Expired);
    }

    /// A link nobody sent reads as invalid.
    #[test]
    fn an_unknown_link_reads_as_invalid() {
        let status = status_of(clock::now() + time::Duration::hours(1), "nobody-sent-this");

        assert_eq!(status, TokenStatus::Invalid);
    }
}
