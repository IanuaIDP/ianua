//! Verification status: what a verification link is worth, without
//! spending it.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::message;
use ianua_domain::shared::clock;

use crate::email::VerificationTokenStatus;
use crate::error::AppError;
use crate::ports::identity::{UserStore, VerificationTokenStore};
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::identity::lookup::existing_verification_token;

/// The ports [`VerificationStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct VerificationStatusPorts {
    /// Loads users.
    pub user_store: Arc<dyn UserStore>,
    /// Loads verification links.
    pub token_store: Arc<dyn VerificationTokenStore>,
    /// Hashes the link being read.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Reads what a verification link is worth before its page acts on it.
pub struct VerificationStatusUseCase {
    ports: VerificationStatusPorts,
}

impl VerificationStatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: VerificationStatusPorts) -> Self {
        Self { ports }
    }
}

impl Query for VerificationStatusUseCase {
    type Caller = ScopedTenant;
    type Input = String;
    type Output = Result<VerificationTokenStatus, AppError>;

    /// What following `raw_token` would do, without spending it.
    ///
    /// The address decides first: once confirmed, no link matters, and its
    /// holder is told the job is done rather than that their link is stale.
    /// After that the link is usable, or it ran out and another can be sent.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the token is unknown, its user is gone, or
    ///   the link must be answered as if it did not exist.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        raw_token: String,
    ) -> Result<VerificationTokenStatus, AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let token_hash = self.ports.token_generator.hash_raw(&raw_token);
        let token =
            existing_verification_token(self.ports.token_store.as_ref(), tenant, &token_hash)
                .await?;
        let user = existing_user(self.ports.user_store.as_ref(), tenant, token.user_id()).await?;
        if user.email_verified() {
            return Ok(VerificationTokenStatus::Verified);
        }
        VerificationTokenStatus::of(token.state_for(&user, clock::now())).ok_or_else(|| {
            AppError::NotFound(message!(
                "identity-invalid-verification-token",
                "invalid verification token"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::identity::{FakeTokenStore, FakeUserStore, stored_verification_link};
    use crate::test_support::{block_on, test_ctx};

    const LINK: &str = "ann-link";

    fn status(
        users: FakeUserStore,
        link_until: OffsetDateTime,
        ann: UserId,
        raw: &str,
    ) -> Result<VerificationTokenStatus, AppError> {
        let tokens = FakeTokenStore::holding(stored_verification_link(
            LINK,
            ann,
            "ann@acme.com",
            link_until,
        ));
        let use_case = VerificationStatusUseCase::new(VerificationStatusPorts {
            user_store: Arc::new(users),
            token_store: Arc::new(tokens),
            ..VerificationStatusPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx().tenant(), raw.to_owned()))
    }

    fn in_an_hour() -> OffsetDateTime {
        clock::now() + time::Duration::hours(1)
    }

    /// Ann opens her page with a live link. It reads as valid, and stays
    /// usable.
    #[test]
    fn a_live_link_is_valid() {
        let ann = UserId::new();

        let result = status(
            FakeUserStore::with_unverified_user(ann, "ann@acme.com"),
            in_an_hour(),
            ann,
            LINK,
        );

        assert_eq!(result.unwrap(), VerificationTokenStatus::Valid);
    }

    /// Ann opens her page a day late. The link reads as expired.
    #[test]
    fn an_expired_link_reads_as_expired() {
        let ann = UserId::new();
        let ran_out = clock::now() - time::Duration::minutes(1);

        let result = status(
            FakeUserStore::with_unverified_user(ann, "ann@acme.com"),
            ran_out,
            ann,
            LINK,
        );

        assert_eq!(result.unwrap(), VerificationTokenStatus::Expired);
    }

    /// Ann already confirmed her address. Any link reads as done.
    #[test]
    fn a_confirmed_address_reads_as_verified() {
        let ann = UserId::new();

        let result = status(
            FakeUserStore::with_user(ann, "ann@acme.com"),
            in_an_hour(),
            ann,
            LINK,
        );

        assert_eq!(result.unwrap(), VerificationTokenStatus::Verified);
    }

    /// A link nobody sent is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let ann = UserId::new();

        let result = status(
            FakeUserStore::with_unverified_user(ann, "ann@acme.com"),
            in_an_hour(),
            ann,
            "nobody-sent-this",
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
