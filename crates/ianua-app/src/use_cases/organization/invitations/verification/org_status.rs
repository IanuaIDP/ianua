//! Org verification status: what a member's verification link is worth,
//! without spending it.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::email_verification::EmailVerification;
use ianua_domain::message;
use ianua_domain::shared::clock;

use crate::email::VerificationTokenStatus;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::{OrgTokenStore, OrgUserStore};
use crate::use_case::Query;
use crate::use_cases::organization::lookup::existing_token;

/// The ports [`OrgVerificationStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgVerificationStatusPorts {
    /// Loads members.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Loads verification links.
    pub token_store: Arc<dyn OrgTokenStore<EmailVerification>>,
    /// Hashes the link being read.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Reads what a member's verification link is worth before its page acts
/// on it.
pub struct OrgVerificationStatusUseCase {
    ports: OrgVerificationStatusPorts,
}

impl OrgVerificationStatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: OrgVerificationStatusPorts) -> Self {
        Self { ports }
    }
}

impl Query for OrgVerificationStatusUseCase {
    type Caller = ();
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
    /// - `AppError::NotFound` if the link is unknown, its member is gone, or
    ///   the link must be answered as if it did not exist.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(
        &self,
        (): &(),
        raw_token: String,
    ) -> Result<VerificationTokenStatus, AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let token_hash = self.ports.token_generator.hash_raw(&raw_token);
        let token = existing_token(self.ports.token_store.as_ref(), &token_hash).await?;
        let member = self
            .ports
            .org_user_store
            .find_by_id(token.org_user_id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "identity-invalid-verification-token",
                "invalid verification token"
            ))?;
        if member.email_verified() {
            return Ok(VerificationTokenStatus::Verified);
        }
        VerificationTokenStatus::of(token.state_for(&member, clock::now())).or_not_found(message!(
            "identity-invalid-verification-token",
            "invalid verification token"
        ))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::types::OrganizationId;
    use time::Duration;

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::organization::{
        FakeOrgTokenStore, org_user_store_with, stored_org_token, test_org_user,
        unconfirmed_org_user,
    };

    const LINK: &str = "fake_refresh_link";

    fn status_of(
        member: OrgUser,
        expires_in: Duration,
    ) -> Result<VerificationTokenStatus, AppError> {
        let link = stored_org_token::<EmailVerification>(&member, LINK, clock::now() + expires_in);
        let uc = OrgVerificationStatusUseCase::new(OrgVerificationStatusPorts {
            org_user_store: Arc::new(org_user_store_with([member])),
            token_store: Arc::new(FakeOrgTokenStore::holding([link])),
            ..OrgVerificationStatusPorts::fakes()
        });
        block_on(uc.execute(&(), LINK.to_owned()))
    }

    /// Fiona opens her link while it is in date. The page is told following
    /// it will confirm her address.
    #[test]
    fn a_usable_link_is_valid() {
        let fiona = unconfirmed_org_user(OrganizationId::new(), "fiona@acme.test");

        let status = status_of(fiona, Duration::hours(1)).unwrap();

        assert_eq!(status, VerificationTokenStatus::Valid);
    }

    /// Fiona opens her link after it ran out. It reads as expired, so she
    /// can ask for another.
    #[test]
    fn an_out_of_date_link_is_expired() {
        let fiona = unconfirmed_org_user(OrganizationId::new(), "fiona@acme.test");

        let status = status_of(fiona, Duration::hours(-1)).unwrap();

        assert_eq!(status, VerificationTokenStatus::Expired);
    }

    /// Dana's address is already confirmed. She is told the job is done.
    #[test]
    fn a_confirmed_address_reads_as_verified() {
        let dana = test_org_user(OrganizationId::new(), "dana@acme.test", OrgRole::Member);

        let status = status_of(dana, Duration::hours(1)).unwrap();

        assert_eq!(status, VerificationTokenStatus::Verified);
    }

    /// An unknown verification link returns not found when its status is requested.
    #[test]
    fn an_unknown_link_is_not_found() {
        let uc = OrgVerificationStatusUseCase::new(OrgVerificationStatusPorts::fakes());

        let result = block_on(uc.execute(&(), LINK.to_owned()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
