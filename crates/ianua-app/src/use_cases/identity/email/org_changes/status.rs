//! Org email change status: what an organization member's or operator's
//! confirmation link is worth, without spending it.

use ianua_domain::shared::clock;
use ianua_domain::types::TokenStatus;

use crate::error::{AppError, OrInternal};
use crate::use_case::Query;
use crate::use_cases::identity::email::org_changes::org_change::{
    OrgChangePorts, changing_account,
};

/// Reads what an organization-plane email change link is worth before its
/// page acts on it.
pub struct OrgChangeStatusUseCase {
    ports: OrgChangePorts,
}

impl OrgChangeStatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: OrgChangePorts) -> Self {
        Self { ports }
    }
}

impl Query for OrgChangeStatusUseCase {
    type Caller = ();
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
    async fn execute(&self, (): &(), raw_token: String) -> Result<TokenStatus, AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let token_hash = self.ports.token_generator.hash_raw(&raw_token);
        let Some(change) = self
            .ports
            .change_store
            .find_by_token_hash(&token_hash)
            .await
            .or_internal()?
        else {
            return Ok(TokenStatus::Invalid);
        };
        let account = match changing_account(&self.ports, &change).await {
            Ok(account) => account,
            Err(AppError::NotFound(_)) => return Ok(TokenStatus::Invalid),
            Err(other) => return Err(other),
        };
        Ok(change.state_for(account.changing(), clock::now()).into())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrganizationId;
    use time::OffsetDateTime;

    use super::*;
    use crate::ports::organization::OrgUserStore;
    use crate::ports::shared::OrgEmailChangeStore;
    use crate::test_support::block_on;
    use crate::test_support::identity::{FakeEmailChangeStore, stored_change};
    use crate::test_support::organization::{FakeOrgUserStore, test_org_user};

    const LINK: &str = "owen-change";

    fn status_of(link_until: OffsetDateTime, raw: &str) -> TokenStatus {
        let owen = test_org_user(OrganizationId::new(), "owen@acme.com", OrgRole::Member);
        let members = FakeOrgUserStore::empty();
        block_on(members.save(&owen)).unwrap();
        let changes = FakeEmailChangeStore::empty();
        let change = stored_change(
            (*owen.id()).into(),
            ("owen@acme.com", "new@acme.com"),
            LINK,
            link_until,
        );
        block_on(OrgEmailChangeStore::save(&changes, &change)).unwrap();
        let use_case = OrgChangeStatusUseCase::new(OrgChangePorts {
            change_store: Arc::new(changes),
            org_user_store: Arc::new(members),
            ..OrgChangePorts::fakes()
        });
        block_on(use_case.execute(&(), raw.to_owned())).unwrap()
    }

    /// Owen opens his page with a live link. It reads as valid.
    #[test]
    fn a_live_link_is_valid() {
        let status = status_of(clock::now() + time::Duration::hours(1), LINK);

        assert_eq!(status, TokenStatus::Valid);
    }

    /// Owen opens his page a day late. The link reads as expired.
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
