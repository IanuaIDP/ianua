//! What a member's password reset link is worth, told without spending it.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::password_reset::PasswordReset;
use ianua_domain::shared::clock;
use ianua_domain::types::{PasswordLinkStatus, TokenStatus};

use crate::error::AppError;
use crate::ports::organization::{OrgTokenStore, OrgUserStore, OrganizationStore};
use crate::services::authentication::password_rules;
use crate::use_case::Query;
use crate::use_cases::organization::password_reset::links::MemberResetLinks;

/// The ports [`OrgResetStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgResetStatusPorts {
    /// The member a link was mailed for.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Members' reset links.
    pub token_store: Arc<dyn OrgTokenStore<PasswordReset>>,
    /// The member's organization, for its own password rules.
    pub org_store: Arc<dyn OrganizationStore>,
    /// Hashes the link's token the way it was stored.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Reports what a member's reset link is worth without spending it.
pub struct OrgResetStatusUseCase {
    ports: OrgResetStatusPorts,
}

impl OrgResetStatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: OrgResetStatusPorts) -> Self {
        Self { ports }
    }
}

impl Query for OrgResetStatusUseCase {
    type Caller = ();
    type Input = String;
    type Output = Result<PasswordLinkStatus, AppError>;

    /// What the reset link `raw_token` is worth, without spending it.
    ///
    /// The page a link lands on chooses between a password form, "this link
    /// has expired" and "your password was already changed" before the
    /// reader types anything. An unknown link, or one whose member is gone,
    /// answers invalid rather than failing. A usable link carries its
    /// organization's own password rules, the ones the reset enforces: the
    /// link is the only thing on this page that names the organization.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the token is malformed.
    /// - `AppError::NotFound` when the link is usable but its organization
    ///   is gone.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(&self, (): &(), raw_token: String) -> Result<PasswordLinkStatus, AppError> {
        let links = MemberResetLinks {
            tokens: self.ports.token_store.as_ref(),
            members: self.ports.org_user_store.as_ref(),
            hasher: self.ports.token_generator.as_ref(),
        };
        let Some(followed) = links.followed(&raw_token).await? else {
            return Ok(PasswordLinkStatus::Invalid);
        };
        let status = TokenStatus::from(followed.link.state_for(&followed.holder, clock::now()));
        if let Some(answer) = PasswordLinkStatus::without_form(status) {
            return Ok(answer);
        }
        let organizations = self.ports.org_store.as_ref();
        let policy =
            password_rules::for_organization(organizations, followed.holder.organization_id())
                .await?;
        Ok(PasswordLinkStatus::Valid(policy))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::access::token::{OrgToken, OrgTokenRow};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{Email, OrgUserId, OrganizationId, Usage};
    use time::Duration;

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::identity::hash_of_link;
    use crate::test_support::organization::{
        FakeOrgTokenStore, org_store_with_strict_password_policy, org_user_store_with,
        strict_password_policy, test_org_user,
    };

    const ADDRESS: &str = "alice@acme.test";
    const LINK: &str = "fake_refresh_0";

    /// A link for `alice` issued an hour before `expires_at` or now,
    /// whichever is earlier, used as `usage` says.
    fn link_for(alice: OrgUserId, expires_in: Duration, usage: Usage) -> OrgToken<PasswordReset> {
        let expires_at = clock::now() + expires_in;
        OrgToken::reconstitute(OrgTokenRow {
            token_hash: hash_of_link(LINK),
            org_user_id: alice,
            sent_to: Email::new(ADDRESS).unwrap(),
            created_at: expires_at.min(clock::now()) - Duration::hours(1),
            expires_at,
            usage,
        })
        .unwrap()
    }

    /// The status of `link`, issued to Alice of an organization with strict
    /// password rules.
    fn status_of(link: impl FnOnce(OrgUserId) -> OrgToken<PasswordReset>) -> PasswordLinkStatus {
        let organization = OrganizationId::new();
        let alice = test_org_user(organization, ADDRESS, OrgRole::Member);
        let tokens = FakeOrgTokenStore::holding([link(*alice.id())]);
        let use_case = OrgResetStatusUseCase::new(OrgResetStatusPorts {
            org_user_store: Arc::new(org_user_store_with([alice])),
            token_store: Arc::new(tokens),
            org_store: org_store_with_strict_password_policy(organization),
            ..OrgResetStatusPorts::fakes()
        });
        block_on(use_case.execute(&(), LINK.to_owned())).unwrap()
    }

    /// Alice follows her link within the hour. The page may show the form,
    /// held to her organization's own rules.
    #[test]
    fn a_usable_link_carries_its_organizations_own_password_policy() {
        let status = status_of(|alice| link_for(alice, Duration::hours(1), Usage::Unused));

        assert_eq!(status, PasswordLinkStatus::Valid(strict_password_policy()));
    }

    /// Alice follows a link that ran out. The page says so.
    #[test]
    fn an_out_of_date_link_reads_expired() {
        let status = status_of(|alice| link_for(alice, -Duration::seconds(1), Usage::Unused));

        assert_eq!(status, PasswordLinkStatus::Expired);
    }

    /// Alice follows a link she already used. The page says the password
    /// was already changed.
    #[test]
    fn a_spent_link_reads_already_used() {
        let status = status_of(|alice| {
            link_for(
                alice,
                Duration::hours(1),
                Usage::Used {
                    at: clock::now() - Duration::minutes(1),
                },
            )
        });

        assert_eq!(status, PasswordLinkStatus::AlreadyUsed);
    }

    /// A link nobody issued reads invalid rather than failing.
    #[test]
    fn an_unknown_link_reads_invalid() {
        let use_case = OrgResetStatusUseCase::new(OrgResetStatusPorts::fakes());

        let status = block_on(use_case.execute(&(), LINK.to_owned()));

        assert_eq!(status.unwrap(), PasswordLinkStatus::Invalid);
    }

    /// An empty reset token fails validation instead of returning a link status.
    #[test]
    fn a_malformed_token_is_refused() {
        let use_case = OrgResetStatusUseCase::new(OrgResetStatusPorts::fakes());

        let status = block_on(use_case.execute(&(), String::new()));

        assert!(matches!(status, Err(AppError::Domain(_))));
    }
}
