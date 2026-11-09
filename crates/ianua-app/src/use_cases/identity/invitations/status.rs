//! Invitation status: what an invitation link is worth, without spending it.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::shared::clock;
use ianua_domain::types::{PasswordLinkStatus, TokenStatus};

use crate::error::{AppError, OrInternal};
use crate::ports::identity::InvitationStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::password_rules;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// The ports [`StatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StatusPorts {
    /// Finds the invitation a link belongs to.
    pub invitation_store: Arc<dyn InvitationStore>,
    /// Reads the tenant's own password rules.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Hashes the link being read.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Reads what an invitation link is worth before its page acts on it.
pub struct StatusUseCase {
    ports: StatusPorts,
}

impl StatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: StatusPorts) -> Self {
        Self { ports }
    }

    /// What the link is worth, before the password rules are added.
    async fn token_status(
        &self,
        tenant: &ScopedTenant,
        raw_token: &str,
    ) -> Result<TokenStatus, AppError> {
        crate::input::validate_token("token", raw_token)?;
        let token_hash = self.ports.token_generator.hash_raw(raw_token);
        let found = self
            .ports
            .invitation_store
            .find_by_token_hash(tenant, &token_hash)
            .await
            .or_internal()?;
        Ok(found.map_or(TokenStatus::Invalid, |invitation| {
            invitation.state(clock::now()).into()
        }))
    }
}

impl Query for StatusUseCase {
    type Caller = ScopedTenant;
    type Input = String;
    type Output = Result<PasswordLinkStatus, AppError>;

    /// What following `raw_token` would do, without spending it.
    ///
    /// A usable link also carries the tenant's password rules, the same ones
    /// accepting enforces, because the invitee has no account yet to learn
    /// them from. A tenant without password sign-in answers that there is no
    /// password to choose. A link this tenant never issued reads as invalid.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the link is usable but its tenant is gone.
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
        let policy =
            password_rules::for_new_tenant_password(self.ports.tenant_store.as_ref(), tenant)
                .await?;
        Ok(policy.map_or(
            PasswordLinkStatus::ValidWithoutPassword,
            PasswordLinkStatus::Valid,
        ))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::invitations::offer::OfferState;
    use ianua_domain::types::{RoleId, UserId};

    use super::*;
    use crate::test_support::identity::{FakeInvitationStore, InvitationSeed};
    use crate::test_support::organization::strict_password_policy;
    use crate::test_support::tenant::{
        FakeTenantStore, tenant_store_with_password_policy, tenant_store_without_password_login,
    };
    use crate::test_support::{block_on, test_ctx};

    const LINK: &str = "bob-invite";

    fn bobs_invitation() -> InvitationSeed {
        InvitationSeed::for_user(UserId::new(), "bob@acme.com", RoleId::new(), LINK)
    }

    fn status_in(
        tenants: Arc<FakeTenantStore>,
        invitations: FakeInvitationStore,
        raw: &str,
    ) -> PasswordLinkStatus {
        let use_case = StatusUseCase::new(StatusPorts {
            invitation_store: Arc::new(invitations),
            tenant_store: tenants,
            ..StatusPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx().tenant(), raw.to_owned())).unwrap()
    }

    fn status_of(invitations: FakeInvitationStore, raw: &str) -> PasswordLinkStatus {
        status_in(
            tenant_store_with_password_policy(strict_password_policy()),
            invitations,
            raw,
        )
    }

    /// Bob opens his invitation a day late. It reads as expired.
    #[test]
    fn an_out_of_date_invitation_reads_as_expired() {
        let ran_out = bobs_invitation().expiring_at(clock::now() - time::Duration::seconds(1));

        let status = status_of(FakeInvitationStore::holding(ran_out.stored()), LINK);

        assert_eq!(status, PasswordLinkStatus::Expired);
    }

    /// Bob's invitation was withdrawn. It reads as used, with nothing left
    /// to do.
    #[test]
    fn a_revoked_invitation_reads_as_already_used() {
        let revoked = bobs_invitation().stored_as(OfferState::Revoked);

        let status = status_of(FakeInvitationStore::holding(revoked), LINK);

        assert_eq!(status, PasswordLinkStatus::AlreadyUsed);
    }

    /// A link nobody sent reads as invalid.
    #[test]
    fn an_unknown_link_reads_as_invalid() {
        let status = status_of(FakeInvitationStore::empty(), LINK);

        assert_eq!(status, PasswordLinkStatus::Invalid);
    }

    /// Bob has no account yet, so the link is the only place the form can
    /// learn the tenant's password rules.
    #[test]
    fn a_usable_invitation_carries_the_tenants_own_password_rules() {
        let status = status_of(
            FakeInvitationStore::holding(bobs_invitation().stored()),
            LINK,
        );

        assert_eq!(status, PasswordLinkStatus::Valid(strict_password_policy()));
    }

    /// The tenant signs people in only with passkeys. There is no password
    /// to choose, so the page shows no form.
    #[test]
    fn a_tenant_without_password_sign_in_offers_no_password_form() {
        let invitations = FakeInvitationStore::holding(bobs_invitation().stored());

        let status = status_in(tenant_store_without_password_login(), invitations, LINK);

        assert_eq!(status, PasswordLinkStatus::ValidWithoutPassword);
    }
}
