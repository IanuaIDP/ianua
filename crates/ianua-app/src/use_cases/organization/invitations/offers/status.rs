//! Org invitation status: what an organization invitation link is worth,
//! without spending it.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::shared::clock;
use ianua_domain::types::{OrganizationId, PasswordLinkStatus, TokenStatus};

use crate::error::AppError;
use crate::ports::organization::{OrgInvitationStore, OrganizationStore};
use crate::services::authentication::password_rules;
use crate::use_case::Query;
use crate::use_cases::organization::invitations::offers::link::InvitationLinks;

/// An invitation link as followed: the organization it names and the
/// token it carries. The token proves nothing until it is looked up.
pub struct FollowedInvitation {
    /// The organization the link names.
    pub organization_id: OrganizationId,
    /// The raw token the link carries.
    pub raw_token: String,
}

/// The ports [`OrgStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgStatusPorts {
    /// Finds the invitation a link belongs to.
    pub org_invitation_store: Arc<dyn OrgInvitationStore>,
    /// Reads the organization's own password rules.
    pub organization_store: Arc<dyn OrganizationStore>,
    /// Hashes the link being read.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Reads what an organization invitation link is worth before its page
/// acts on it.
pub struct OrgStatusUseCase {
    ports: OrgStatusPorts,
}

impl OrgStatusUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: OrgStatusPorts) -> Self {
        Self { ports }
    }

    /// What the link is worth, before the password rules are added.
    async fn link_status(
        &self,
        organization_id: &OrganizationId,
        raw_token: &str,
    ) -> Result<TokenStatus, AppError> {
        let links = InvitationLinks {
            invitations: self.ports.org_invitation_store.as_ref(),
            token_generator: self.ports.token_generator.as_ref(),
        };
        let found = links.followed(organization_id, raw_token).await?;
        Ok(found.map_or(TokenStatus::Invalid, |invitation| {
            invitation.state(clock::now()).into()
        }))
    }
}

impl Query for OrgStatusUseCase {
    type Caller = ();
    type Input = FollowedInvitation;
    type Output = Result<PasswordLinkStatus, AppError>;

    /// What following `raw_token` would do, without spending it.
    ///
    /// A usable link also carries the organization's password rules, the
    /// same ones accepting enforces, because the invitee has no account yet
    /// to learn them from. A link this organization never sent reads as
    /// invalid, so nothing here confirms an invitation exists.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the link is usable but the organization is
    ///   gone.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(
        &self,
        (): &(),
        link: FollowedInvitation,
    ) -> Result<PasswordLinkStatus, AppError> {
        let organization_id = &link.organization_id;
        let status = self.link_status(organization_id, &link.raw_token).await?;
        if let Some(answer) = PasswordLinkStatus::without_form(status) {
            return Ok(answer);
        }
        let policy = password_rules::for_organization(
            self.ports.organization_store.as_ref(),
            organization_id,
        )
        .await?;
        Ok(PasswordLinkStatus::Valid(policy))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{ActedBy, OrgUserId, TokenHash};

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::organization::{
        FakeOrgInvitationStore, expired_org_invitation, org_store_with_strict_password_policy,
        pending_org_invitation, strict_password_policy,
    };

    const LINK: &str = "fake_refresh_7";

    fn followed(organization_id: OrganizationId) -> FollowedInvitation {
        FollowedInvitation {
            organization_id,
            raw_token: LINK.to_owned(),
        }
    }

    fn link_hash() -> TokenHash {
        TokenHash::from_stored("fake_hash_7".to_owned())
    }

    fn status_of(
        invitations: FakeOrgInvitationStore,
        organization_id: OrganizationId,
    ) -> PasswordLinkStatus {
        let uc = OrgStatusUseCase::new(OrgStatusPorts {
            org_invitation_store: Arc::new(invitations),
            organization_store: org_store_with_strict_password_policy(organization_id),
            ..OrgStatusPorts::fakes()
        });
        block_on(uc.execute(&(), followed(organization_id))).unwrap()
    }

    fn revoked(organization_id: OrganizationId) -> FakeOrgInvitationStore {
        let mut invitation = pending_org_invitation(
            organization_id,
            OrgUserId::new(),
            "bob@acme.test",
            link_hash(),
        );
        invitation.revoke(ActedBy::Platform).unwrap();
        FakeOrgInvitationStore::holding([invitation])
    }

    /// Bob opens his invitation while it is open. The page is told it is
    /// valid, with Acme's own password rules for the form.
    #[test]
    fn an_open_invitation_is_valid_with_the_organizations_rules() {
        let organization_id = OrganizationId::new();
        let invitations = FakeOrgInvitationStore::holding([pending_org_invitation(
            organization_id,
            OrgUserId::new(),
            "bob@acme.test",
            link_hash(),
        )]);

        let status = status_of(invitations, organization_id);

        assert_eq!(status, PasswordLinkStatus::Valid(strict_password_policy()));
    }

    /// Bob opens his invitation after it ran out. It reads as expired, so
    /// he knows to ask for another.
    #[test]
    fn an_out_of_date_invitation_is_expired() {
        let organization_id = OrganizationId::new();
        let invitations = FakeOrgInvitationStore::holding([expired_org_invitation(
            organization_id,
            OrgUserId::new(),
            "bob@acme.test",
            link_hash(),
        )]);

        assert_eq!(
            status_of(invitations, organization_id),
            PasswordLinkStatus::Expired
        );
    }

    /// Bob opens an invitation Olivia withdrew. It reads as used.
    #[test]
    fn a_revoked_invitation_is_already_used() {
        let organization_id = OrganizationId::new();

        assert_eq!(
            status_of(revoked(organization_id), organization_id),
            PasswordLinkStatus::AlreadyUsed
        );
    }

    /// An unknown invitation link reports an invalid status.
    #[test]
    fn an_unknown_link_is_invalid() {
        assert_eq!(
            status_of(FakeOrgInvitationStore::empty(), OrganizationId::new()),
            PasswordLinkStatus::Invalid
        );
    }

    /// Reading the link does not spend it: Bob's invitation still reads as
    /// valid afterwards.
    #[test]
    fn reading_the_link_leaves_it_open() {
        let organization_id = OrganizationId::new();
        let invitations = Arc::new(FakeOrgInvitationStore::holding([pending_org_invitation(
            organization_id,
            OrgUserId::new(),
            "bob@acme.test",
            link_hash(),
        )]));
        let uc = OrgStatusUseCase::new(OrgStatusPorts {
            org_invitation_store: invitations.clone(),
            organization_store: org_store_with_strict_password_policy(organization_id),
            ..OrgStatusPorts::fakes()
        });
        block_on(uc.execute(&(), followed(organization_id))).unwrap();

        let again = block_on(uc.execute(&(), followed(organization_id))).unwrap();

        assert_eq!(again.token_status(), TokenStatus::Valid);
    }
}
