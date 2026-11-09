//! What a member may do on their organization, worked out from the stored
//! records for the credential they came with.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignedIn;
use ianua_domain::domains::organization::access::api_key::OrgApiKey;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::access::session_check::OrgSessionCheck;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::control::{Carried, OrgControl};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::status::OrgStanding;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::clock;
use ianua_domain::types::Seconds;
use time::OffsetDateTime;

use crate::acting::OrgActors;
use crate::context::{OrgCaller, OrgCredential};
use crate::error::AppError;
use crate::ports::organization::{
    OrgApiKeyStore, OrgSessionStore, OrgUserStore, OrganizationStore,
};

/// The stores [`OrgActing`] reads a member's records from.
pub struct OrgActingPorts {
    /// Loads the member's organization and its current access settings.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Their members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Members' sessions.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Organization API keys.
    pub org_api_keys: Arc<dyn OrgApiKeyStore>,
}

/// Works out who acts on an organization, and through what, from the
/// stored records for the credential a member came with.
pub struct OrgActing {
    ports: OrgActingPorts,
}

/// What a member acts through, as loaded.
pub(crate) enum Held {
    /// A session they signed in to.
    Session(OrgSession),
    /// An organization API key.
    Key(OrgApiKey),
}

/// A member, loaded fresh, with what they act through, checked when it was
/// loaded. It gives the domain the [`OrgControl`] it asks for.
pub struct OrgActor {
    standing: OrgStanding,
    idle_timeout: Seconds,
    now: OffsetDateTime,
    member: OrgUser,
    held: Held,
}

impl OrgActor {
    /// `member` acting through `held` on `organization` as it stands at
    /// `now`.
    pub(crate) fn new(
        organization: &Organization,
        member: OrgUser,
        held: Held,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            standing: organization.standing(),
            idle_timeout: organization.auth_config().idle_timeout_secs(),
            now,
            member,
            held,
        }
    }

    /// The member acting.
    #[must_use]
    pub fn member(&self) -> &OrgUser {
        &self.member
    }

    /// The control the domain asks for: the member, the organization as it
    /// stood when loaded, and what they act through.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session no longer passes its
    ///   check.
    pub fn control(&self) -> Result<OrgControl<'_>, AppError> {
        let carried = match &self.held {
            Held::Session(session) => Carried::Session(
                self.check()
                    .checked(session)
                    .ok_or(AppError::Unauthenticated)?,
            ),
            Held::Key(key) => Carried::Key(key),
        };
        Ok(OrgControl::new(self.standing, &self.member, carried))
    }

    /// The member signed in to the session they act through, while it
    /// passes its check. For what a member does to their own account:
    /// their devices, passkeys and sessions.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when they act through a key rather
    ///   than a session, or the session no longer passes its check.
    pub fn signed_in(&self) -> Result<SignedIn<ResolvedOrganization>, AppError> {
        match &self.held {
            Held::Session(session) => session
                .signed_in(&self.check())
                .ok_or(AppError::Unauthenticated),
            Held::Key(_) => Err(AppError::Unauthenticated),
        }
    }

    /// What the member's session is held to each time it is used.
    fn check(&self) -> OrgSessionCheck<'_> {
        OrgSessionCheck {
            organization: self.standing,
            member: &self.member,
            idle_timeout: self.idle_timeout,
            now: self.now,
        }
    }
}

impl OrgActing {
    /// A resolver reading from `ports`.
    #[must_use]
    pub fn new(ports: OrgActingPorts) -> Self {
        Self { ports }
    }

    async fn held(&self, caller: &OrgCaller) -> Result<Held, AppError> {
        match caller.credential() {
            OrgCredential::Session(id) => self
                .ports
                .org_sessions
                .find_by_id(id)
                .await
                .map_err(AppError::from_domain)?
                .map(Held::Session)
                .ok_or(AppError::Unauthenticated),
            OrgCredential::ApiKey(id) => self
                .ports
                .org_api_keys
                .find_by_id(id)
                .await
                .map_err(AppError::from_domain)?
                .map(Held::Key)
                .ok_or(AppError::Unauthenticated),
        }
    }
}

#[async_trait]
impl OrgActors for OrgActing {
    async fn actor(&self, caller: &OrgCaller) -> Result<(Organization, OrgActor), AppError> {
        let organization = self
            .ports
            .organizations
            .find_by_id(&caller.organization_id())
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)?;
        let member = self
            .ports
            .org_users
            .find_by_id(caller.member())
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)?;
        let held = self.held(caller).await?;
        let actor = OrgActor::new(&organization, member, held, clock::now());
        actor
            .control()?
            .ensure_genuine(organization.id())
            .map_err(AppError::from_domain)?;
        Ok((organization, actor))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::access::api_key::MintedThrough;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{OrgApiKeyId, OrgUserId, OrganizationId};

    use super::*;
    use crate::test_support::organization::{
        FakeOrgApiKeyStore, OrgShape, org_shaped, org_store_with, org_user_store_with,
        stored_org_api_key, test_org_user,
    };
    use crate::test_support::{Fake, block_on};

    /// Acme, its members Ann and Bob, and a key each of them made.
    struct Acme {
        actors: OrgActing,
        id: OrganizationId,
        ann: OrgUserId,
        anns_key: OrgApiKeyId,
        bobs_key: OrgApiKeyId,
    }

    fn acme_with(outsider: OrgUser) -> Acme {
        let id = OrganizationId::new();
        let ann = test_org_user(id, "ann@acme.com", OrgRole::Owner);
        let bob = test_org_user(id, "bob@acme.com", OrgRole::Owner);
        let anns_key = stored_org_api_key(id, *ann.id(), "ann", MintedThrough::Session);
        let bobs_key = stored_org_api_key(id, *bob.id(), "bob", MintedThrough::Session);
        Acme {
            id,
            ann: *ann.id(),
            anns_key: *anns_key.id(),
            bobs_key: *bobs_key.id(),
            actors: OrgActing::new(OrgActingPorts {
                organizations: org_store_with([org_shaped(id, OrgShape::owning(&[]))]),
                org_users: Arc::new(org_user_store_with([ann, bob, outsider])),
                org_sessions: Fake::fake(),
                org_api_keys: Arc::new(FakeOrgApiKeyStore::holding([anns_key, bobs_key])),
            }),
        }
    }

    fn acme() -> Acme {
        acme_with(test_org_user(
            OrganizationId::new(),
            "eve@other.com",
            OrgRole::Owner,
        ))
    }

    fn with_key(member: OrgUserId, key: OrgApiKeyId, organization: OrganizationId) -> OrgCaller {
        OrgCaller::new(member, OrgCredential::ApiKey(key), organization)
    }

    /// Ann acts on Acme with the key she made. She is the member acting.
    #[test]
    fn a_member_acts_through_their_own_key() {
        let acme = acme();

        let (_, actor) = block_on(
            acme.actors
                .actor(&with_key(acme.ann, acme.anns_key, acme.id)),
        )
        .unwrap();

        assert_eq!(actor.member().id(), &acme.ann);
    }

    /// Ann cannot act on the organization with Bob's key. Resolving that
    /// caller returns forbidden.
    #[test]
    fn a_member_is_refused_with_another_members_key() {
        let acme = acme();

        let result = block_on(
            acme.actors
                .actor(&with_key(acme.ann, acme.bobs_key, acme.id)),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An owner from another organization cannot act on Acme by naming
    /// Ann's key; the mismatched caller is forbidden.
    #[test]
    fn a_member_of_another_organization_is_refused() {
        let mallory = test_org_user(OrganizationId::new(), "mallory@other.com", OrgRole::Owner);
        let mallorys_id = *mallory.id();
        let acme = acme_with(mallory);

        let result = block_on(
            acme.actors
                .actor(&with_key(mallorys_id, acme.anns_key, acme.id)),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
