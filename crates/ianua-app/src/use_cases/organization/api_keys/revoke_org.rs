//! Revoking an organization API key for good, with every key minted through
//! it.
//!
//! A key may mint keys that carry no more than it does. Were they to stay
//! when it is revoked, whoever leaked the key would have minted a child
//! first and kept working with it. So revoking a key revokes the keys
//! minted through it, all the way down.

use std::sync::Arc;

use ianua_domain::domains::organization::access::api_key::OrgApiKey;
use ianua_domain::shared::events::raised::RaisesComplete;
use ianua_domain::types::{OrgApiKeyId, OrganizationId};

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgApiKeyStore, OrganizationStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_api_key;
use crate::use_cases::organization::steward::{OrganizationSteward, StewardSources, Stewarding};

/// Which key to revoke.
pub struct RevokeOrgRequest {
    /// The organization the key belongs to.
    pub organization_id: OrganizationId,
    /// The key to revoke.
    pub key_id: OrgApiKeyId,
}

/// The ports [`RevokeOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeOrgPorts {
    /// Where the organization's keys are kept.
    pub key_store: Arc<dyn OrgApiKeyStore>,
    /// Organizations, for the one an operator names.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Revokes an organization API key and the keys minted through it. It
/// cannot be undone.
pub struct RevokeOrgUseCase {
    ports: RevokeOrgPorts,
}

impl RevokeOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeOrgPorts) -> Self {
        Self { ports }
    }

    /// The keys still active that were minted through `root`, at any depth,
    /// each revoked as `steward` decides.
    async fn revoked_descendants(
        &self,
        steward: &Stewarding,
        root: &OrgApiKeyId,
    ) -> Result<Vec<OrgApiKey>, AppError> {
        let minted = self
            .ports
            .key_store
            .list_minted_through(steward.organization().id(), root)
            .await
            .or_internal()?;
        let mut revoked = Vec::new();
        for mut key in minted.into_iter().filter(|key| !key.is_revoked()) {
            steward.decide(|by| key.revoke(by))?;
            revoked.push(key);
        }
        Ok(revoked)
    }
}

impl Command for RevokeOrgUseCase {
    type Caller = OrganizationSteward;
    type Input = RevokeOrgRequest;
    type Output = Result<(), AppError>;

    /// Revokes the key `request` names and every active key minted through
    /// it, drops every cached credential lookup, and records
    /// `organization.org_api_key_revoked` for each.
    ///
    /// The key's creator, a member who may revoke keys, or the platform
    /// revokes it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not revoke the key, or the
    ///   operator is disabled.
    /// - `AppError::NotFound` when the organization has no such key, or a
    ///   member names another organization.
    /// - `AppError::Domain` when the key was already revoked.
    /// - `AppError::Internal` when a store, the cache or the audit fails.
    async fn execute(
        &self,
        caller: &OrganizationSteward,
        auditor: &RequestAuditor,
        request: RevokeOrgRequest,
    ) -> Result<(), AppError> {
        let sources = StewardSources {
            org_actors: self.ports.org_actors.as_ref(),
            operators: self.ports.operator_authorities.as_ref(),
            organizations: self.ports.organizations.as_ref(),
        };
        let steward = Stewarding::resolve(sources, caller, &request.organization_id).await?;
        let store = self.ports.key_store.as_ref();
        let mut key = existing_api_key(store, steward.organization().id(), &request.key_id).await?;
        steward.decide(|by| key.revoke(by))?;
        let mut revoked = self.revoked_descendants(&steward, key.id()).await?;
        revoked.insert(0, key);
        for key in &revoked {
            store.save(key).await.or_internal()?;
        }
        let events = revoked
            .iter_mut()
            .flat_map(RaisesComplete::take_events)
            .collect();
        auditor
            .dispatch_by(&steward.audit_actor(), events)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::access::api_key::MintedThrough;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{OperatorId, OrgUserId};

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, FakeOrgActors, Refusal};
    use crate::test_support::notifications::operator_caller;
    use crate::test_support::organization::{
        FakeOrgApiKeyStore, org_store_with, stored_org_api_key, test_org,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Fixture {
        keys: Arc<FakeOrgApiKeyStore>,
        audit: Arc<FakeEventDispatcher>,
        uc: RevokeOrgUseCase,
    }

    impl Fixture {
        fn with(keys: Vec<OrgApiKey>, ports: RevokeOrgPorts) -> Self {
            let keys = Arc::new(FakeOrgApiKeyStore::holding(keys));
            Self {
                uc: RevokeOrgUseCase::new(RevokeOrgPorts {
                    key_store: keys.clone(),
                    ..ports
                }),
                keys,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn acting_as(keys: Vec<OrgApiKey>, actors: FakeOrgActors) -> Self {
            Self::with(
                keys,
                RevokeOrgPorts {
                    org_actors: Arc::new(actors),
                    ..RevokeOrgPorts::fakes()
                },
            )
        }

        fn revoke_as(
            &self,
            caller: &OrganizationSteward,
            key_id: OrgApiKeyId,
        ) -> Result<(), AppError> {
            let request = RevokeOrgRequest {
                organization_id: acme(),
                key_id,
            };
            block_on(
                self.uc
                    .execute(caller, &test_auditor(self.audit.clone()), request),
            )
        }

        fn revoke(&self, key_id: OrgApiKeyId) -> Result<(), AppError> {
            self.revoke_as(&OrganizationSteward::Member(test_org_caller()), key_id)
        }

        fn is_revoked(&self, id: &OrgApiKeyId) -> bool {
            self.keys.stored(id).unwrap().is_revoked()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn acme() -> OrganizationId {
        test_org_caller().organization_id()
    }

    fn olivias_key(name: &str, minted_through: MintedThrough) -> OrgApiKey {
        stored_org_api_key(acme(), *test_org_caller().member(), name, minted_through)
    }

    /// Olivia revokes her deploy key. It stops being active, and the
    /// revocation is recorded: the event the token cache drops the key's
    /// cached caller by.
    #[test]
    fn revoking_a_key_stops_it_being_active() {
        let key = olivias_key("deploy", MintedThrough::Session);
        let id = *key.id();
        let fixture = Fixture::acting_as(vec![key], FakeOrgActors::in_role(OrgRole::Owner));

        fixture.revoke(id).unwrap();

        assert!(fixture.is_revoked(&id));
        assert_eq!(fixture.recorded(), vec!["organization.org_api_key_revoked"]);
    }

    /// Olivia's deploy key minted a CI key, which minted a nightly key. She
    /// revokes the deploy key, and the CI and nightly keys go with it, each
    /// recorded. Her other key stays.
    #[test]
    fn revoking_a_key_revokes_every_key_minted_through_it() {
        let deploy = olivias_key("deploy", MintedThrough::Session);
        let ci = olivias_key("ci", MintedThrough::Key(*deploy.id()));
        let nightly = olivias_key("nightly", MintedThrough::Key(*ci.id()));
        let other = olivias_key("other", MintedThrough::Session);
        let ids = [*deploy.id(), *ci.id(), *nightly.id(), *other.id()];
        let fixture = Fixture::acting_as(
            vec![deploy, ci, nightly, other],
            FakeOrgActors::in_role(OrgRole::Owner),
        );

        fixture.revoke(ids[0]).unwrap();

        assert!(fixture.is_revoked(&ids[0]));
        assert!(fixture.is_revoked(&ids[1]));
        assert!(fixture.is_revoked(&ids[2]));
        assert!(!fixture.is_revoked(&ids[3]));
        assert_eq!(fixture.recorded().len(), 3);
    }

    /// The platform revokes a key of Acme's on an operator's order, as when
    /// its creator leaves. It is revoked.
    #[test]
    fn an_operator_revokes_a_key_for_the_platform() {
        let key = olivias_key("deploy", MintedThrough::Session);
        let id = *key.id();
        let fixture = Fixture::with(
            vec![key],
            RevokeOrgPorts {
                organizations: org_store_with([test_org(acme(), "acme")]),
                ..RevokeOrgPorts::fakes()
            },
        );

        fixture
            .revoke_as(
                &OrganizationSteward::Platform(operator_caller(OperatorId::new())),
                id,
            )
            .unwrap();

        assert!(fixture.is_revoked(&id));
    }

    /// Key ids are not secret: they show in listings and audit records. A
    /// key of another organization reads as absent, so one organization
    /// never revokes another's.
    #[test]
    fn a_key_from_another_organization_cannot_be_revoked() {
        let foreign = stored_org_api_key(
            OrganizationId::new(),
            OrgUserId::new(),
            "deploy",
            MintedThrough::Session,
        );
        let id = *foreign.id();
        let fixture = Fixture::acting_as(vec![foreign], FakeOrgActors::in_role(OrgRole::Owner));

        let result = fixture.revoke(id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!fixture.is_revoked(&id));
    }

    /// A plain member cannot revoke another member's key; it stays active
    /// and no revocation is recorded.
    #[test]
    fn a_plain_member_cannot_revoke_anothers_key() {
        let key = stored_org_api_key(acme(), OrgUserId::new(), "deploy", MintedThrough::Session);
        let id = *key.id();
        let fixture = Fixture::acting_as(vec![key], FakeOrgActors::in_role(OrgRole::Member));

        let result = fixture.revoke(id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!fixture.is_revoked(&id));
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out caller cannot revoke a key, which stays active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let key = olivias_key("deploy", MintedThrough::Session);
        let id = *key.id();
        let fixture = Fixture::acting_as(vec![key], FakeOrgActors::refusing(Refusal::SignedOut));

        let result = fixture.revoke(id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(!fixture.is_revoked(&id));
    }

    /// Refused organization authority prevents revoking a key.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let key = olivias_key("deploy", MintedThrough::Session);
        let id = *key.id();
        let fixture = Fixture::acting_as(vec![key], FakeOrgActors::refusing(Refusal::Forbidden));

        let result = fixture.revoke(id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Refused operator authority leaves Acme's key active.
    #[test]
    fn a_refused_operator_cannot_revoke() {
        let key = olivias_key("deploy", MintedThrough::Session);
        let id = *key.id();
        let fixture = Fixture::with(
            vec![key],
            RevokeOrgPorts {
                operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(
                    Refusal::Forbidden,
                )),
                organizations: org_store_with([test_org(acme(), "acme")]),
                ..RevokeOrgPorts::fakes()
            },
        );

        let result = fixture.revoke_as(
            &OrganizationSteward::Platform(operator_caller(OperatorId::new())),
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!fixture.is_revoked(&id));
    }
}
