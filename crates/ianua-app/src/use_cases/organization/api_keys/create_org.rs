//! Minting an API key that acts for the organization. The raw key is shown
//! once.

use std::sync::Arc;

use ianua_domain::domains::organization::access::api_key::{CreateOrgApiKeyParams, OrgApiKey};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Expiry, KeyPrefix, Label, OrgApiKeyId, Scope};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgApiKeyStore;
use crate::ports::shared::{ApiKeyGenerator, KeyFamily};
use crate::use_case::Command;

/// The key to mint.
pub struct CreateOrgRequest {
    /// The name shown in the keys list, such as "CI/CD Pipeline".
    pub name: Label,
    /// What the key may do, as `org:<domain>:<action>` scopes.
    pub scopes: Vec<Scope>,
    /// When the key stops working, or that it never does.
    pub expires_at: Expiry,
}

/// A key just minted, with its raw value. It holds the raw key, so it has no
/// `Debug`.
pub struct CreatedOrg {
    /// The key's id.
    pub id: OrgApiKeyId,
    /// The raw key, shown once and never stored.
    pub raw_key: Secret,
    /// The scannable prefix the key is listed by.
    pub key_prefix: KeyPrefix,
}

/// The ports [`CreateOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreateOrgPorts {
    /// Where the organization's keys are kept.
    pub key_store: Arc<dyn OrgApiKeyStore>,
    /// Makes the raw key and its hash.
    pub key_generator: Arc<dyn ApiKeyGenerator>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Mints an organization API key that carries no more than its maker holds.
pub struct CreateOrgUseCase {
    ports: CreateOrgPorts,
}

impl CreateOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreateOrgPorts) -> Self {
        Self { ports }
    }

    /// The key `req` describes, minted by the member `control` names, with
    /// its raw value, which exists only here.
    async fn minted(
        &self,
        organization: &Organization,
        req: CreateOrgRequest,
        control: &OrgControl<'_>,
    ) -> Result<(OrgApiKey, Secret), AppError> {
        let generated = self
            .ports
            .key_generator
            .generate(KeyFamily::Organization, organization.slug())
            .await
            .or_internal()?;
        let params = CreateOrgApiKeyParams {
            id: OrgApiKeyId::new(),
            organization_id: *organization.id(),
            name: req.name,
            key_prefix: generated.key_prefix,
            key_hash: generated.key_hash,
            scopes: req.scopes,
            expires_at: req.expires_at,
        };
        let key = OrgApiKey::create(params, control).map_err(AppError::from_domain)?;
        Ok((key, generated.raw_key))
    }
}

impl Command for CreateOrgUseCase {
    type Caller = OrgCaller;
    type Input = CreateOrgRequest;
    type Output = Result<CreatedOrg, AppError>;

    /// Mints the key `req` describes for `caller` and returns its raw value.
    /// Records `organization.org_api_key_created`.
    ///
    /// A key minted through another key carries no more than that key's
    /// scopes and ends no later than it, and is revoked with it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not mint keys, a scope
    ///   reaches beyond what they carry, or a key minted through a key would
    ///   outlive it.
    /// - `AppError::Domain` when no scope is given, a scope names no org
    ///   permission, or the expiry has passed.
    /// - `AppError::Internal` when the key cannot be made, saved or audited.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        req: CreateOrgRequest,
    ) -> Result<CreatedOrg, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let (mut key, raw_key) = self.minted(&organization, req, &control).await?;
        self.ports.key_store.save(&key).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*key.created_by()), key.take_events())
            .await
            .or_internal()?;
        Ok(CreatedOrg {
            id: *key.id(),
            raw_key,
            key_prefix: key.key_prefix().clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::access::api_key::MintedThrough;
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::FakeOrgApiKeyStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Fixture {
        keys: Arc<FakeOrgApiKeyStore>,
        audit: Arc<FakeEventDispatcher>,
        uc: CreateOrgUseCase,
    }

    impl Fixture {
        fn acting_as(actors: FakeOrgActors) -> Self {
            let keys = Arc::new(FakeOrgApiKeyStore::empty());
            Self {
                uc: CreateOrgUseCase::new(CreateOrgPorts {
                    key_store: keys.clone(),
                    org_actors: Arc::new(actors),
                    ..CreateOrgPorts::fakes()
                }),
                keys,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn mint(&self, scopes: &[&str]) -> Result<CreatedOrg, AppError> {
            let req = CreateOrgRequest {
                name: Label::new("api_key_name", "deploy").unwrap(),
                scopes: scopes.iter().map(|s| Scope::new(*s).unwrap()).collect(),
                expires_at: Expiry::Never,
            };
            block_on(
                self.uc
                    .execute(&test_org_caller(), &test_auditor(self.audit.clone()), req),
            )
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Olivia, an owner, mints a key that may view tenants. It is saved as
    /// hers, minted through her session, and the minting is recorded.
    #[test]
    fn an_owner_mints_a_key_that_is_hers() {
        let fixture = Fixture::acting_as(FakeOrgActors::in_role(OrgRole::Owner));

        let created = fixture.mint(&["org:tenants:view"]).unwrap();

        let key = fixture.keys.stored(&created.id).unwrap();
        assert_eq!(key.created_by(), test_org_caller().member());
        assert_eq!(key.minted_through(), MintedThrough::Session);
        assert!(created.raw_key.expose().starts_with("oak_acme_"));
        assert_eq!(fixture.recorded(), vec!["organization.org_api_key_created"]);
    }

    /// Olivia's deploy key may mint keys and view tenants. A key it mints
    /// records that it was minted through it, so revoking the deploy key
    /// revokes this one too.
    #[test]
    fn a_key_minted_through_a_key_records_its_parent() {
        let scopes = ["org:api_keys:create", "org:tenants:view"]
            .iter()
            .map(|s| Scope::new(*s).unwrap())
            .collect();
        let fixture = Fixture::acting_as(FakeOrgActors::through_key(OrgRole::Owner, scopes));

        let created = fixture.mint(&["org:tenants:view"]).unwrap();

        let key = fixture.keys.stored(&created.id).unwrap();
        assert!(matches!(key.minted_through(), MintedThrough::Key(_)));
    }

    /// A key limited to minting cannot grant organization-update rights;
    /// the broader child key is refused and none is saved.
    #[test]
    fn a_key_cannot_mint_beyond_its_own_scopes() {
        let scopes = vec![Scope::new("org:api_keys:create").unwrap()];
        let fixture = Fixture::acting_as(FakeOrgActors::through_key(OrgRole::Owner, scopes));

        let result = fixture.mint(&["org:organization:update"]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.keys.count(), 0);
    }

    /// A plain member cannot mint an organization key, and the refusal
    /// produces no creation record.
    #[test]
    fn a_plain_member_is_refused() {
        let fixture = Fixture::acting_as(FakeOrgActors::in_role(OrgRole::Member));

        let result = fixture.mint(&["org:tenants:view"]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A scope naming no organization permission is refused even for an owner.
    #[test]
    fn an_unknown_scope_is_refused() {
        let fixture = Fixture::acting_as(FakeOrgActors::in_role(OrgRole::Owner));

        let result = fixture.mint(&["org:nothing:here"]);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// A signed-out caller must authenticate before minting a key.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::acting_as(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = fixture.mint(&["org:tenants:view"]);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents minting and leaves the key
    /// store empty.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let fixture = Fixture::acting_as(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = fixture.mint(&["org:tenants:view"]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.keys.count(), 0);
    }
}
