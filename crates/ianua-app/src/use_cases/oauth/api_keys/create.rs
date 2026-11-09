//! Creating an API key for a machine. The raw key is shown once.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::api_key::{ApiKey, NewApiKey};
use ianua_domain::domains::oauth::control::OAuthControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ApiKeyId, Expiry, Label, Scope, TenantSlug};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::{CallerContext, Credential};
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::oauth::ApiKeyStore;
use crate::ports::shared::{ApiKeyGenerator, KeyFamily};
use crate::use_case::Command;
use crate::use_cases::oauth::lookup::existing_api_key;

/// The key to create.
pub struct CreateRequest {
    /// The name shown in the API keys list.
    pub name: Label,
    /// The permissions the key may be spent on.
    pub scopes: Vec<Scope>,
    /// When the key stops working, or that it never does.
    pub expires_at: Expiry,
    /// The tenant's slug, written into the key so secret scanners can tell
    /// whose it is.
    pub tenant_slug: TenantSlug,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Where keys are kept.
    pub key_store: Arc<dyn ApiKeyStore>,
    /// Makes the raw key and its hash.
    pub key_generator: Arc<dyn ApiKeyGenerator>,
    /// Whether the tenant's plan has room for another key.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// A key just created, with its raw value.
pub struct CreateResult {
    /// The key's id.
    pub key_id: ApiKeyId,
    /// The raw key, shown once and never stored.
    pub raw_key: Secret,
}

/// Creates an API key that carries no more than its maker holds.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// The latest a key `caller` makes may end: the end of the key they
    /// came with, when they came with one.
    async fn ends_by(&self, caller: &CallerContext) -> Result<Expiry, AppError> {
        let Credential::TenantApiKey(parent) = caller.credential() else {
            return Ok(Expiry::Never);
        };
        let store = self.ports.key_store.as_ref();
        let parent = existing_api_key(store, &caller.tenant(), parent).await?;
        Ok(parent.expires_at())
    }

    /// The key `req` describes, ending by `ends_by`, made by the person
    /// `control` names, with its raw value, which exists only here.
    async fn new_key(
        &self,
        req: CreateRequest,
        ends_by: Expiry,
        control: &OAuthControl<'_>,
    ) -> Result<(ApiKey<ResolvedTenant>, Secret), AppError> {
        let generated = self
            .ports
            .key_generator
            .generate(KeyFamily::Tenant, &req.tenant_slug)
            .await
            .or_internal()?;
        let key = ApiKey::create(
            NewApiKey {
                id: ApiKeyId::new(),
                name: req.name,
                key_prefix: generated.key_prefix,
                key_hash: generated.key_hash,
                scopes: req.scopes,
                expires_at: req.expires_at,
                ends_by,
            },
            control,
        )
        .map_err(AppError::from_domain)?;
        Ok((key, generated.raw_key))
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<CreateResult, AppError>;

    /// Creates the key `req` describes for `caller` and returns its raw
    /// value. Records `ApiKeyCreated`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not create keys, a scope
    ///   reaches a permission they do not hold, the plan has no room for
    ///   another key, or the key would outlive the key the caller came with.
    /// - `AppError::Domain` when no scope is given, a scope names no
    ///   permission, or the expiry is not ahead of now.
    /// - `AppError::Internal` when the key cannot be made, saved or audited.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: CreateRequest,
    ) -> Result<CreateResult, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(
                caller.plan_limits(),
                &caller.tenant(),
                ResourceKind::ApiKeys,
            )
            .await
            .map_err(AppError::from_domain)?;
        let ends_by = self.ends_by(caller).await?;
        let (mut key, raw_key) = self
            .new_key(req, ends_by, &OAuthControl::new(&authority))
            .await?;
        let tenant = caller.tenant();
        self.ports
            .key_store
            .insert(&tenant, &key)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), key.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(CreateResult {
            key_id: *key.id(),
            raw_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{ApiKeyAction, SystemPermission};
    use ianua_domain::shared::clock;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::ActorRef;
    use time::Duration;

    use super::*;
    use crate::context::CallerIdentity;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeApiKeyStore, api_key_row};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    fn ci_key() -> CreateRequest {
        CreateRequest {
            name: Label::new("name", "CI Pipeline").unwrap(),
            scopes: vec![Scope::new("idp:routing:view").unwrap()],
            expires_at: Expiry::Never,
            tenant_slug: TenantSlug::new("acme", &DomainLimits::default().slug).unwrap(),
        }
    }

    fn create(ports: CreatePorts) -> Result<CreateResult, AppError> {
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(CreateUseCase::new(ports).execute(&test_ctx(), &auditor, ci_key()))
    }

    /// `request`, made by `caller` into `store`.
    fn make(
        store: &Arc<FakeApiKeyStore>,
        caller: &CallerContext,
        request: CreateRequest,
    ) -> Result<CreateResult, AppError> {
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let use_case = CreateUseCase::new(CreatePorts {
            key_store: store.clone(),
            ..CreatePorts::fakes()
        });
        block_on(use_case.execute(caller, &auditor, request))
    }

    /// The test caller, come with the key `key`.
    fn through_key(key: ApiKeyId) -> CallerContext {
        let tenant = test_ctx();
        CallerContext::new(
            *tenant.identity(),
            Credential::TenantApiKey(key),
            tenant.organization_id(),
            tenant.tenant_id(),
            tenant.plan_limits().clone(),
        )
        .unwrap()
    }

    fn refused_by(authorities: FakeTenantAuthorities) -> Result<CreateResult, AppError> {
        create(CreatePorts {
            tenant_authorities: Arc::new(authorities),
            ..CreatePorts::fakes()
        })
    }

    /// Ann creates a key for the CI pipeline. She gets the raw key once, the
    /// key is kept and its creation is recorded.
    #[test]
    fn a_key_is_created_kept_and_recorded() {
        let store = Arc::new(FakeApiKeyStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = CreateUseCase::new(CreatePorts {
            key_store: store.clone(),
            ..CreatePorts::fakes()
        });

        let created =
            block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), ci_key()))
                .unwrap();

        assert!(created.raw_key.expose().starts_with("ik_live_acme_"));
        assert_eq!(store.count(), 1);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["oauth.api_key_created"]
        );
    }

    /// Ann creates a key. It is kept under her name as its maker, and works
    /// from now on.
    #[test]
    fn the_key_names_its_maker() {
        let store = Arc::new(FakeApiKeyStore::empty());
        let created = create(CreatePorts {
            key_store: store.clone(),
            ..CreatePorts::fakes()
        })
        .unwrap();

        let saved = block_on(store.find_by_id(&test_ctx().tenant(), &created.key_id))
            .unwrap()
            .unwrap();
        assert!(matches!(
            (saved.created_by(), test_ctx().identity()),
            (ActorRef::User(maker), CallerIdentity::TenantUser(caller)) if maker == caller
        ));
        assert!(saved.is_active(clock::now()));
    }

    /// Tess makes the contractor a key for three weeks. It is kept with that
    /// end, and works until it.
    #[test]
    fn an_end_is_kept_with_the_key() {
        let store = Arc::new(FakeApiKeyStore::empty());
        let end = clock::now() + Duration::weeks(3);
        let request = CreateRequest {
            expires_at: Expiry::At(end),
            ..ci_key()
        };

        let created = make(&store, &test_ctx(), request).unwrap();

        let saved = block_on(store.find_by_id(&test_ctx().tenant(), &created.key_id))
            .unwrap()
            .unwrap();
        assert_eq!(saved.expires_at(), Expiry::At(end));
        assert!(saved.is_active(end - Duration::seconds(1)));
        assert!(!saved.is_active(end));
    }

    /// Tess mistypes the year and the end is behind her. The key is refused
    /// and nothing is kept.
    #[test]
    fn an_end_in_the_past_is_refused() {
        let store = Arc::new(FakeApiKeyStore::empty());
        let request = CreateRequest {
            expires_at: Expiry::At(clock::now() - Duration::minutes(1)),
            ..ci_key()
        };

        let refused = make(&store, &test_ctx(), request);

        assert!(matches!(refused, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// The contractor's key may make keys and ends tomorrow. A key it asks
    /// to last for ever, or one second past tomorrow, is refused; one ending
    /// with it is made.
    #[test]
    fn a_key_made_through_a_key_may_not_outlive_it() {
        let tomorrow = clock::now() + Duration::days(1);
        let mut row = api_key_row("contractor", test_ctx().actor());
        row.expires_at = Expiry::At(tomorrow);
        let parent = ApiKey::reconstitute(row).unwrap();
        let caller = through_key(*parent.id());
        let store = Arc::new(FakeApiKeyStore::holding(&test_ctx().tenant(), parent));
        let ending = |expires_at| CreateRequest {
            expires_at,
            ..ci_key()
        };

        let for_ever = make(&store, &caller, ending(Expiry::Never));
        let later = make(
            &store,
            &caller,
            ending(Expiry::At(tomorrow + Duration::seconds(1))),
        );
        let with_it = make(&store, &caller, ending(Expiry::At(tomorrow)));

        assert!(matches!(for_ever, Err(AppError::Forbidden(_))));
        assert!(matches!(later, Err(AppError::Forbidden(_))));
        assert!(with_it.is_ok());
        assert_eq!(store.count(), 2);
    }

    /// A rejected API-key limit refuses creation and stores no key.
    #[test]
    fn a_full_plan_refuses_the_key() {
        let store = Arc::new(FakeApiKeyStore::empty());

        let result = create(CreatePorts {
            key_store: store.clone(),
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..CreatePorts::fakes()
        });

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// A signed-out caller receives unauthenticated when creating an API key.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = refused_by(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A caller with no permissions is forbidden from creating an API key.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let result = refused_by(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// API-key create permission alone cannot grant a key route-view access
    /// that its maker lacks.
    #[test]
    fn a_scope_beyond_the_maker_is_refused() {
        let result = refused_by(FakeTenantAuthorities::holding(&[
            SystemPermission::ApiKeys(ApiKeyAction::Create),
        ]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
