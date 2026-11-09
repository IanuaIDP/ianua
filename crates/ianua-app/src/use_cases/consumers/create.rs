//! Create consumer: register a new machine identity within a tenant. An API
//! key it signs in with is made here and shown once.

use std::sync::Arc;

use ianua_domain::domains::consumers::consumer::{Consumer, CreateConsumerParams};
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::domains::consumers::quota::ConsumerQuota;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ConsumerId, Expiry, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::consumers::{ConsumerKeyGenerator, ConsumerStore};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::services::consumers::NewCredential;
use crate::services::issuers::TenantIssuers;
use crate::services::limits::room::ensure_room_in_tenant;
use crate::use_case::Command;

/// Request to create a new consumer.
pub struct CreateRequest {
    /// Display name (e.g. `"payment-processor"`).
    pub name: Label,
    /// Optional description.
    pub description: Option<Label>,
    /// Initial authentication credential.
    pub credential: NewCredential,
    /// When the credential stops working.
    pub credential_expiry: Expiry,
    /// How many requests it may send.
    pub quota: ConsumerQuota,
    /// The most sensitive data it may receive.
    pub clearance: DataClassLevel,
}

/// Ports needed by the create consumer use case.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Port for saving consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// Port for checking plan limits.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// The tenant's own token issuer, which no consumer may trust.
    pub issuers: TenantIssuers,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Makes the API key a consumer signs in with, and its digest.
    pub key_generator: Arc<dyn ConsumerKeyGenerator>,
}

/// A consumer just created.
pub struct CreateResult {
    /// The consumer's id.
    pub consumer_id: ConsumerId,
    /// The API key it signs in with, shown this once and never kept;
    /// `None` when it signs in with a certificate or its own tokens.
    pub api_key: Option<Secret>,
}

/// Registers a tenant's machine identity and issues its initial credential.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// The consumer `request` describes, created by the caller, with the
    /// raw API key made for it, if any, which exists only here.
    async fn new_consumer(
        &self,
        ctx: &CallerContext,
        request: CreateRequest,
    ) -> Result<(Consumer<ResolvedTenant>, Option<Secret>), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let tenant_issuer = self.ports.issuers.of(&ctx.tenant_id()).await?;
        let issued = request
            .credential
            .issued(self.ports.key_generator.as_ref())
            .await?;
        let params = CreateConsumerParams {
            name: request.name,
            description: request.description,
            credential: issued.kind,
            credential_expiry: request.credential_expiry,
            quota: request.quota,
            clearance: request.clearance,
        };
        let consumer = Consumer::create(params, &tenant_issuer, &ConsumerControl::new(&authority))
            .map_err(AppError::from_domain)?;
        Ok((consumer, issued.api_key))
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<CreateResult, AppError>;

    /// Creates a consumer within the tenant and records
    /// `consumers.consumer_created`. An API key is made by the platform,
    /// kept as its digest only, and returned this once.
    ///
    /// The new consumer can authenticate with its credential as soon as it
    /// is saved, so the record is written first: access the audit trail
    /// cannot show is never handed out.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not create consumers,
    ///   clears it for more than they may see, the credential trusts the
    ///   tenant's own issuer, or the plan's consumer limit is reached.
    /// - `AppError::Domain` when the credential's expiry has already passed.
    /// - `AppError::NotFound` when the tenant is not on record.
    /// - `AppError::Internal` when no key can be made, or on persistence or
    ///   audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<CreateResult, AppError> {
        let (mut consumer, api_key) = self.new_consumer(ctx, request).await?;
        ensure_room_in_tenant(
            self.ports.limit_enforcer.as_ref(),
            ctx,
            ResourceKind::Consumers,
        )
        .await?;
        let tenant = ctx.tenant();

        self.ports
            .consumer_store
            .save(&tenant, &consumer)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(
                &consumer.created_by().clone(),
                consumer.take_events(&tenant),
            )
            .await
            .or_internal()?;

        Ok(CreateResult {
            consumer_id: *consumer.id(),
            api_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        ConsumersAction, DataAccessAction, SystemPermission,
    };
    use ianua_domain::domains::consumers::credential::ConsumerCredentialKind;
    use ianua_domain::domains::consumers::quota::{QuotaPeriod, RequestAllowance};
    use ianua_domain::shared::clock;
    use ianua_domain::types::{
        CertificateFingerprint, FederatedSubject, HttpsUrl, KeyPrefix, TokenHash,
    };

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{FakeConsumerStore, UnreachableConsumerKeys};
    use crate::test_support::{
        Fake, FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    const CREATE: SystemPermission = SystemPermission::Consumers(ConsumersAction::Create);

    fn use_case_over(store: Arc<FakeConsumerStore>) -> CreateUseCase {
        CreateUseCase::new(CreatePorts {
            consumer_store: store,
            ..CreatePorts::fakes()
        })
    }

    fn holding(store: Arc<FakeConsumerStore>, held: &[SystemPermission]) -> CreateUseCase {
        CreateUseCase::new(CreatePorts {
            consumer_store: store,
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
            ..CreatePorts::fakes()
        })
    }

    fn request() -> CreateRequest {
        CreateRequest {
            name: Label::new("name", "payment-processor").unwrap(),
            description: None,
            credential: NewCredential::ApiKey,
            credential_expiry: Expiry::Never,
            quota: ConsumerQuota::Unlimited,
            clearance: DataClassLevel::Internal,
        }
    }

    /// Ann creates "payment-processor" with an API key. The platform makes
    /// the key and hands it back this once; only its prefix and digest are
    /// kept, so the gateway can check it.
    #[test]
    fn an_api_key_is_made_kept_by_its_digest_and_shown_once() {
        let store = Arc::new(FakeConsumerStore::empty());

        let (result, _) = run(&use_case_over(store.clone()), request());

        let created = result.unwrap();
        let shown = created.api_key.unwrap();
        let saved = store.find_by_id_direct(&created.consumer_id).unwrap();
        assert_eq!(
            saved.credential(),
            &ConsumerCredentialKind::ApiKey {
                prefix: KeyPrefix::new("sk_live_minted1").unwrap(),
                key_hash: TokenHash::from_stored("minted-digest-1".to_owned()),
            }
        );
        assert_eq!(shown.expose(), "sk_live_minted1.minted-digest-1");
    }

    /// Ann creates "edge-device" with its client certificate. No key is
    /// made or shown.
    #[test]
    fn a_certificate_consumer_is_shown_no_key() {
        let store = Arc::new(FakeConsumerStore::empty());
        let fingerprint = CertificateFingerprint::from_digest([0xaa; 32]);
        let certificate = CreateRequest {
            credential: NewCredential::ClientCert { fingerprint },
            ..request()
        };

        let (result, _) = run(&use_case_over(store.clone()), certificate);

        let created = result.unwrap();
        assert!(created.api_key.is_none());
        let saved = store.find_by_id_direct(&created.consumer_id).unwrap();
        assert_eq!(
            saved.credential(),
            &ConsumerCredentialKind::ClientCert { fingerprint }
        );
    }

    /// Key-generation failure creates no consumer and records no creation event.
    #[test]
    fn a_key_that_cannot_be_made_creates_nothing() {
        let store = Arc::new(FakeConsumerStore::empty());
        let use_case = CreateUseCase::new(CreatePorts {
            consumer_store: store.clone(),
            key_generator: Arc::new(UnreachableConsumerKeys),
            ..CreatePorts::fakes()
        });

        let (result, audit) = run(&use_case, request());

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann creates "payment-processor" with a key for a month and 10 000
    /// requests a day, as the partner's contract says. Both are kept.
    #[test]
    fn a_consumer_keeps_its_expiry_and_quota() {
        let store = Arc::new(FakeConsumerStore::empty());
        let in_a_month = Expiry::At(clock::now() + time::Duration::days(30));
        let quota =
            ConsumerQuota::Limited(RequestAllowance::new(10_000, QuotaPeriod::Day).unwrap());
        let limited = CreateRequest {
            credential_expiry: in_a_month,
            quota,
            ..request()
        };

        let (result, _) = run(&use_case_over(store.clone()), limited);

        let saved = store
            .find_by_id_direct(&result.unwrap().consumer_id)
            .unwrap();
        assert_eq!(saved.credentials().current().expiry(), in_a_month);
        assert_eq!(saved.quota(), quota);
    }

    /// Ann sets up a key that expired yesterday. It is refused, since
    /// nothing could sign in with it, and nothing is kept or recorded.
    #[test]
    fn a_consumer_with_an_expired_key_is_refused() {
        let store = Arc::new(FakeConsumerStore::empty());
        let expired = CreateRequest {
            credential_expiry: Expiry::At(clock::now() - time::Duration::days(1)),
            ..request()
        };

        let (result, audit) = run(&use_case_over(store.clone()), expired);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    fn run(
        use_case: &CreateUseCase,
        request: CreateRequest,
    ) -> (Result<CreateResult, AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request));
        (result, audit)
    }

    /// Ann creates "payment-processor". It is kept, active, and the
    /// creation is on record.
    #[test]
    fn a_consumer_is_created_and_recorded() {
        let store = Arc::new(FakeConsumerStore::empty());

        let (result, audit) = run(&use_case_over(store.clone()), request());

        let saved = store
            .find_by_id_direct(&result.unwrap().consumer_id)
            .unwrap();
        assert_eq!(saved.name().as_str(), "payment-processor");
        assert!(saved.is_active());
        assert_eq!(
            audit.records.lock().unwrap()[0],
            "consumers.consumer_created"
        );
    }

    /// Sam may create consumers but not see confidential data. The new
    /// consumer is cleared for internal data, which everyone sees.
    #[test]
    fn the_create_right_is_enough_for_an_internal_consumer() {
        let store = Arc::new(FakeConsumerStore::empty());

        let (result, _) = run(&holding(store.clone(), &[CREATE]), request());

        assert!(result.is_ok());
        assert_eq!(store.count(), 1);
    }

    /// Creation with clearance above the creator's own is forbidden and saves no consumer.
    #[test]
    fn a_consumer_is_cleared_for_no_more_than_its_creator_sees() {
        let store = Arc::new(FakeConsumerStore::empty());
        let cleared = CreateRequest {
            clearance: DataClassLevel::Restricted,
            ..request()
        };

        let (result, _) = run(&holding(store.clone(), &[CREATE]), cleared);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// Fay may create consumers and see restricted data. She clears a new
    /// consumer for restricted data.
    #[test]
    fn someone_cleared_for_restricted_data_may_clear_a_consumer_for_it() {
        let store = Arc::new(FakeConsumerStore::empty());
        let held = [CREATE, SystemPermission::Data(DataAccessAction::Restricted)];
        let cleared = CreateRequest {
            clearance: DataClassLevel::Restricted,
            ..request()
        };

        let (result, _) = run(&holding(store.clone(), &held), cleared);

        let saved = store
            .find_by_id_direct(&result.unwrap().consumer_id)
            .unwrap();
        assert_eq!(saved.clearance(), DataClassLevel::Restricted);
    }

    /// A consumer cannot trust the tenant's own token issuer; the request
    /// is forbidden and no consumer is saved.
    #[test]
    fn a_consumer_trusting_the_tenants_own_issuer_is_refused() {
        let store = Arc::new(FakeConsumerStore::empty());
        let tenant_issuer = block_on(TenantIssuers::fake().of(&test_ctx().tenant_id())).unwrap();
        let trusting = CreateRequest {
            credential: NewCredential::JwtBearer {
                issuer: tenant_issuer,
                subject: FederatedSubject::new("ann").unwrap(),
                jwks_uri: HttpsUrl::new("https://keys.example.test/jwks").unwrap(),
            },
            ..request()
        };

        let (result, _) = run(&use_case_over(store.clone()), trusting);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// A viewer cannot create a consumer, leaving storage and the audit trail empty.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let store = Arc::new(FakeConsumerStore::empty());
        let viewer = [SystemPermission::Consumers(ConsumersAction::View)];

        let (result, audit) = run(&holding(store.clone(), &viewer), request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot create a consumer, and none is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeConsumerStore::empty());
        let use_case = CreateUseCase::new(CreatePorts {
            consumer_store: store.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..CreatePorts::fakes()
        });

        let (result, _) = run(&use_case, request());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 0);
    }

    /// Plan-limit rejection prevents consumer creation and its audit event.
    #[test]
    fn a_consumer_past_the_plan_limit_is_refused() {
        let store = Arc::new(FakeConsumerStore::empty());
        let use_case = CreateUseCase::new(CreatePorts {
            consumer_store: store.clone(),
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..CreatePorts::fakes()
        });

        let (result, audit) = run(&use_case, request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }
}
