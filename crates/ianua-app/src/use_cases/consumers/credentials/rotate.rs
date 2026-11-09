//! Rotate credential: replace a consumer's authentication credential. A new
//! API key is made here and shown once.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::ConsumersAction;
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::domains::consumers::credentials::CredentialRotation;
use ianua_domain::domains::consumers::takeover::ConsumerTakeover;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ConsumerId, Expiry, PrincipalRef, RotationOverlap};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, Holder};
use crate::ports::consumers::{ConsumerKeyGenerator, ConsumerStore};
use crate::services::consumers::NewCredential;
use crate::services::issuers::TenantIssuers;
use crate::use_case::Command;
use crate::use_cases::consumers::lookup::existing_consumer;

/// Which consumer gets which new credential.
pub struct RotateCredentialRequest {
    /// The consumer whose credential is replaced.
    pub consumer_id: ConsumerId,
    /// The credential it authenticates with from now on.
    pub credential: NewCredential,
    /// When the new credential stops working.
    pub expiry: Expiry,
    /// How long the old credential keeps working, so callers can move over.
    pub overlap: RotationOverlap,
}

/// A credential just rotated.
pub struct RotatedCredential {
    /// The new API key, shown this once and never kept; `None` when the
    /// new credential is a certificate or the consumer's own tokens.
    pub api_key: Option<Secret>,
}

/// Ports needed by the rotate credential use case.
#[derive(ianua_macros::Fakes)]
pub struct RotateCredentialPorts {
    /// Port for loading and saving consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// Who holds which roles in the tenant, the consumer among them.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's own token issuer, which no consumer may trust.
    pub issuers: TenantIssuers,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Makes a new API key and its digest.
    pub key_generator: Arc<dyn ConsumerKeyGenerator>,
}

/// Replaces a machine identity's credential with a bounded overlap.
pub struct RotateCredentialUseCase {
    ports: RotateCredentialPorts,
}

impl RotateCredentialUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: RotateCredentialPorts) -> Self {
        Self { ports }
    }

    /// The move to the credential `request` asks for, with the raw API key
    /// made for it, if any, which exists only here.
    async fn rotation(
        &self,
        request: RotateCredentialRequest,
    ) -> Result<(CredentialRotation, Option<Secret>), AppError> {
        let issued = request
            .credential
            .issued(self.ports.key_generator.as_ref())
            .await?;
        let rotation = CredentialRotation {
            credential: issued.kind,
            expiry: request.expiry,
            overlap: request.overlap,
        };
        Ok((rotation, issued.api_key))
    }

    /// Moves `consumer` to the credential `rotation` names, once the caller
    /// may take it over.
    async fn rotate(
        &self,
        ctx: &CallerContext,
        control: &ConsumerControl<'_>,
        consumer: &mut Consumer<ResolvedTenant>,
        rotation: CredentialRotation,
    ) -> Result<(), AppError> {
        let records = self
            .ports
            .access_records
            .load_held_by(
                &ctx.tenant(),
                Holder::of(PrincipalRef::Consumer(*consumer.id())),
            )
            .await
            .or_internal()?;
        let tenant_issuer = self.ports.issuers.of(&ctx.tenant_id()).await?;
        let takeover =
            ConsumerTakeover::of(control, &records.access(ctx.tenant_id()), consumer.id())
                .map_err(AppError::from_domain)?;
        consumer
            .rotate_credential(rotation, &tenant_issuer, &takeover)
            .map_err(AppError::from_domain)
    }
}

impl Command for RotateCredentialUseCase {
    type Caller = CallerContext;
    type Input = RotateCredentialRequest;
    type Output = Result<RotatedCredential, AppError>;

    /// Rotates the consumer's credential to a new one and records
    /// `consumers.credential_rotated`, with when the old one stops working.
    /// A new API key is made by the platform, kept as its digest only, and
    /// returned this once.
    ///
    /// Whoever sets the credential can sign in as the consumer, so the
    /// caller must hold everything the consumer holds. The old credential
    /// keeps working for the overlap asked, at most a week; a credential
    /// kept from an earlier rotation stops now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without consumer-update rights, regardless of existence.
    /// - `AppError::NotFound` for a missing consumer; `Forbidden` for insufficient held rights or trusting the tenant's own issuer.
    /// - `AppError::Domain` for an unchanged/expired credential or overlap longer than a week.
    /// - `AppError::Internal` on key generation, persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RotateCredentialRequest,
    ) -> Result<RotatedCredential, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = ConsumerControl::new(&authority);
        control
            .ensure_may(ConsumersAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut consumer = existing_consumer(
            self.ports.consumer_store.as_ref(),
            &tenant,
            &request.consumer_id,
        )
        .await?;
        let (rotation, api_key) = self.rotation(request).await?;
        self.rotate(ctx, &control, &mut consumer, rotation).await?;

        self.ports
            .consumer_store
            .save(&tenant, &consumer)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), consumer.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(RotatedCredential { api_key })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::consumers::credential::ConsumerCredentialKind;
    use ianua_domain::types::{CertificateFingerprint, KeyPrefix, Lifetime, TokenHash};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeAccessRecordStore;
    use crate::test_support::consumers::{
        FakeConsumerStore, UnreachableConsumerKeys, billing_sync, consumer_holding,
        consumers_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const UPDATE: SystemPermission = SystemPermission::Consumers(ConsumersAction::Update);

    const FINGERPRINT: [u8; 32] = [0xaa; 32];

    fn certificate() -> ConsumerCredentialKind {
        ConsumerCredentialKind::ClientCert {
            fingerprint: CertificateFingerprint::from_digest(FINGERPRINT),
        }
    }

    fn rotation_of(consumer_id: ConsumerId) -> RotateCredentialRequest {
        RotateCredentialRequest {
            consumer_id,
            credential: NewCredential::ClientCert {
                fingerprint: CertificateFingerprint::from_digest(FINGERPRINT),
            },
            expiry: Expiry::Never,
            overlap: RotationOverlap::Immediate,
        }
    }

    /// Ann rotates "billing-sync" to a new API key. The platform makes it
    /// and hands it back this once; the consumer keeps only its prefix and
    /// digest.
    #[test]
    fn a_new_api_key_is_made_and_shown_once() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let to_a_key = RotateCredentialRequest {
            credential: NewCredential::ApiKey,
            ..rotation_of(id)
        };

        let (result, _) = run(&use_case_over(store.clone()), to_a_key);

        let shown = result.unwrap().api_key.unwrap();
        assert_eq!(shown.expose(), "sk_live_minted1.minted-digest-1");
        assert_eq!(
            store.find_by_id_direct(&id).unwrap().credential(),
            &ConsumerCredentialKind::ApiKey {
                prefix: KeyPrefix::new("sk_live_minted1").unwrap(),
                key_hash: TokenHash::from_stored("minted-digest-1".to_owned()),
            }
        );
    }

    /// Failure to generate a replacement key leaves the stored credential
    /// unchanged and records no rotation.
    #[test]
    fn a_key_that_cannot_be_made_leaves_the_old_one() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let use_case = RotateCredentialUseCase::new(RotateCredentialPorts {
            consumer_store: store.clone(),
            key_generator: Arc::new(UnreachableConsumerKeys),
            ..RotateCredentialPorts::fakes()
        });
        let to_a_key = RotateCredentialRequest {
            credential: NewCredential::ApiKey,
            ..rotation_of(id)
        };

        let (result, audit) = run(&use_case, to_a_key);

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(
            store.find_by_id_direct(&id).unwrap().credential(),
            billing_sync().credential()
        );
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// The rotation of [`rotation_of`], keeping the old key for `days`.
    fn keeping_old_key(consumer_id: ConsumerId, days: i64) -> RotateCredentialRequest {
        let lifetime = Lifetime::new(time::Duration::days(days)).unwrap();
        RotateCredentialRequest {
            overlap: RotationOverlap::For(lifetime),
            ..rotation_of(consumer_id)
        }
    }

    /// Ann rotates "billing-sync" to a certificate, keeping its old key for
    /// a day while the partner deploys. Both work for that day.
    #[test]
    fn the_old_key_is_kept_for_the_overlap_asked() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);

        let (result, _) = run(&use_case_over(store.clone()), keeping_old_key(id, 1));

        result.unwrap();
        let saved = store.find_by_id_direct(&id).unwrap();
        assert_eq!(saved.credentials().live().count(), 2);
    }

    /// A month-long overlap is rejected without installing the replacement
    /// certificate or recording a rotation.
    #[test]
    fn an_overlap_longer_than_a_week_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);

        let (result, audit) = run(&use_case_over(store.clone()), keeping_old_key(id, 30));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_ne!(
            store.find_by_id_direct(&id).unwrap().credential(),
            &certificate()
        );
        assert!(audit.records.lock().unwrap().is_empty());
    }

    fn use_case_over(store: Arc<FakeConsumerStore>) -> RotateCredentialUseCase {
        RotateCredentialUseCase::new(RotateCredentialPorts {
            consumer_store: store,
            ..RotateCredentialPorts::fakes()
        })
    }

    fn run(
        use_case: &RotateCredentialUseCase,
        request: RotateCredentialRequest,
    ) -> (
        Result<RotatedCredential, AppError>,
        Arc<FakeEventDispatcher>,
    ) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request));
        (result, audit)
    }

    /// Ann replaces the API key of "billing-sync", which holds no role, with
    /// a client certificate. It signs in with the certificate from now on,
    /// and the rotation is on record.
    #[test]
    fn a_credential_is_rotated_and_recorded() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);

        let (result, audit) = run(&use_case_over(store.clone()), rotation_of(id));

        result.unwrap();
        let saved = store.find_by_id_direct(&id).unwrap();
        assert_eq!(saved.credential(), &certificate());
        assert_eq!(
            audit.records.lock().unwrap()[0],
            "consumers.credential_rotated"
        );
    }

    /// A caller lacking the consumer's user-management rights cannot install
    /// a replacement certificate, and no rotation is recorded.
    #[test]
    fn taking_over_a_consumer_holding_more_than_the_caller_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let records = consumer_holding(&id, &[SystemPermission::ManageUsers]);
        let use_case = RotateCredentialUseCase::new(RotateCredentialPorts {
            consumer_store: store.clone(),
            access_records: Arc::new(FakeAccessRecordStore::holding(
                test_ctx().tenant_id(),
                records,
            )),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[UPDATE])),
            ..RotateCredentialPorts::fakes()
        });

        let (result, audit) = run(&use_case, rotation_of(id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_ne!(
            store.find_by_id_direct(&id).unwrap().credential(),
            &certificate()
        );
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Consumer-view rights do not authorize credential rotation.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let use_case = RotateCredentialUseCase::new(RotateCredentialPorts {
            consumer_store: consumers_of_test_tenant(consumer),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Consumers(ConsumersAction::View),
            ])),
            ..RotateCredentialPorts::fakes()
        });

        let (result, _) = run(&use_case, rotation_of(id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot rotate a consumer credential.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let use_case = RotateCredentialUseCase::new(RotateCredentialPorts {
            consumer_store: consumers_of_test_tenant(consumer),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..RotateCredentialPorts::fakes()
        });

        let (result, _) = run(&use_case, rotation_of(id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A consumer the tenant does not have is not found, and nothing is
    /// recorded.
    #[test]
    fn rotating_an_unknown_consumer_is_not_found() {
        let (result, audit) = run(
            &use_case_over(Arc::new(FakeConsumerStore::empty())),
            rotation_of(ConsumerId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Missing update rights return forbidden even when rotation names an unknown consumer.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_consumer() {
        let use_case = RotateCredentialUseCase::new(RotateCredentialPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..RotateCredentialPorts::fakes()
        });

        let (result, _) = run(&use_case, rotation_of(ConsumerId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
