//! Create operator API key: an operator makes an `opk_` key of their own
//! for their CLI and scripts.

use std::sync::Arc;

use ianua_domain::domains::operator::api_key::{NewOperatorApiKey, OperatorApiKey};
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Expiry, KeyPrefix, TenantSlug};

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::operator::{OperatorKeyStore, OperatorStore};
use crate::ports::shared::{ApiKeyGenerator, KeyFamily};
use crate::use_case::Command;
use crate::use_cases::operator::lookup::existing_operator;

/// The slug every operator key carries after its `opk_` start.
const OPERATOR_KEY_SLUG: &str = "platform";

/// The ports [`CreateOperatorUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreateOperatorPorts {
    /// Platform operators, for the key holder's audit label.
    pub operator_store: Arc<dyn OperatorStore>,
    /// Operator keys.
    pub key_store: Arc<dyn OperatorKeyStore>,
    /// Makes the raw key and its hash.
    pub key_generator: Arc<dyn ApiKeyGenerator>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// A key just made, shown to its holder once.
pub struct OperatorKeyCreated {
    /// The whole key. Shown once, never stored.
    pub raw_key: Secret,
    /// The visible start the key is found by, such as `opk_platform_01HXK`.
    pub key_prefix: KeyPrefix,
}

/// Makes an API key for the operator who asks for it.
pub struct CreateOperatorUseCase {
    ports: CreateOperatorPorts,
}

impl CreateOperatorUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: CreateOperatorPorts) -> Self {
        Self { ports }
    }
}

impl Command for CreateOperatorUseCase {
    type Caller = OperatorCaller;
    type Input = Expiry;
    type Output = Result<OperatorKeyCreated, AppError>;

    /// Makes a key of the calling operator's own that works until
    /// `expires_at`, stores its hash and records
    /// `operator.operator_api_key_created`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's operator or key no
    ///   longer exists.
    /// - `AppError::Forbidden` when the caller's key no longer works, their
    ///   account is disabled, or they act through a key that ends before
    ///   the new one would.
    /// - `AppError::Domain` when `expires_at` has already passed.
    /// - `AppError::Internal` on key generation, persistence or audit
    ///   failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        expires_at: Expiry,
    ) -> Result<OperatorKeyCreated, AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let holder =
            existing_operator(self.ports.operator_store.as_ref(), authority.operator()).await?;
        let (raw_key, new) = fresh_key(self.ports.key_generator.as_ref(), expires_at).await?;
        let mut key =
            OperatorApiKey::create(new, &authority, &holder).map_err(AppError::from_domain)?;
        self.ports.key_store.save(&key).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), key.take_events())
            .await
            .or_internal()?;
        Ok(OperatorKeyCreated {
            raw_key,
            key_prefix: key.key_prefix().clone(),
        })
    }
}

/// A fresh `opk_` key ending at `expires_at`: the whole key, shown once,
/// and what is kept of it.
///
/// # Errors
///
/// `AppError::Internal` when the key cannot be generated.
pub(super) async fn fresh_key(
    generator: &dyn ApiKeyGenerator,
    expires_at: Expiry,
) -> Result<(Secret, NewOperatorApiKey), AppError> {
    let slug = TenantSlug::new(OPERATOR_KEY_SLUG, &SlugLimits::default())
        .map_err(|error| AppError::from_domain(error.into()))?;
    let generated = generator
        .generate(KeyFamily::Operator, &slug)
        .await
        .or_internal()?;
    let new = NewOperatorApiKey {
        key_prefix: generated.key_prefix,
        key_hash: generated.key_hash,
        expires_at,
    };
    Ok((generated.raw_key, new))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::operator::status::OperatorStatus;
    use ianua_domain::shared::clock;
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::oauth::FakeApiKeyGenerator;
    use crate::test_support::operator::{
        FakeOperatorKeyStore, FakeOperatorStore, stored_operator, test_operator_caller,
        test_operator_id,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Setup {
        uc: CreateOperatorUseCase,
        keys: Arc<FakeOperatorKeyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(authorities: FakeOperatorAuthorities) -> Self {
            let keys = Arc::new(FakeOperatorKeyStore::empty());
            let bob = stored_operator(test_operator_id(), "bob@ianua.dev", OperatorStatus::Active);
            Self {
                uc: CreateOperatorUseCase::new(CreateOperatorPorts {
                    operator_store: Arc::new(FakeOperatorStore::holding([bob])),
                    key_store: keys.clone(),
                    key_generator: Arc::new(FakeApiKeyGenerator::new()),
                    operator_authorities: Arc::new(authorities),
                }),
                keys,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::with(FakeOperatorAuthorities::admitting())
        }

        fn create(&self, expires_at: Expiry) -> Result<OperatorKeyCreated, AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                expires_at,
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Bob makes a key for his CLI. It is his, starts with `opk_`, is
    /// stored, and its making is recorded.
    #[test]
    fn creates_key_and_audits() {
        let setup = Setup::new();

        let created = setup.create(Expiry::Never).unwrap();

        let stored = block_on(setup.keys.find_by_prefix(&created.key_prefix))
            .unwrap()
            .unwrap();
        assert!(created.key_prefix.as_str().starts_with("opk_"));
        assert_eq!(stored.operator_id(), &test_operator_id());
        assert_eq!(setup.recorded(), vec!["operator.operator_api_key_created"]);
    }

    /// Bob asks for a key that ended an hour ago. It is refused and nothing
    /// is stored.
    #[test]
    fn a_key_that_has_already_ended_is_refused() {
        let setup = Setup::new();

        let result = setup.create(Expiry::At(clock::now() - Duration::hours(1)));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.keys.count(), 0);
    }

    /// A disabled operator's authority refusal prevents creating a key,
    /// leaving the key store empty.
    #[test]
    fn disabled_operator_returns_forbidden() {
        let setup = Setup::with(FakeOperatorAuthorities::refusing(Refusal::Forbidden));

        let result = setup.create(Expiry::Never);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.keys.count(), 0);
    }

    /// An unauthenticated operator cannot create a key, and no creation
    /// event is recorded.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let setup = Setup::with(FakeOperatorAuthorities::refusing(Refusal::SignedOut));

        let result = setup.create(Expiry::Never);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.recorded().is_empty());
    }
}
