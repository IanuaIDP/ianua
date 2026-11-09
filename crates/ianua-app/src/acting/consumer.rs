//! A consumer acting through the API: the credential it came with, checked
//! by the consumer itself, and what its roles give it now.
//!
//! This is the resolver behind [`ConsumerAuthorities`] in production.
//!
//! A request never names the consumer it acts as. The gateway hands over
//! the credential it saw, the consumer is found by it, and only the
//! consumer's own sign-in check turns it into the proof that
//! [`ConsumerAuthority::of`] asks for. Any caller that could name a
//! consumer would make topics and subscriptions in its name.
//!
//! The sign-in check counts a credential only until it expires, and a key a
//! rotation replaced only while its overlap lasts. Each request that acts
//! is then counted against the consumer's quota, and refused once the
//! period's allowance is spent.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::consumers::authority::ConsumerAuthority;
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::consumers::quota::{ConsumerQuota, QuotaVerdict};
use ianua_domain::domains::consumers::sign_in::{ConsumerSignIn, PresentedToken};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::PrincipalRef;

use crate::acting::ConsumerAuthorities;
use crate::context::{ConsumerCaller, PresentedCredential, QuotaCharge};
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, Holder};
use crate::ports::consumers::{ConsumerQuotaCounter, ConsumerStore};
use crate::services::issuers::TenantIssuers;

/// The stores [`ConsumerActing`] reads a consumer's sign-in from.
#[derive(ianua_macros::Fakes)]
pub struct ConsumerActingPorts {
    /// The tenant's consumers, found by their credentials.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// Who holds which roles in the tenant.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's own token issuer, which no consumer may trust.
    pub issuers: TenantIssuers,
    /// Counts each consumer's requests against its quota.
    pub quota_counter: Arc<dyn ConsumerQuotaCounter>,
}

/// Signs consumers in from the stored records for the credential they
/// present.
pub struct ConsumerActing {
    ports: ConsumerActingPorts,
}

impl ConsumerActing {
    /// A resolver reading from `ports`.
    #[must_use]
    pub fn new(ports: ConsumerActingPorts) -> Self {
        Self { ports }
    }

    /// The consumer the credential names, with the proof it signed in with
    /// it.
    async fn signed_in(
        &self,
        caller: &ConsumerCaller,
    ) -> Result<(Consumer<ResolvedTenant>, ConsumerSignIn), AppError> {
        let consumer = self.named_by(caller).await?;
        let signed_in = match caller.credential() {
            PresentedCredential::Key { digest, .. } => consumer.sign_in_with_key(digest),
            PresentedCredential::Certificate(fingerprint) => {
                consumer.sign_in_with_certificate(fingerprint)
            }
            PresentedCredential::Token { issuer, subject } => {
                let tenant_issuer = self.ports.issuers.of(caller.tenant()).await?;
                consumer.sign_in_with_token(PresentedToken { issuer, subject }, &tenant_issuer)
            }
        };
        let signed_in = signed_in.map_err(|_| AppError::Unauthenticated)?;
        Ok((consumer, signed_in))
    }

    /// The tenant's consumer the credential names.
    async fn named_by(
        &self,
        caller: &ConsumerCaller,
    ) -> Result<Consumer<ResolvedTenant>, AppError> {
        let store = self.ports.consumer_store.as_ref();
        let tenant = caller.tenant();
        let found = match caller.credential() {
            PresentedCredential::Key { prefix, .. } => {
                store.find_by_key_prefix(tenant, prefix).await
            }
            PresentedCredential::Certificate(fingerprint) => {
                store.find_by_cert_fingerprint(tenant, fingerprint).await
            }
            PresentedCredential::Token { issuer, subject } => {
                store
                    .find_by_jwt_issuer_subject(tenant, issuer, subject)
                    .await
            }
        };
        found.or_internal()?.ok_or(AppError::Unauthenticated)
    }

    /// Counts this request against `consumer`'s quota, and refuses it once
    /// the period's allowance is spent. A consumer without a quota is not
    /// counted, nor a check on a connection already counted when it opened.
    ///
    /// # Errors
    ///
    /// - `AppError::TooManyRequests` when the allowance is spent.
    /// - `AppError::Internal` when the counter fails, so a request nobody
    ///   could count is refused rather than let through.
    async fn ensure_within_quota(
        &self,
        caller: &ConsumerCaller,
        consumer: &Consumer<ResolvedTenant>,
    ) -> Result<(), AppError> {
        if caller.charge() == QuotaCharge::AlreadyCounted {
            return Ok(());
        }
        let quota = consumer.quota();
        let ConsumerQuota::Limited(allowance) = quota else {
            return Ok(());
        };
        let used = self
            .ports
            .quota_counter
            .spend(caller.tenant(), consumer.id(), allowance.per())
            .await
            .or_internal()?;
        ensure_admitted(quota.admits(used))
    }
}

#[async_trait]
impl ConsumerAuthorities for ConsumerActing {
    async fn authority(&self, caller: &ConsumerCaller) -> Result<ConsumerAuthority, AppError> {
        let (consumer, signed_in) = self.signed_in(caller).await?;
        let records = self
            .ports
            .access_records
            .load_held_by(
                caller.tenant(),
                Holder::of(PrincipalRef::Consumer(*consumer.id())),
            )
            .await
            .or_internal()?;
        let authority =
            ConsumerAuthority::of(&consumer, &signed_in, &records.access(**caller.tenant()))
                .map_err(AppError::from_domain)?;
        self.ensure_within_quota(caller, &consumer).await?;
        Ok(authority)
    }
}

/// Refuses a request the consumer's quota has no room for.
///
/// # Errors
///
/// - `AppError::TooManyRequests` when `verdict` says the allowance is spent.
fn ensure_admitted(verdict: QuotaVerdict) -> Result<(), AppError> {
    match verdict {
        QuotaVerdict::Within { .. } => Ok(()),
        QuotaVerdict::Exhausted => Err(AppError::TooManyRequests(message!(
            "app-the-consumer-s-quota-for-this",
            "the consumer's quota for this period is spent"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
    use ianua_domain::domains::consumers::quota::{QuotaPeriod, RequestAllowance};
    use ianua_domain::shared::clock;
    use ianua_domain::types::{
        CertificateFingerprint, Expiry, FederatedSubject, Issuer, TokenHash,
    };

    use super::*;
    use crate::test_support::consumers::{
        FakeConsumerQuotaCounter, UnreachableQuotaCounter, billing_sync, billing_sync_expiring,
        billing_sync_overlapping, billing_sync_with_quota, key_caller, old_key_caller,
        sign_in_counted_by, sign_in_of, test_key_digest,
    };
    use crate::test_support::{block_on, test_ctx};

    const PUBLISH: SystemPermission = SystemPermission::Messaging(MessagingAction::Publish);

    /// A quota of `requests` a day.
    fn daily(requests: u64) -> ConsumerQuota {
        ConsumerQuota::Limited(RequestAllowance::new(requests, QuotaPeriod::Day).unwrap())
    }

    /// Ann rotated the key of "billing-sync" an hour ago, keeping the old
    /// one for a day. A caller still on the old key acts as the consumer.
    #[test]
    fn the_old_key_works_while_its_overlap_lasts() {
        let consumer = billing_sync_overlapping();
        let id = *consumer.id();
        let consumers = sign_in_of(consumer, &[PUBLISH]);

        let authority = block_on(consumers.authority(&old_key_caller())).unwrap();

        assert_eq!(authority.id(), &id);
    }

    /// A consumer key that expired yesterday is unauthenticated on the
    /// next authority lookup.
    #[test]
    fn an_expired_key_is_signed_out() {
        let yesterday = clock::now() - time::Duration::days(1);
        let consumers = sign_in_of(billing_sync_expiring(Expiry::At(yesterday)), &[PUBLISH]);

        let result = block_on(consumers.authority(&key_caller(test_key_digest())));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// "billing-sync" may send 3 requests a day and has sent 2. The third
    /// acts, and is counted.
    #[test]
    fn the_last_request_of_the_quota_is_admitted_and_counted() {
        let consumer = billing_sync_with_quota(daily(3));
        let id = *consumer.id();
        let counter = Arc::new(FakeConsumerQuotaCounter::having_counted(
            id,
            QuotaPeriod::Day,
            2,
        ));
        let consumers = sign_in_counted_by(consumer, &[PUBLISH], counter.clone());

        let result = block_on(consumers.authority(&key_caller(test_key_digest())));

        assert!(result.is_ok());
        assert_eq!(counter.counted(id, QuotaPeriod::Day), 3);
    }

    /// Billing-sync has spent its three-request daily quota. A fourth
    /// request returns too many requests.
    #[test]
    fn a_request_past_the_quota_is_refused() {
        let consumer = billing_sync_with_quota(daily(3));
        let counter = Arc::new(FakeConsumerQuotaCounter::having_counted(
            *consumer.id(),
            QuotaPeriod::Day,
            3,
        ));
        let consumers = sign_in_counted_by(consumer, &[PUBLISH], counter);

        let result = block_on(consumers.authority(&key_caller(test_key_digest())));

        assert!(matches!(result, Err(AppError::TooManyRequests(_))));
    }

    /// An unreachable quota counter causes an internal error for a
    /// consumer with a daily limit, rather than granting authority unchecked.
    #[test]
    fn a_request_nobody_could_count_is_refused() {
        let consumers = sign_in_counted_by(
            billing_sync_with_quota(daily(3)),
            &[PUBLISH],
            Arc::new(UnreachableQuotaCounter),
        );

        let result = block_on(consumers.authority(&key_caller(test_key_digest())));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// "billing-sync" pays for 3 requests a day and has sent 3. Its tunnel,
    /// opened earlier, is checked again while it stays open. The check
    /// still signs it in, and is not counted.
    #[test]
    fn a_check_on_an_open_connection_is_not_counted() {
        let consumer = billing_sync_with_quota(daily(3));
        let id = *consumer.id();
        let counter = Arc::new(FakeConsumerQuotaCounter::having_counted(
            id,
            QuotaPeriod::Day,
            3,
        ));
        let consumers = sign_in_counted_by(consumer, &[PUBLISH], counter.clone());
        let held = key_caller(test_key_digest()).charged(QuotaCharge::AlreadyCounted);

        let result = block_on(consumers.authority(&held));

        assert!(result.is_ok());
        assert_eq!(counter.counted(id, QuotaPeriod::Day), 3);
    }

    /// Marking a connection as already counted does not bypass credential
    /// expiry. Its expired consumer key is still unauthenticated.
    #[test]
    fn a_check_on_an_open_connection_still_refuses_an_expired_key() {
        let yesterday = clock::now() - time::Duration::days(1);
        let consumers = sign_in_of(billing_sync_expiring(Expiry::At(yesterday)), &[PUBLISH]);
        let held = key_caller(test_key_digest()).charged(QuotaCharge::AlreadyCounted);

        let result = block_on(consumers.authority(&held));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// "billing-sync" has no quota. Its requests act and are not counted.
    #[test]
    fn a_consumer_without_a_quota_is_not_counted() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let counter = Arc::new(FakeConsumerQuotaCounter::empty());
        let consumers = sign_in_counted_by(consumer, &[PUBLISH], counter.clone());

        let result = block_on(consumers.authority(&key_caller(test_key_digest())));

        assert!(result.is_ok());
        assert_eq!(counter.counted(id, QuotaPeriod::Day), 0);
    }

    /// "billing-sync" calls with its own API key. It acts as itself, with
    /// the publishing right its role gives it.
    #[test]
    fn a_consumer_with_its_own_key_acts_with_its_roles() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let consumers = sign_in_of(consumer, &[PUBLISH]);

        let authority = block_on(consumers.authority(&key_caller(test_key_digest()))).unwrap();

        assert_eq!(authority.id(), &id);
        assert!(authority.holds(PUBLISH));
    }

    /// A matching key prefix with the wrong digest is unauthenticated.
    #[test]
    fn a_wrong_key_under_the_right_prefix_is_signed_out() {
        let consumers = sign_in_of(billing_sync(), &[PUBLISH]);
        let guessed = TokenHash::from_stored("guessed".to_owned());

        let result = block_on(consumers.authority(&key_caller(guessed)));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// When no consumer owns the presented key, authority resolution
    /// returns unauthenticated.
    #[test]
    fn a_key_no_consumer_has_is_signed_out() {
        let consumers = ConsumerActing::new(ConsumerActingPorts::fakes());

        let result = block_on(consumers.authority(&key_caller(test_key_digest())));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An unknown client certificate cannot resolve consumer authority
    /// and returns unauthenticated.
    #[test]
    fn a_certificate_no_consumer_has_is_signed_out() {
        let consumers = sign_in_of(billing_sync(), &[PUBLISH]);
        let caller = ConsumerCaller::new(
            test_ctx().tenant(),
            PresentedCredential::Certificate(CertificateFingerprint::from_digest([7; 32])),
        );

        let result = block_on(consumers.authority(&caller));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Naming a key-authenticated consumer as a foreign token's subject
    /// does not authenticate it. The token lookup returns unauthenticated.
    #[test]
    fn a_token_for_a_key_consumer_is_signed_out() {
        let consumers = sign_in_of(billing_sync(), &[PUBLISH]);
        let caller = ConsumerCaller::new(
            test_ctx().tenant(),
            PresentedCredential::Token {
                issuer: Issuer::new("https://eve.example.test").unwrap(),
                subject: FederatedSubject::new("billing-sync").unwrap(),
            },
        );

        let result = block_on(consumers.authority(&caller));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
