//! The rate limits and throttles: the API's per-minute budget, simple
//! binds per tenant, one mailed link per address and purpose, and the
//! resends and verification requests a person or a receiver may ask for.
//!
//! Each counts in a fixed window on the shared state it is given. The
//! ports say they are held in the process, so the composition root hands
//! them the in-memory state; any of them counts across the fleet on the
//! cache server just as well. A count that cannot be read refuses, never
//! admits.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::directory::BindThrottle;
use ianua_app::ports::limits::{MailPurpose, MailThrottle, RateBudget, RateLimiter};
use ianua_app::ports::signals::VerificationThrottle;
use ianua_app::ports::webhooks::WebhookSendThrottle;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, SignalStreamId, TenantId, WebhookSubscriptionId};

use crate::cache::state::{SharedState, key};

/// The window the per-minute limits count in.
const MINUTE: Duration = Duration::from_secs(60);

/// What a window allows: how many in how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowance {
    /// The most admitted in one window.
    pub most: u32,
    /// How long a window lasts.
    pub window: Duration,
}

/// Whether one more in the window `key` stays within `allowance`.
async fn within(
    state: &dyn SharedState,
    key: &str,
    allowance: Allowance,
) -> Result<bool, DomainError> {
    let count = state.count(key, 1, allowance.window).await?;
    Ok(count <= u64::from(allowance.most))
}

/// The API's rate limit: requests per budget per minute.
pub struct CacheRateLimiter {
    state: Arc<dyn SharedState>,
}

impl CacheRateLimiter {
    /// A limit counting on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

/// The key a budget's requests are counted under.
fn budget_key(budget: &RateBudget) -> String {
    match budget {
        RateBudget::Tenant(id) => key(&["rate", "tenant", &id.to_string()]),
        RateBudget::Organization(id) => key(&["rate", "organization", &id.to_string()]),
        RateBudget::Operator(id) => key(&["rate", "operator", &id.to_string()]),
    }
}

#[async_trait]
impl RateLimiter for CacheRateLimiter {
    async fn check_and_increment(
        &self,
        budget: &RateBudget,
        limit_per_minute: u32,
    ) -> Result<u32, DomainError> {
        let count = self.state.count(&budget_key(budget), 1, MINUTE).await?;
        let limit = u64::from(limit_per_minute);
        if count > limit {
            return Err(DomainError::forbidden(message!(
                "infra-the-rate-limit-is-exceeded",
                "the rate limit is exceeded"
            )));
        }
        Ok(u32::try_from(limit.saturating_sub(count)).unwrap_or(u32::MAX))
    }
}

/// The throttle on simple binds, per tenant per minute, apart from the API
/// budget so a bind-guessing flood never spends the tenant's API quota.
pub struct CacheBindThrottle {
    state: Arc<dyn SharedState>,
    per_minute: u32,
}

impl CacheBindThrottle {
    /// A throttle letting `per_minute` binds through per tenant, counting on
    /// `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>, per_minute: u32) -> Self {
        Self { state, per_minute }
    }
}

#[async_trait]
impl BindThrottle for CacheBindThrottle {
    async fn check_and_record(&self, tenant_id: &TenantId) -> Result<(), DomainError> {
        let allowance = Allowance {
            most: self.per_minute,
            window: MINUTE,
        };
        if within(
            self.state.as_ref(),
            &key(&["bind", &tenant_id.to_string()]),
            allowance,
        )
        .await?
        {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "infra-the-bind-rate-limit-is-exceeded",
            "the bind rate limit is exceeded"
        )))
    }
}

/// The word a purpose's mail is counted under.
fn purpose_word(purpose: MailPurpose) -> &'static str {
    match purpose {
        MailPurpose::PasswordReset => "password-reset",
        MailPurpose::MagicLink => "magic-link",
        MailPurpose::OrgPasswordReset => "org-password-reset",
        MailPurpose::Invitation => "invitation",
        MailPurpose::OrgInvitation => "org-invitation",
        MailPurpose::AddressConfirmation => "address-confirmation",
        MailPurpose::OrgAddressConfirmation => "org-address-confirmation",
        MailPurpose::Signup => "signup",
    }
}

/// The throttle on mailed links: one per address and purpose per window.
pub struct CacheMailThrottle {
    state: Arc<dyn SharedState>,
    window: Duration,
}

impl CacheMailThrottle {
    /// A throttle letting one link per address and purpose through each
    /// `window`, counting on `state`. A zero window lets every mail
    /// through.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>, window: Duration) -> Self {
        Self { state, window }
    }
}

#[async_trait]
impl MailThrottle for CacheMailThrottle {
    async fn admit(&self, purpose: MailPurpose, recipient: &Email) -> Result<bool, DomainError> {
        if self.window.is_zero() {
            return Ok(true);
        }
        let address = recipient.as_str().to_ascii_lowercase();
        let claim = key(&["mail", purpose_word(purpose), &address]);
        Ok(self.state.claim_once(&claim, self.window).await?)
    }
}

/// The throttle on a person's resends and tests of one webhook.
pub struct CacheWebhookSendThrottle {
    state: Arc<dyn SharedState>,
    allowance: Allowance,
}

impl TenantScoped for CacheWebhookSendThrottle {}

impl CacheWebhookSendThrottle {
    /// A throttle admitting `allowance` per subscription, counting on
    /// `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>, allowance: Allowance) -> Self {
        Self { state, allowance }
    }
}

#[async_trait]
impl WebhookSendThrottle for CacheWebhookSendThrottle {
    async fn admit(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
    ) -> Result<bool, DomainError> {
        let window = key(&[
            "webhook-send",
            &tenant_id.to_string(),
            &subscription_id.to_string(),
        ]);
        within(self.state.as_ref(), &window, self.allowance).await
    }
}

/// The throttle on a receiver's requests for verification events.
pub struct CacheVerificationThrottle {
    state: Arc<dyn SharedState>,
    allowance: Allowance,
}

impl TenantScoped for CacheVerificationThrottle {}

impl CacheVerificationThrottle {
    /// A throttle admitting `allowance` per stream, counting on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>, allowance: Allowance) -> Self {
        Self { state, allowance }
    }
}

#[async_trait]
impl VerificationThrottle for CacheVerificationThrottle {
    async fn admit(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
    ) -> Result<bool, DomainError> {
        let window = key(&[
            "verification",
            &tenant_id.to_string(),
            &stream_id.to_string(),
        ]);
        within(self.state.as_ref(), &window, self.allowance).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{OrganizationId, TenantId};

    use super::*;
    use crate::cache::MemoryState;

    fn state() -> Arc<dyn SharedState> {
        Arc::new(MemoryState::new(1_000))
    }

    /// The API budget counts down per minute and refuses past the limit;
    /// another budget keeps its own count.
    #[tokio::test]
    async fn the_rate_limit_counts_each_budget_apart() {
        let limiter = CacheRateLimiter::new(state());
        let acme = RateBudget::Tenant(TenantId::new());
        let other = RateBudget::Organization(OrganizationId::new());

        let first = limiter.check_and_increment(&acme, 2).await.unwrap();
        let second = limiter.check_and_increment(&acme, 2).await.unwrap();
        let third = limiter.check_and_increment(&acme, 2).await;
        let elsewhere = limiter.check_and_increment(&other, 2).await.unwrap();

        assert_eq!((first, second), (1, 0));
        assert!(matches!(third, Err(DomainError::Forbidden(_))));
        assert_eq!(elsewhere, 1);
    }

    /// With a one-bind limit, the first bind passes and the second is forbidden.
    #[tokio::test]
    async fn binds_past_the_limit_are_refused() {
        let throttle = CacheBindThrottle::new(state(), 1);
        let tenant = TenantId::new();

        let first = throttle.check_and_record(&tenant).await;
        let second = throttle.check_and_record(&tenant).await;

        assert!(first.is_ok());
        assert!(matches!(second, Err(DomainError::Forbidden(_))));
    }

    /// One link per address and purpose goes out per window, whatever case
    /// the address is written in; another purpose to the same address goes
    /// too.
    #[tokio::test]
    async fn one_link_per_address_and_purpose_goes_out() {
        let throttle = CacheMailThrottle::new(state(), MINUTE);
        let ann = Email::new("ann@acme.example").unwrap();
        let shouted = Email::new("ANN@acme.example").unwrap();

        let first = throttle
            .admit(MailPurpose::PasswordReset, &ann)
            .await
            .unwrap();
        let again = throttle
            .admit(MailPurpose::PasswordReset, &shouted)
            .await
            .unwrap();
        let other = throttle.admit(MailPurpose::MagicLink, &ann).await.unwrap();

        assert!(first);
        assert!(!again);
        assert!(other);
    }

    /// A webhook's resends are admitted within the allowance and refused
    /// past it.
    #[tokio::test]
    async fn resends_past_the_allowance_are_refused() {
        let throttle = CacheWebhookSendThrottle::new(
            state(),
            Allowance {
                most: 2,
                window: MINUTE,
            },
        );
        let tenant = ScopedTenant::for_background(TenantId::new());
        let subscription = WebhookSubscriptionId::new();

        let admitted = [
            throttle.admit(&tenant, &subscription).await.unwrap(),
            throttle.admit(&tenant, &subscription).await.unwrap(),
            throttle.admit(&tenant, &subscription).await.unwrap(),
        ];

        assert_eq!(admitted, [true, true, false]);
    }
}
