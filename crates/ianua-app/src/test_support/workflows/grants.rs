//! An exchanger and a lease for accounts' grants, and the shared service
//! built over fakes of both.

use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use async_trait::async_trait;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{IntegrationAccountId, SealedSecret, UntrustedText};

use crate::ports::authentication::SealedAt;
use crate::ports::workflows::{GrantExchangeLease, GrantExchanger, GrantTurn, Renewal, TurnHolder};
use crate::services::account_grants::{AccountGrants, AccountGrantsPorts};
use crate::test_support::Fake;

/// Lets everything else that is ready run before going on.
async fn give_way() {
    let mut gave = false;
    poll_fn(move |context| {
        if gave {
            return Poll::Ready(());
        }
        gave = true;
        context.waker().wake_by_ref();
        Poll::Pending
    })
    .await;
}

/// What a [`FakeGrantExchanger`] does with a grant.
enum Answer {
    NeverDue,
    Renews(String),
    Refuses(String),
}

/// An exchanger that counts its exchanges.
pub struct FakeGrantExchanger {
    answer: Answer,
    takes_a_moment: bool,
    exchanges: AtomicUsize,
}

impl FakeGrantExchanger {
    fn answering(answer: Answer) -> Self {
        Self {
            answer,
            takes_a_moment: false,
            exchanges: AtomicUsize::new(0),
        }
    }

    /// One saying no grant is ever due.
    #[must_use]
    pub fn not_due() -> Self {
        Self::answering(Answer::NeverDue)
    }

    /// One issuing `renewed`, and saying a grant is due until it holds that.
    #[must_use]
    pub fn renewing(renewed: &str) -> Self {
        Self::answering(Answer::Renews(renewed.to_owned()))
    }

    /// One saying a grant is due and refusing it, for `reason`.
    #[must_use]
    pub fn refusing(reason: &str) -> Self {
        Self::answering(Answer::Refuses(reason.to_owned()))
    }

    /// The same exchanger, giving way to other callers mid-exchange, as a
    /// call to a service does.
    #[must_use]
    pub fn taking_a_moment(self) -> Self {
        Self {
            takes_a_moment: true,
            ..self
        }
    }

    /// How many exchanges were made.
    #[must_use]
    pub fn exchanges(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl GrantExchanger for FakeGrantExchanger {
    async fn is_due(&self, _: &IntegrationKey, credential: &SealedAt) -> bool {
        match &self.answer {
            Answer::NeverDue => false,
            Answer::Renews(renewed) => credential.secret.as_str() != renewed,
            Answer::Refuses(_) => true,
        }
    }

    async fn exchange(&self, _: &IntegrationKey, _: &SealedAt) -> Result<Renewal, ActionOutcome> {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        if self.takes_a_moment {
            give_way().await;
        }
        match &self.answer {
            Answer::NeverDue => Ok(Renewal::Unchanged),
            Answer::Renews(renewed) => Ok(Renewal::Renewed(
                SealedSecret::new(renewed).expect("a sealed value"),
            )),
            Answer::Refuses(reason) => Err(ActionOutcome::Failed(UntrustedText::record(reason))),
        }
    }
}

impl Fake for Arc<dyn GrantExchanger> {
    fn fake() -> Self {
        Arc::new(FakeGrantExchanger::not_due())
    }
}

/// A lease held in memory: a claim on a held account waits until it is
/// free, unless told it never will be.
#[derive(Default)]
pub struct FakeGrantLease {
    held: Mutex<Vec<IntegrationAccountId>>,
    never: AtomicBool,
    broken: AtomicBool,
    claims: AtomicUsize,
    released: AtomicUsize,
}

impl FakeGrantLease {
    /// From now on no turn is had: every wait runs out.
    pub fn never_grant(&self) {
        self.never.store(true, Ordering::SeqCst);
    }

    /// From now on the lease cannot be read.
    pub fn fail(&self) {
        self.broken.store(true, Ordering::SeqCst);
    }

    /// How many turns were asked for.
    #[must_use]
    pub fn claims(&self) -> usize {
        self.claims.load(Ordering::SeqCst)
    }

    /// How many turns were ended.
    #[must_use]
    pub fn released(&self) -> usize {
        self.released.load(Ordering::SeqCst)
    }

    fn try_take(&self, account: &IntegrationAccountId) -> bool {
        let mut held = self.held.lock().unwrap();
        if held.contains(account) {
            return false;
        }
        held.push(*account);
        true
    }
}

#[async_trait]
impl GrantExchangeLease for FakeGrantLease {
    async fn claim_within(
        &self,
        account: &IntegrationAccountId,
    ) -> Result<Option<GrantTurn>, DomainError> {
        self.claims.fetch_add(1, Ordering::SeqCst);
        if self.broken.load(Ordering::SeqCst) {
            return Err(DomainError::infra_msg("the lease is down"));
        }
        if self.never.load(Ordering::SeqCst) {
            return Ok(None);
        }
        while !self.try_take(account) {
            give_way().await;
        }
        Ok(Some(GrantTurn {
            account: *account,
            holder: TurnHolder::new(),
        }))
    }

    async fn release(&self, turn: GrantTurn) {
        self.released.fetch_add(1, Ordering::SeqCst);
        self.held
            .lock()
            .unwrap()
            .retain(|account| *account != turn.account);
    }
}

impl Fake for Arc<dyn GrantExchangeLease> {
    fn fake() -> Self {
        Arc::new(FakeGrantLease::default())
    }
}

impl Fake for Arc<AccountGrants> {
    fn fake() -> Self {
        Arc::new(AccountGrants::new(AccountGrantsPorts::fakes()))
    }
}
