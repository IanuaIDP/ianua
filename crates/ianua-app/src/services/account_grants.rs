//! Exchanging an account's lasting grant before a call goes through it,
//! one exchange per account at a time across every worker.
//!
//! A service such as Jira or GitLab retires a refresh token the moment it
//! is used. Two calls at once on one account would send the same token and
//! the second would be refused. So when an account's short-lived token is
//! near its end, the caller takes the account's turn, reads the account
//! again, exchanges only if nobody just did, and keeps the new pair before
//! the turn ends. A caller that waited finds that pair and exchanges
//! nothing. Without a turn nothing is exchanged: the call is turned away
//! and tried again.

use std::sync::Arc;

use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, IntegrationAccountId, SealedSecret, UntrustedText};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SealedAt;
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{
    GrantExchangeLease, GrantExchanger, IntegrationAccountStore, Renewal,
};
use crate::services::kept_together::kept_apart;
use crate::tenancy::ScopedTenant;

/// The ports [`AccountGrants`] works through.
#[derive(ianua_macros::Fakes)]
pub struct AccountGrantsPorts {
    /// The accounts, read again once the turn is held.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Asks the integration whether a grant is due, and exchanges it.
    pub exchanger: Arc<dyn GrantExchanger>,
    /// Lets one caller per account exchange at a time.
    pub lease: Arc<dyn GrantExchangeLease>,
    /// Keeps the new pair and its record together, at once.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// The account a call is about to go through.
#[derive(Clone, Copy)]
pub struct GrantHolder<'a> {
    /// The account the call acts through.
    pub id: &'a IntegrationAccountId,
    /// The integration whose service issued its grant.
    pub integration: &'a IntegrationKey,
    /// Its credential as the caller read it.
    pub credential: &'a SealedAt,
}

/// Keeps accounts' short-lived tokens good just before they are used.
pub struct AccountGrants {
    ports: AccountGrantsPorts,
}

impl AccountGrants {
    /// Working through `ports`.
    #[must_use]
    pub fn new(ports: AccountGrantsPorts) -> Self {
        Self { ports }
    }

    /// The credential a call through `holder` should use: the one the
    /// caller read, or the one just exchanged for it.
    ///
    /// # Errors
    ///
    /// The outcome of a call that was not sent: turned away when the
    /// account's turn could not be had or the new pair could not be kept,
    /// and failed when the service refused the grant.
    pub async fn current(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        holder: GrantHolder<'_>,
    ) -> Result<SealedAt, ActionOutcome> {
        let exchanger = self.ports.exchanger.as_ref();
        if !exchanger
            .is_due(holder.integration, holder.credential)
            .await
        {
            return Ok(holder.credential.clone());
        }
        let turn = match self.ports.lease.claim_within(holder.id).await {
            Ok(Some(turn)) => turn,
            Ok(None) => return Err(unsent("another call is renewing this account's sign-in")),
            Err(error) => {
                tracing::warn!(%error, account = %holder.id, "a grant exchange's turn could not be taken");
                return Err(unsent("this account's sign-in could not be renewed yet"));
            }
        };
        let current = self.exchanged_in_turn(tenant, auditor, holder).await;
        self.ports.lease.release(turn).await;
        current
    }

    /// The account's credential once its turn is held, exchanged unless a
    /// caller before this one just did. An account removed in the meantime
    /// keeps nothing, and the call goes on with what it read.
    async fn exchanged_in_turn(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        holder: GrantHolder<'_>,
    ) -> Result<SealedAt, ActionOutcome> {
        let Ok(found) = self.ports.accounts.find_by_id(tenant, holder.id).await else {
            return Err(unsent("this account could not be read"));
        };
        let Some(mut account) = found else {
            return Ok(holder.credential.clone());
        };
        let current = at_place(account.credential().clone(), holder.credential);
        let exchanger = self.ports.exchanger.as_ref();
        if !exchanger.is_due(holder.integration, &current).await {
            return Ok(current);
        }
        let Renewal::Renewed(renewed) = exchanger.exchange(holder.integration, &current).await?
        else {
            return Ok(current);
        };
        account.renew_credential(renewed);
        if let Err(error) = self.keep(tenant, auditor, &mut account).await {
            tracing::error!(%error, account = %holder.id, "a renewed grant could not be kept");
            return Err(unsent("this account's renewed sign-in could not be kept"));
        }
        Ok(at_place(account.credential().clone(), holder.credential))
    }

    /// Keeps `account`'s new credential and its record in a unit of its
    /// own, so a worker waiting for the turn sees it however the request
    /// around this one ends: the old grant no longer works.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        account: &mut IntegrationAccount<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let accounts = self.ports.accounts.as_ref();
        kept_apart(self.ports.unit_of_work.as_ref(), async {
            accounts.save(tenant, account).await.or_internal()?;
            auditor
                .dispatch_by(&ActorRef::System, account.take_events(tenant))
                .await
                .or_internal()
        })
        .await
    }
}

/// `secret`, sealed where `read` says.
fn at_place(secret: SealedSecret, read: &SealedAt) -> SealedAt {
    SealedAt {
        secret,
        place: read.place.clone(),
    }
}

/// The outcome of a call not sent, to be tried again.
fn unsent(reason: &str) -> ActionOutcome {
    ActionOutcome::TurnedAway(UntrustedText::record(reason))
}

#[cfg(test)]
mod tests {
    use futures_util::future::join;
    use ianua_domain::domains::workflows::account::AccountSharing;

    use super::*;
    use crate::test_support::workflows::{
        FakeGrantExchanger, FakeGrantLease, FakeIntegrationAccountStore, person, sheets_account,
    };
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::workflows::accounts::connect::integration_credential_place;

    struct Bench {
        account: IntegrationAccount<ResolvedTenant>,
        accounts: Arc<FakeIntegrationAccountStore>,
        exchanger: Arc<FakeGrantExchanger>,
        lease: Arc<FakeGrantLease>,
        unit: Arc<RecordingUnitOfWork>,
        events: Arc<FakeEventDispatcher>,
    }

    impl Bench {
        fn new(exchanger: FakeGrantExchanger) -> Self {
            let account = sheets_account(&person("bob@corp.test"), AccountSharing::Tenant);
            Self {
                accounts: Arc::new(FakeIntegrationAccountStore::holding(&account)),
                account,
                exchanger: Arc::new(exchanger),
                lease: Arc::new(FakeGrantLease::default()),
                unit: Arc::new(RecordingUnitOfWork::default()),
                events: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn grants(&self) -> AccountGrants {
            AccountGrants::new(AccountGrantsPorts {
                accounts: self.accounts.clone(),
                exchanger: self.exchanger.clone(),
                lease: self.lease.clone(),
                unit_of_work: self.unit.clone(),
            })
        }

        fn read(&self) -> SealedAt {
            SealedAt {
                secret: self.account.credential().clone(),
                place: integration_credential_place(&test_ctx().tenant(), self.account.id()),
            }
        }

        async fn current(&self, grants: &AccountGrants) -> Result<SealedAt, ActionOutcome> {
            let read = self.read();
            let holder = GrantHolder {
                id: self.account.id(),
                integration: self.account.integration(),
                credential: &read,
            };
            grants
                .current(
                    &test_ctx().tenant(),
                    &test_auditor(self.events.clone()),
                    holder,
                )
                .await
        }
    }

    /// Pat's Jira token has hours left. The call goes through what it read,
    /// no turn is taken and Jira is not asked.
    #[test]
    fn a_grant_not_due_is_left_alone() {
        let bench = Bench::new(FakeGrantExchanger::not_due());

        let current = block_on(bench.current(&bench.grants())).unwrap();

        assert_eq!(current.secret, *bench.account.credential());
        assert_eq!(bench.exchanger.exchanges(), 0);
        assert_eq!(bench.lease.claims(), 0);
    }

    /// Pat's token is near its end. The grant is exchanged, the new pair
    /// kept at once in a unit of its own and recorded, and the call goes
    /// through the new one.
    #[test]
    fn a_due_grant_is_exchanged_and_kept_before_the_call() {
        let bench = Bench::new(FakeGrantExchanger::renewing("v1.RENEWED"));

        let current = block_on(bench.current(&bench.grants())).unwrap();

        assert_eq!(current.secret.as_str(), "v1.RENEWED");
        let stored = bench.accounts.stored(bench.account.id()).unwrap();
        assert_eq!(stored.credential().as_str(), "v1.RENEWED");
        assert_eq!(
            *bench.events.records.lock().unwrap(),
            ["workflows.account_credential_renewed"]
        );
        assert_eq!(bench.lease.released(), 1);
    }

    /// Stops: Pat's workflow and a picker both reach a Jira account in the
    /// token's last minute. Sending the same refresh token twice would get
    /// the second refused. One exchanges, the other waits for its turn,
    /// finds the new pair and exchanges nothing, and both call through it.
    #[tokio::test]
    async fn two_callers_at_once_make_one_exchange() {
        let bench = Bench::new(FakeGrantExchanger::renewing("v1.RENEWED").taking_a_moment());
        let grants = bench.grants();

        let (first, second) = join(bench.current(&grants), bench.current(&grants)).await;

        assert_eq!(bench.exchanger.exchanges(), 1);
        assert_eq!(first.unwrap().secret.as_str(), "v1.RENEWED");
        assert_eq!(second.unwrap().secret.as_str(), "v1.RENEWED");
    }

    /// Someone else holds the turn past the wait. Nothing is exchanged and
    /// the call is turned away, so it is tried again later.
    #[test]
    fn no_turn_turns_the_call_away_without_an_exchange() {
        let bench = Bench::new(FakeGrantExchanger::renewing("v1.RENEWED"));
        bench.lease.never_grant();

        let refused = block_on(bench.current(&bench.grants())).unwrap_err();

        assert!(matches!(refused, ActionOutcome::TurnedAway(_)));
        assert_eq!(bench.exchanger.exchanges(), 0);
    }

    /// The lease's database is down. Exchanging anyway could spend the
    /// token twice, so the call is turned away.
    #[test]
    fn a_lease_that_cannot_be_read_exchanges_nothing() {
        let bench = Bench::new(FakeGrantExchanger::renewing("v1.RENEWED"));
        bench.lease.fail();

        let refused = block_on(bench.current(&bench.grants())).unwrap_err();

        assert!(matches!(refused, ActionOutcome::TurnedAway(_)));
        assert_eq!(bench.exchanger.exchanges(), 0);
    }

    /// Jira refuses the grant. The call fails with that answer, nothing is
    /// kept, and the turn is given back.
    #[test]
    fn a_refused_grant_fails_the_call_and_ends_the_turn() {
        let bench = Bench::new(FakeGrantExchanger::refusing("the grant was revoked"));

        let refused = block_on(bench.current(&bench.grants())).unwrap_err();

        assert!(matches!(refused, ActionOutcome::Failed(_)));
        assert_eq!(bench.lease.released(), 1);
        assert_eq!(
            bench
                .accounts
                .stored(bench.account.id())
                .unwrap()
                .credential(),
            bench.account.credential()
        );
    }
}
