//! The last step of connecting a cloud account: the attached credential is
//! used once, against a harmless endpoint, and whose account answered is
//! recorded.

use std::sync::Arc;

use ianua_domain::domains::organization::cloud::account::CloudAccount;
use ianua_domain::domains::organization::cloud::credential::CloudCredential;
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::cloud::{CloudAccountStore, CloudProviderRegistry};
use crate::use_case::Command;
use crate::use_cases::organization::cloud_accounts::lookup::{
    begun_external_id, existing_cloud_account,
};
use crate::use_cases::organization::cloud_accounts::rights::ensure_may_connect;

/// Which connection to prove, and when.
pub struct VerifyRequest {
    /// The cloud whose connection is tried.
    pub provider: CloudProvider,
    /// When the verification runs.
    pub now: OffsetDateTime,
}

/// The ports [`VerifyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct VerifyPorts {
    /// Where connections are kept.
    pub store: Arc<dyn CloudAccountStore>,
    /// Reaches each cloud this deployment can drive.
    pub registry: Arc<dyn CloudProviderRegistry>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Uses an attached credential once and records whether it worked.
pub struct VerifyUseCase {
    ports: VerifyPorts,
}

impl VerifyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: VerifyPorts) -> Self {
        Self { ports }
    }

    /// Tries `credential` against its cloud and records the answer on
    /// `account`: verified with whose account answered, or failed with why.
    /// Only failing to ask at all is an error.
    async fn record_verification(
        &self,
        account: &mut CloudAccount,
        credential: &CloudCredential,
        now: OffsetDateTime,
    ) -> Result<(), AppError> {
        let verifier = self
            .ports
            .registry
            .factory(credential.provider())
            .map_err(AppError::from_domain)?
            .credential_verifier();
        let recorded = match verifier.verify(credential).await {
            Ok(identity) => account.mark_verified(identity, now),
            Err(DomainError::Forbidden(reason)) => account.mark_failed(reason.as_str(), now),
            Err(other) => return Err(AppError::from_domain(other)),
        };
        recorded.map_err(AppError::from_domain)
    }
}

impl Command for VerifyUseCase {
    type Caller = OrgCaller;
    type Input = VerifyRequest;
    type Output = Result<CloudAccount, AppError>;

    /// Uses the credential once, records what happened, and records
    /// `organization.cloud_account_verified` with the result.
    ///
    /// A refused credential is the answer to "does this work", not an
    /// error: it is recorded on the connection and the screen shows why.
    /// Only being unable to ask is an error, so our own outage is never
    /// written down as the customer's failure.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without organization-change rights or for credentials opening another cloud account.
    /// - `AppError::NotFound` for no connection; `Conflict` for no attached credential.
    /// - `AppError::Domain` for an unsupported cloud, an unrecordable refusal reason, or a credential the customer can correct, such as a cluster address nobody can reach.
    /// - `AppError::Internal` on cloud connectivity, storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: VerifyRequest,
    ) -> Result<CloudAccount, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        ensure_may_connect(&actor.control()?, organization.id())?;
        let store = self.ports.store.as_ref();
        let provider = request.provider;
        let external_id = begun_external_id(store, organization.id(), provider).await?;
        let mut account = existing_cloud_account(store, organization.id(), provider).await?;
        let credential = attached_credential(&account)?;
        self.record_verification(&mut account, &credential, request.now)
            .await?;
        store.save(&account, &external_id).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), account.take_events())
            .await
            .or_internal()?;
        Ok(account)
    }
}

/// The credential `account` holds, proved or not.
///
/// # Errors
///
/// - `AppError::Conflict` when the connection still waits for one.
fn attached_credential(account: &CloudAccount) -> Result<CloudCredential, AppError> {
    account.credential().cloned().ok_or_else(|| {
        AppError::Conflict(message!(
            "organization-this-connection-is-still-waiting-for",
            "this connection is still waiting for a credential"
        ))
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::account::{CloudIdentity, ConnectionState};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        AwsOnlyRegistry, FakeCloudAccountStore, VerifyOutcome, seeded_aws_connection,
        seeded_aws_credential,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Fixture {
        store: Arc<FakeCloudAccountStore>,
        audit: Arc<FakeEventDispatcher>,
        uc: VerifyUseCase,
    }

    impl Fixture {
        fn with(state: ConnectionState, outcome: VerifyOutcome, actors: FakeOrgActors) -> Self {
            let store = Arc::new(FakeCloudAccountStore::holding(seeded_aws_connection(
                acme(),
                state,
            )));
            Self {
                uc: VerifyUseCase::new(VerifyPorts {
                    store: store.clone(),
                    registry: Arc::new(AwsOnlyRegistry(outcome)),
                    org_actors: Arc::new(actors),
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn attached(outcome: VerifyOutcome) -> Self {
            Self::with(awaiting_verification(), outcome, owner())
        }

        fn verify(&self) -> Result<CloudAccount, AppError> {
            let request = VerifyRequest {
                provider: CloudProvider::Aws,
                now: clock::now(),
            };
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn stored_state(&self) -> ConnectionState {
            self.store
                .stored(&acme(), CloudProvider::Aws)
                .unwrap()
                .state()
                .clone()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn acme() -> OrganizationId {
        test_org_caller().organization_id()
    }

    fn owner() -> FakeOrgActors {
        FakeOrgActors::in_role(OrgRole::Owner)
    }

    fn awaiting_verification() -> ConnectionState {
        ConnectionState::AwaitingVerification {
            credential: seeded_aws_credential(),
        }
    }

    /// Olivia, an owner, proves the role she attached. AWS answers, the
    /// connection becomes usable, and the result is recorded.
    #[test]
    fn verify_marks_a_working_credential_usable() {
        let fixture = Fixture::attached(VerifyOutcome::Accepts);

        let account = fixture.verify().unwrap();

        assert!(account.is_usable());
        assert!(account.usable_credential().is_some());
        assert_eq!(
            fixture.recorded(),
            vec!["organization.cloud_account_verified"]
        );
    }

    /// AWS refuses Olivia's role. That is an answer, not a failure: it is
    /// recorded on the connection, which stays unusable.
    #[test]
    fn a_rejected_credential_is_recorded_rather_than_raised() {
        let fixture = Fixture::attached(VerifyOutcome::Rejects);

        let account = fixture.verify().unwrap();

        assert!(!account.is_usable());
        assert!(matches!(
            fixture.stored_state(),
            ConnectionState::Failed { .. }
        ));
    }

    /// AWS cannot be reached. Our outage is an error, and the connection is
    /// left waiting to be proved, not marked as the customer's failure.
    #[test]
    fn our_own_outage_is_not_written_down_as_their_failure() {
        let fixture = Fixture::attached(VerifyOutcome::Unreachable);

        let result = fixture.verify();

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(fixture.stored_state(), awaiting_verification());
    }

    /// Olivia names a cluster address nobody can reach: hers to correct.
    /// She gets the reason, the connection waits to be proved again, and no
    /// outage of ours is reported.
    #[test]
    fn a_credential_the_customer_can_correct_is_refused_with_its_reason() {
        let fixture = Fixture::attached(VerifyOutcome::Correctable);

        let result = fixture.verify();

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(fixture.stored_state(), awaiting_verification());
    }

    /// A verifier reporting a different cloud account is refused, leaving
    /// the stored verified connection and its identity unchanged.
    #[test]
    fn a_credential_opening_another_account_is_refused() {
        let tied = ConnectionState::Verified {
            credential: seeded_aws_credential(),
            at: clock::now(),
            identity: CloudIdentity::new("999999999999").unwrap(),
        };
        let fixture = Fixture::with(tied.clone(), VerifyOutcome::Accepts, owner());

        let result = fixture.verify();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.stored_state(), tied);
    }

    /// Olivia proves a connection still waiting for its role. There is
    /// nothing to try, so it is refused as a conflict.
    #[test]
    fn verifying_without_a_credential_is_refused() {
        let fixture = Fixture::with(
            ConnectionState::AwaitingCredential,
            VerifyOutcome::Accepts,
            owner(),
        );

        let result = fixture.verify();

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Olivia proves a connection to a cloud she never began connecting. It
    /// is not found.
    #[test]
    fn verifying_a_connection_that_was_never_begun_is_refused() {
        let uc = VerifyUseCase::new(VerifyPorts::fakes());

        let result = block_on(uc.execute(
            &test_org_caller(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            VerifyRequest {
                provider: CloudProvider::Aws,
                now: clock::now(),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A plain member cannot verify an attached credential, and nothing is
    /// recorded.
    #[test]
    fn a_plain_member_is_refused() {
        let fixture = Fixture::with(
            awaiting_verification(),
            VerifyOutcome::Accepts,
            FakeOrgActors::in_role(OrgRole::Member),
        );

        let result = fixture.verify();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out caller must authenticate before verifying a connection.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::with(
            awaiting_verification(),
            VerifyOutcome::Accepts,
            FakeOrgActors::refusing(Refusal::SignedOut),
        );

        let result = fixture.verify();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents connection verification.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let fixture = Fixture::with(
            awaiting_verification(),
            VerifyOutcome::Accepts,
            FakeOrgActors::refusing(Refusal::Forbidden),
        );

        let result = fixture.verify();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
