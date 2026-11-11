//! Finish connection: the dashboard, with the person's session, finishes a
//! connection the service answered, with the one-time code the browser
//! brought back, and the account is connected with the credential the
//! service issued.
//!
//! Only the person who began it may. Mallory begins a connection and sends
//! Bob the link; Bob signs in at GitHub and his dashboard finishes it as
//! Bob. He is refused, the connection is spent, and the refusal is
//! recorded, so his token never lands in Mallory's tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::account::connection::{
    Finished, FinishedConnection, PendingConnection,
};
use ianua_domain::domains::workflows::account::{ConnectAccountParams, IntegrationAccount};
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{IntegrationAccountId, PendingConnectionId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{
    AccountVerifier, ConnectionSecrets, IntegrationAccountStore, PendingConnectionStore,
};
use crate::services::kept_together::kept_together;
use crate::services::sealing::{opened_text, sealed_text};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::accounts::connect::{
    ensure_credential_works, integration_credential_place,
};
use crate::use_cases::workflows::accounts::connections::lookup::{
    existing_connection, issued_credential_place,
};

/// Which connection to finish, with the one-time code the browser brought
/// back. Holds the code, so it has no `Debug`.
pub struct FinishRequest {
    /// The pending exchange to complete under the caller's session.
    pub connection_id: PendingConnectionId,
    /// The one-time code.
    pub code: Secret,
}

/// The ports [`FinishUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct FinishPorts {
    /// Keeps the connections.
    pub connections: Arc<dyn PendingConnectionStore>,
    /// Keeps the accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Asks the integration whether the credential works.
    pub verifier: Arc<dyn AccountVerifier>,
    /// Digests the one-time code.
    pub secrets: Arc<dyn ConnectionSecrets>,
    /// Opens the service's credential and seals it for the account.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Keeps the spent connection, the account and their records together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Finishes account connections.
pub struct FinishUseCase {
    ports: FinishPorts,
}

impl FinishUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: FinishPorts) -> Self {
        Self { ports }
    }

    /// The account `finished` describes, under a fresh id, its credential
    /// opened from the connection and sealed for the account, once the
    /// service vouched for it.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the service refused the credential.
    /// - `AppError::Upstream` when the service could not be asked.
    /// - `AppError::Internal` when the credential cannot be opened or
    ///   sealed.
    async fn params(
        &self,
        tenant: &ScopedTenant,
        connection_id: &PendingConnectionId,
        finished: FinishedConnection,
    ) -> Result<ConnectAccountParams, AppError> {
        let credential = self.vouched(tenant, connection_id, &finished).await?;
        let id = IntegrationAccountId::new();
        let sealed = sealed_text(
            self.ports.encryptor.as_ref(),
            credential.expose(),
            &integration_credential_place(tenant, &id),
        )
        .await?;
        Ok(ConnectAccountParams {
            id,
            integration: finished.integration,
            name: finished.name,
            credential: sealed,
            sharing: finished.sharing,
            scope: finished.scope,
        })
    }

    /// The credential `finished` holds, opened from the connection, once
    /// the service vouched for it, or what vouching replaced it with.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the service refused the credential.
    /// - `AppError::Upstream` when the service could not be asked.
    /// - `AppError::Internal` when the credential cannot be opened.
    async fn vouched(
        &self,
        tenant: &ScopedTenant,
        connection_id: &PendingConnectionId,
        finished: &FinishedConnection,
    ) -> Result<Secret, AppError> {
        let credential = opened_text(
            self.ports.encryptor.as_ref(),
            &finished.credential,
            &issued_credential_place(tenant, connection_id),
        )
        .await
        .or_internal()?;
        ensure_credential_works(
            self.ports.verifier.as_ref(),
            &finished.integration,
            &credential,
        )
        .await
    }

    /// Keeps the spent `connection` and the refusal it recorded, together,
    /// and the error the person who tried is told.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when they cannot be kept.
    async fn refused(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        connection: &mut PendingConnection<ResolvedTenant>,
    ) -> Result<AppError, AppError> {
        let tenant = ctx.tenant();
        let events = connection.take_events(&tenant);
        kept_together(self.ports.unit_of_work.as_ref(), async {
            self.ports
                .connections
                .save(&tenant, connection)
                .await
                .or_internal()?;
            auditor
                .dispatch_by(&ctx.actor(), events)
                .await
                .or_internal()
        })
        .await?;
        Ok(AppError::Forbidden(message!(
            "workflows-only-the-person-who-began-it-finishes-a-connection",
            "only the person who began connecting the account may finish it"
        )))
    }

    /// Keeps the spent `connection`, the new `account` and what both
    /// recorded, together.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when they cannot be kept.
    async fn keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        connection: &mut PendingConnection<ResolvedTenant>,
        account: &mut IntegrationAccount<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        kept_together(self.ports.unit_of_work.as_ref(), async {
            self.ports
                .connections
                .save(&tenant, connection)
                .await
                .or_internal()?;
            self.ports
                .accounts
                .save(&tenant, account)
                .await
                .or_internal()?;
            let mut events = connection.take_events(&tenant);
            events.extend(account.take_events(&tenant));
            auditor
                .dispatch_by(&ctx.actor(), events)
                .await
                .or_internal()
        })
        .await
    }
}

impl Command for FinishUseCase {
    type Caller = CallerContext;
    type Input = FinishRequest;
    type Output = Result<IntegrationAccount<ResolvedTenant>, AppError>;

    /// Finishes the connection for the person `ctx` names, connecting the
    /// account it was begun for, owned by them.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing tenant connection.
    /// - `AppError::Forbidden` for a wrong code or a caller other than the initiator; the latter spends the connection.
    /// - `AppError::Conflict` for expiry, no service answer or prior completion; `Domain` for a refused credential.
    /// - `AppError::Upstream` for an unreachable service; `Internal` on sealing, storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: FinishRequest,
    ) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::ConnectAccounts)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut connection = existing_connection(
            self.ports.connections.as_ref(),
            &tenant,
            &request.connection_id,
        )
        .await?;
        let code = self.ports.secrets.digest(&request.code);
        let finished = connection
            .finish(&code, &control)
            .map_err(AppError::from_domain)?;
        let Finished::Connect(finished) = finished else {
            return Err(self.refused(ctx, auditor, &mut connection).await?);
        };
        let params = self
            .params(&tenant, &request.connection_id, finished)
            .await?;
        let mut account =
            IntegrationAccount::connect(params, &control).map_err(AppError::from_domain)?;
        self.keep(ctx, auditor, &mut connection, &mut account)
            .await?;
        Ok(account)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::account::connection::{ConnectionRequest, ServicePlace};
    use ianua_domain::domains::workflows::account::{AccountSharing, OperationScope};
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
    use ianua_domain::types::{Label, OrganizationId, UserId};

    use super::*;
    use crate::context::CallerContext;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeAccountVerifier, FakeConnectionSecrets, FakeIntegrationAccountStore,
        FakePendingConnectionStore, FakeServiceSignIn, account_credential_place,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with,
    };
    use crate::use_cases::workflows::accounts::connections::{
        AnswerPorts, AnswerRequest, AnswerUseCase, Answered, BeginPorts, BeginUseCase, Begun,
    };

    /// The token GitHub issues for the code it sends back.
    const ISSUED: &str = "github token issued for ann";

    /// One connection's journey: the stores and the service it goes through.
    struct Journey {
        connections: Arc<FakePendingConnectionStore>,
        accounts: Arc<FakeIntegrationAccountStore>,
        sign_in: Arc<FakeServiceSignIn>,
        secrets: Arc<FakeConnectionSecrets>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Journey {
        fn new() -> Self {
            Self {
                connections: Arc::new(FakePendingConnectionStore::empty()),
                accounts: Arc::new(FakeIntegrationAccountStore::empty()),
                sign_in: Arc::new(FakeServiceSignIn::issuing("github", "github code", ISSUED)),
                secrets: Arc::new(FakeConnectionSecrets::default()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The test caller begins connecting the team's GitHub.
        fn begin(&self, integration: &str) -> Result<Begun, AppError> {
            self.begin_in(integration, None)
        }

        /// The test caller begins connecting `integration`, naming `place`.
        fn begin_in(&self, integration: &str, place: Option<&str>) -> Result<Begun, AppError> {
            let use_case = BeginUseCase::new(BeginPorts {
                connections: self.connections.clone(),
                sign_in: self.sign_in.clone(),
                secrets: self.secrets.clone(),
                encryptor: Arc::new(FakeEncryptor),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
            });
            let request = ConnectionRequest {
                integration: IntegrationKey::new(integration).unwrap(),
                name: Label::new("name", "Team GitHub").unwrap(),
                sharing: AccountSharing::Tenant,
                scope: OperationScope::All,
                place: place.map(|place| ServicePlace::new(place).unwrap()),
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        /// GitHub sends the browser back with `state` and `code`.
        fn answer(&self, state: &str, code: &str) -> Result<Answered, AppError> {
            let use_case = AnswerUseCase::new(AnswerPorts {
                states: self.connections.clone(),
                connections: self.connections.clone(),
                sign_in: self.sign_in.clone(),
                secrets: self.secrets.clone(),
                encryptor: Arc::new(FakeEncryptor),
            });
            let request = AnswerRequest {
                state: Secret::new(state),
                code: Secret::new(code),
            };
            block_on(use_case.execute(&(), &test_auditor(self.sink.clone()), request))
        }

        /// `caller`'s dashboard finishes the connection with `code`.
        fn finish(
            &self,
            caller: &CallerContext,
            answered: &Answered,
            code: &str,
        ) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
            let verifier = FakeAccountVerifier::answering(AccountCheck::Accepted);
            self.finish_checked_by(verifier, caller, answered, code)
        }

        /// `caller`'s dashboard finishes the connection with `code`, the
        /// credential checked by `verifier`.
        fn finish_checked_by(
            &self,
            verifier: FakeAccountVerifier,
            caller: &CallerContext,
            answered: &Answered,
            code: &str,
        ) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
            let use_case = FinishUseCase::new(FinishPorts {
                connections: self.connections.clone(),
                accounts: self.accounts.clone(),
                verifier: Arc::new(verifier),
                secrets: self.secrets.clone(),
                encryptor: Arc::new(FakeEncryptor),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
                ..FinishPorts::fakes()
            });
            let request = FinishRequest {
                connection_id: answered.connection_id,
                code: Secret::new(code),
            };
            block_on(use_case.execute(caller, &test_auditor(self.sink.clone()), request))
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// A journey through Azure DevOps, whose sign-in asks for the
    /// organization.
    fn through_azure() -> Journey {
        Journey {
            sign_in: Arc::new(
                FakeServiceSignIn::issuing("azure-devops", "azure code", ISSUED)
                    .asking_for("organization"),
            ),
            ..Journey::new()
        }
    }

    /// Bob connects Azure DevOps naming the organization `contoso`; the
    /// code is swapped for `contoso`, so the account works there.
    #[test]
    fn the_organization_named_reaches_the_exchange() {
        let journey = through_azure();

        journey.begin_in("azure-devops", Some("contoso")).unwrap();
        journey.answer("value-1", "azure code").unwrap();

        assert_eq!(journey.sign_in.places(), [Some("contoso".to_owned())]);
    }

    /// An Azure DevOps connection missing its organization and a GitHub
    /// connection supplying one are both refused without audit events.
    #[test]
    fn a_place_left_out_or_not_asked_for_is_refused() {
        let azure = through_azure();
        let github = Journey::new();

        let without = azure.begin_in("azure-devops", None);
        let needless = github.begin_in("github", Some("contoso"));

        assert!(matches!(without, Err(AppError::Domain(_))));
        assert!(matches!(needless, Err(AppError::Domain(_))));
        assert!(azure.records().is_empty());
        assert!(github.records().is_empty());
    }

    /// The test caller's colleague in the same tenant.
    fn colleague() -> CallerContext {
        let caller = test_ctx();
        test_ctx_with(
            OrganizationId::from_uuid(*caller.organization_id().as_uuid()),
            caller.tenant_id(),
            UserId::new(),
        )
    }

    /// Ann begins connecting GitHub: her browser is sent to GitHub with the
    /// state. GitHub sends it back with a code, swapped at once with the
    /// verifier made for it. Ann's dashboard finishes with the one-time
    /// code: the account is kept with GitHub's token sealed for it, and
    /// the start and the connection are recorded.
    #[test]
    fn ann_signs_in_at_github_and_the_account_is_connected() {
        let journey = Journey::new();

        let begun = journey.begin("github").unwrap();
        let answered = journey.answer("value-1", "github code").unwrap();
        let account = journey
            .finish(&test_ctx(), &answered, answered.code.expose())
            .unwrap();

        assert!(begun.address.as_str().ends_with("state=value-1"));
        assert_eq!(
            journey.sign_in.swapped(),
            [("github code".to_owned(), "value-2".to_owned())]
        );
        let kept = journey.accounts.stored(account.id()).unwrap();
        assert_eq!(
            kept.credential(),
            &FakeEncryptor::sealed_for(ISSUED, &account_credential_place(account.id()))
        );
        assert_eq!(
            journey.records(),
            [
                "workflows.account_connection_started",
                "workflows.account_connected"
            ]
        );
    }

    /// Tess signs in at Atlassian, whose grants rotate: checking the grant
    /// replaces it, so the account keeps the replacement, not the grant the
    /// check retired.
    #[test]
    fn a_grant_replaced_by_the_check_is_the_one_kept() {
        let journey = Journey::new();
        journey.begin("github").unwrap();
        let answered = journey.answer("value-1", "github code").unwrap();
        let rotating =
            FakeAccountVerifier::answering(AccountCheck::Accepted).replacing_with("the next grant");

        let account = journey
            .finish_checked_by(rotating, &test_ctx(), &answered, answered.code.expose())
            .unwrap();

        let kept = journey.accounts.stored(account.id()).unwrap();
        assert_eq!(
            kept.credential(),
            &FakeEncryptor::sealed_for("the next grant", &account_credential_place(account.id()))
        );
    }

    /// A colleague cannot finish the initiator's connection. The refusal is
    /// recorded, no account is saved and the initiator's later attempt also fails.
    #[test]
    fn someone_other_than_the_person_who_began_it_is_refused() {
        let journey = Journey::new();
        journey.begin("github").unwrap();
        let answered = journey.answer("value-1", "github code").unwrap();

        let by_bob = journey.finish(&colleague(), &answered, answered.code.expose());
        let then_ann = journey.finish(&test_ctx(), &answered, answered.code.expose());

        assert!(matches!(by_bob, Err(AppError::Forbidden(_))));
        assert!(matches!(
            then_ann,
            Err(AppError::Domain(_) | AppError::Conflict(_))
        ));
        assert_eq!(journey.accounts.count(), 0);
        assert!(
            journey
                .records()
                .contains(&"workflows.account_connection_refused".to_owned())
        );
    }

    /// GitHub's answer for Ann's connection comes back a second time with
    /// the same state, as a replayed callback address does. The second is
    /// refused as already answered before any code is swapped, so GitHub
    /// is asked once.
    #[test]
    fn a_replayed_answer_is_refused_before_the_service_is_asked_again() {
        let journey = Journey::new();
        journey.begin("github").unwrap();
        journey.answer("value-1", "github code").unwrap();

        let replayed = journey.answer("value-1", "github code");

        assert!(matches!(
            replayed,
            Err(AppError::Conflict(_) | AppError::Domain(_))
        ));
        assert_eq!(journey.sign_in.swapped().len(), 1, "GitHub was asked once");
    }

    /// An unknown state, refused provider code, guessed finish code and
    /// unsupported integration each fail without saving an account.
    #[test]
    fn a_stray_state_a_refused_code_or_a_guessed_code_connects_nothing() {
        let journey = Journey::new();
        journey.begin("github").unwrap();

        let stray = journey.answer("never begun", "github code");
        let refused = journey.answer("value-1", "stolen code");
        let answered = journey.answer("value-1", "github code").unwrap();
        let guessed = journey.finish(&test_ctx(), &answered, "guessed");
        let unoffered = journey.begin("slack");

        assert!(matches!(stray, Err(AppError::Unauthenticated)));
        assert!(matches!(refused, Err(AppError::Domain(_))));
        assert!(matches!(guessed, Err(AppError::Forbidden(_))));
        assert!(matches!(unoffered, Err(AppError::Domain(_))));
        assert_eq!(journey.accounts.count(), 0);
    }
}
