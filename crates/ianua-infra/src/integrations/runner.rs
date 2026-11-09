//! Making one action step's call through its installed integration.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::{SealedAt, SecretEncryptor};
use ianua_app::ports::workflows::{ActionRun, ActionRunner, CallCredential, Renewal};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::routing::stream::{LoginTls, TlsAuthority};
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::{AccountNeed, OperationSpec};
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::answer::failed;
use ianua_integration::data::{DataLogin, DataTls, Through, TlsCheck};
use ianua_integration::{Called, Integration, Renewed};

use crate::http::client::LONGEST_CALL;
use crate::integrations::data::DataLink;
use crate::integrations::installed::Installed;

/// Makes action calls through the installed integrations.
///
/// Before anything is called it finds the integration and the operation
/// again, so one withdrawn since the step started is not called, and opens
/// the account's credential itself, handing it only to an operation that
/// acts through an account. Every call is held to a time limit; a call
/// past it may have acted, so it is reported failed, never turned away.
pub struct InstalledActionRunner {
    installed: Arc<Installed>,
    encryptor: Arc<dyn SecretEncryptor>,
    limit: Duration,
    data: Option<DataLink>,
}

impl TenantScoped for InstalledActionRunner {}

impl InstalledActionRunner {
    /// A runner calling through `installed`, opening credentials with
    /// `encryptor`, and giving up on a call after `limit`, at most
    /// [`LONGEST_CALL`].
    #[must_use]
    pub fn new(
        installed: Arc<Installed>,
        encryptor: Arc<dyn SecretEncryptor>,
        limit: Duration,
    ) -> Self {
        Self {
            installed,
            encryptor,
            limit: limit.min(LONGEST_CALL),
            data: None,
        }
    }

    /// The same runner, opening Protected data connections through `link`.
    /// Without one, every Protected data call fails unsent.
    #[must_use]
    pub fn with_data(self, link: DataLink) -> Self {
        Self {
            data: Some(link),
            ..self
        }
    }

    /// The credential the operation acts through, opened, or why the call
    /// cannot be made. An operation needing no account is handed none; one
    /// acting as the run's person is handed its pass and nothing else.
    async fn credential_for(
        &self,
        spec: &OperationSpec,
        credential: CallCredential<'_>,
    ) -> Result<Option<Secret>, ActionOutcome> {
        match (spec.account(), credential) {
            (AccountNeed::NoAccount, _) => Ok(None),
            (AccountNeed::Account, CallCredential::Account(sealed)) => {
                self.opened(sealed).await.map(Some)
            }
            (AccountNeed::Account, CallCredential::Nothing | CallCredential::Pass(_)) => Err(
                failed("the operation acts through an account, and none was handed over"),
            ),
            (AccountNeed::Account, CallCredential::Data(_)) => Err(failed(
                "the operation acts through an account, and a stream route's login was handed over",
            )),
            (AccountNeed::RunPerson, CallCredential::Pass(pass)) => Ok(Some(pass.clone())),
            (
                AccountNeed::RunPerson,
                CallCredential::Nothing | CallCredential::Account(_) | CallCredential::Data(_),
            ) => Err(failed(
                "the operation acts as the run's person, and no pass was handed over",
            )),
            (AccountNeed::RunPersonData, _) => Err(failed(
                "the operation reaches protected data, which is called over a connection",
            )),
            (AccountNeed::TenantMemory, _) => Err(failed(
                "the operation keeps or searches a memory, which the platform runs itself",
            )),
            (AccountNeed::Company, _) => Err(failed(
                "the operation acts on the company itself, which the platform runs itself",
            )),
        }
    }

    /// `call` made through `integration` over a connection to the stream
    /// route its pass names, signing in with the route's login, the whole
    /// held to the time limit. A call handed no login, or made where no
    /// connection can be opened, fails unsent.
    async fn data_call(
        &self,
        integration: &dyn Integration,
        call: &ActionCall,
        credential: CallCredential<'_>,
    ) -> Called {
        let CallCredential::Data(handed) = credential else {
            return failed("the operation reaches protected data, and no login was handed over")
                .into();
        };
        let Some(link) = &self.data else {
            return failed("protected data is not set up on this deployment").into();
        };
        let through = async {
            let password = self.opened(&handed.password).await.map_err(Called::from)?;
            let login = DataLogin {
                user: handed.user.as_str().to_owned(),
                password,
            };
            let opener = Box::new(link.opener(handed.pass.clone()));
            let through = Through::new(opener, login, data_tls(&handed.tls));
            Ok::<_, Called>(integration.call_through(call, through).await)
        };
        match tokio::time::timeout(self.limit, through).await {
            Ok(Ok(called) | Err(called)) => called,
            Err(_) => failed("the integration did not answer in time").into(),
        }
    }

    /// The account's credential, opened for the account it was sealed for,
    /// or the failure when it does not open. The sealer's error is dropped,
    /// so nothing of the credential reaches the step's record.
    async fn opened(&self, sealed: &SealedAt) -> Result<Secret, ActionOutcome> {
        let Ok(bytes) = self.encryptor.decrypt(&sealed.secret, &sealed.place).await else {
            return Err(failed("the account's credential could not be opened"));
        };
        let Ok(text) = String::from_utf8(bytes) else {
            return Err(failed("the account's credential is not text"));
        };
        Ok(Secret::new(text))
    }

    /// `call` made through `integration`, held to the time limit.
    async fn made(
        &self,
        integration: &dyn Integration,
        call: &ActionCall,
        credential: Option<&Secret>,
    ) -> Called {
        tokio::time::timeout(self.limit, integration.call(call, credential))
            .await
            .unwrap_or_else(|_| failed("the integration did not answer in time").into())
    }

    /// The credential the service issued in place of the account's one in
    /// `credential`, sealed for the same account. A renewed credential with
    /// nowhere to be kept, or one that does not seal, is dropped with a
    /// warning; the call itself stands.
    async fn kept(&self, renewed: Renewed, credential: CallCredential<'_>) -> Renewal {
        let Renewed::To(replacement) = renewed else {
            return Renewal::Unchanged;
        };
        let CallCredential::Account(sealed) = credential else {
            tracing::warn!("a service renewed a credential no account was handed for");
            return Renewal::Unchanged;
        };
        match self
            .encryptor
            .encrypt(replacement.expose().as_bytes(), &sealed.place)
            .await
        {
            Ok(renewed) => Renewal::Renewed(renewed),
            Err(error) => {
                tracing::warn!(%error, "a renewed credential could not be sealed");
                Renewal::Unchanged
            }
        }
    }
}

#[async_trait]
impl ActionRunner for InstalledActionRunner {
    async fn run(
        &self,
        _tenant_id: &ScopedTenant,
        call: &ActionCall,
        credential: CallCredential<'_>,
    ) -> ActionRun {
        let Some(integration) = self.installed.find(&call.integration) else {
            return unrenewed(failed("the integration is not installed"));
        };
        let Some(spec) = integration
            .operations()
            .iter()
            .find(|spec| spec.operation() == &call.operation)
        else {
            return unrenewed(failed("the integration no longer offers the operation"));
        };
        if spec.account() == AccountNeed::RunPersonData {
            return unrenewed(self.data_call(integration, call, credential).await.outcome);
        }
        let opened = match self.credential_for(spec, credential).await {
            Ok(opened) => opened,
            Err(refused) => return unrenewed(refused),
        };
        let called = self.made(integration, call, opened.as_ref()).await;
        ActionRun {
            outcome: called.outcome,
            renewal: self.kept(called.renewed, credential).await,
        }
    }
}

/// The protection the SDK hands an integration, as the route's login says.
fn data_tls(tls: &LoginTls) -> DataTls {
    match tls {
        LoginTls::Required(check) => DataTls::Required(TlsCheck::new(
            match check.authority() {
                TlsAuthority::Own(pem) => Some(pem.as_str().to_owned()),
                TlsAuthority::PublicRoots => None,
            },
            check.server_name().as_str().to_owned(),
        )),
        LoginTls::Off => DataTls::Off,
    }
}

/// A run that came to `outcome` without touching the credential.
fn unrenewed(outcome: ActionOutcome) -> ActionRun {
    ActionRun {
        outcome,
        renewal: Renewal::Unchanged,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ianua_app::ports::authentication::{SealOwner, SealedField, SealedFor};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::data::FlowData;
    use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
    use ianua_domain::domains::workflows::integration::guide::OperationGuide;
    use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
    use ianua_domain::domains::workflows::integration::{
        ActionAccount, IntegrationKey, OperationKey,
    };
    use ianua_domain::shared::events::chain::EventOrigin;
    use ianua_domain::types::{
        ActionCallId, DeclaredAction, IntegrationAccountId, SealedSecret, UntrustedText,
    };

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::http::client::InternalLink;
    use crate::integrations::apps::{AppSettings, ProtectedApps};
    use crate::integrations::installed::tests::{guide_of, profile_of, spec};

    /// An integration keeping the credential each call was handed, and
    /// answering with `outcome` after `delay`.
    struct Recording {
        profile: IntegrationProfile,
        operations: Vec<OperationSpec>,
        guides: Vec<OperationGuide>,
        delay: Duration,
        outcome: ActionOutcome,
        renews: Option<String>,
        handed: Mutex<Vec<Option<String>>>,
    }

    #[async_trait]
    impl Integration for Recording {
        fn profile(&self) -> &IntegrationProfile {
            &self.profile
        }

        fn operations(&self) -> &[OperationSpec] {
            &self.operations
        }

        fn guides(&self) -> &[OperationGuide] {
            &self.guides
        }

        async fn check_account(&self, _credential: &Secret) -> AccountCheck {
            AccountCheck::NotCheckable
        }

        async fn call(&self, _call: &ActionCall, credential: Option<&Secret>) -> Called {
            self.handed
                .lock()
                .unwrap()
                .push(credential.map(|secret| secret.expose().to_owned()));
            tokio::time::sleep(self.delay).await;
            Called {
                outcome: self.outcome.clone(),
                renewed: self.renews.as_ref().map_or(Renewed::Unchanged, |to| {
                    Renewed::To(Secret::new(to.clone()))
                }),
            }
        }
    }

    impl Recording {
        /// The integration, renewing the credential to `to` on every call.
        fn renewing(self: Arc<Self>, to: &str) -> Arc<Self> {
            let mut recording = Arc::into_inner(self).unwrap();
            recording.renews = Some(to.to_owned());
            Arc::new(recording)
        }
    }

    fn sealer() -> Arc<AesGcmSecretEncryptor> {
        Arc::new(AesGcmSecretEncryptor::new(
            SealingKey::new("k1", [7; 32]).unwrap(),
            Vec::new(),
        ))
    }

    /// Where the test tenant's account `account` keeps its credential.
    fn account_place(account: IntegrationAccountId) -> SealedFor {
        SealedFor::new(
            SealOwner::from(&tenant()),
            SealedField::IntegrationCredential,
            account,
        )
    }

    /// `credential` sealed by `sealer` for the test tenant's account
    /// `account`.
    async fn sealed_for(
        sealer: &AesGcmSecretEncryptor,
        credential: &[u8],
        account: IntegrationAccountId,
    ) -> SealedAt {
        let place = account_place(account);
        SealedAt {
            secret: sealer.encrypt(credential, &place).await.unwrap(),
            place,
        }
    }

    fn succeeded() -> ActionOutcome {
        ActionOutcome::Succeeded {
            output: FlowData::text("done").unwrap(),
            exposure: DataClassLevel::Internal,
        }
    }

    fn sheets(delay: Duration, outcome: ActionOutcome) -> Arc<Recording> {
        let operations = vec![
            spec("sheets", "append-row", AccountNeed::Account),
            spec("sheets", "status", AccountNeed::NoAccount),
        ];
        Arc::new(Recording {
            profile: profile_of("sheets"),
            guides: operations.iter().map(guide_of).collect(),
            operations,
            delay,
            outcome,
            renews: None,
            handed: Mutex::new(Vec::new()),
        })
    }

    fn runner(integration: Arc<Recording>, limit: Duration) -> InstalledActionRunner {
        let installed = Installed::new(vec![integration as Arc<dyn Integration>]).unwrap();
        InstalledActionRunner::new(Arc::new(installed), sealer(), limit)
    }

    fn call(integration: &str, operation: &str) -> ActionCall {
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new(integration).unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments: FlowData::null(),
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn tenant() -> ScopedTenant {
        crate::test_support::rows::authorization::tenant()
    }

    fn reason(outcome: &ActionOutcome) -> &str {
        match outcome {
            ActionOutcome::Failed(why) | ActionOutcome::TurnedAway(why) => why.as_str(),
            ActionOutcome::Succeeded { .. } | ActionOutcome::NotYet { .. } => "",
        }
    }

    /// The account's credential is opened and handed to the integration,
    /// and the integration's answer is the step's outcome.
    #[tokio::test]
    async fn the_opened_credential_reaches_the_integration() {
        let integration = sheets(Duration::ZERO, succeeded());
        let runner = runner(integration.clone(), Duration::from_secs(5));
        let sealed = sealed_for(&sealer(), b"sheets-api-token", IntegrationAccountId::new()).await;

        let outcome = runner
            .run(
                &tenant(),
                &call("sheets", "append-row"),
                CallCredential::Account(&sealed),
            )
            .await
            .outcome;

        assert_eq!(outcome, succeeded());
        assert_eq!(
            *integration.handed.lock().unwrap(),
            [Some("sheets-api-token".to_owned())]
        );
    }

    /// An operation requiring no account receives no credential even when the
    /// runner was given a sealed account credential.
    #[tokio::test]
    async fn an_operation_without_an_account_is_handed_no_credential() {
        let integration = sheets(Duration::ZERO, succeeded());
        let runner = runner(integration.clone(), Duration::from_secs(5));
        let sealed = sealed_for(&sealer(), b"sheets-api-token", IntegrationAccountId::new()).await;

        runner
            .run(
                &tenant(),
                &call("sheets", "status"),
                CallCredential::Account(&sealed),
            )
            .await;

        assert_eq!(*integration.handed.lock().unwrap(), [None]);
    }

    /// A call naming an uninstalled integration fails without invoking the
    /// installed integration.
    #[tokio::test]
    async fn an_integration_not_installed_fails_the_call() {
        let integration = sheets(Duration::ZERO, succeeded());
        let runner = runner(integration.clone(), Duration::from_secs(5));

        let outcome = runner
            .run(&tenant(), &call("payments", "pay"), CallCredential::Nothing)
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert!(integration.handed.lock().unwrap().is_empty());
    }

    /// A call naming an operation absent from the installed integration fails
    /// without invoking it.
    #[tokio::test]
    async fn an_operation_no_longer_offered_fails_the_call() {
        let integration = sheets(Duration::ZERO, succeeded());
        let runner = runner(integration.clone(), Duration::from_secs(5));

        let outcome = runner
            .run(
                &tenant(),
                &call("sheets", "delete-sheet"),
                CallCredential::Nothing,
            )
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert!(integration.handed.lock().unwrap().is_empty());
    }

    /// An account operation with no credential fails without invoking the
    /// integration.
    #[tokio::test]
    async fn an_account_operation_without_a_credential_fails() {
        let integration = sheets(Duration::ZERO, succeeded());
        let runner = runner(integration.clone(), Duration::from_secs(5));

        let outcome = runner
            .run(
                &tenant(),
                &call("sheets", "append-row"),
                CallCredential::Nothing,
            )
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert!(integration.handed.lock().unwrap().is_empty());
    }

    /// A credential sealed with an unavailable key makes the call fail without
    /// invoking the integration or exposing the token in the failure reason.
    #[tokio::test]
    async fn a_credential_that_does_not_open_fails_the_call() {
        let integration = sheets(Duration::ZERO, succeeded());
        let runner = runner(integration.clone(), Duration::from_secs(5));
        let other = AesGcmSecretEncryptor::new(SealingKey::new("k9", [9; 32]).unwrap(), Vec::new());
        let sealed = sealed_for(&other, b"sheets-api-token", IntegrationAccountId::new()).await;

        let outcome = runner
            .run(
                &tenant(),
                &call("sheets", "append-row"),
                CallCredential::Account(&sealed),
            )
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert!(!reason(&outcome).contains("sheets-api-token"));
        assert!(integration.handed.lock().unwrap().is_empty());
    }

    /// Moving a sealed credential to another account makes the call fail without
    /// invoking the integration.
    #[tokio::test]
    async fn a_credential_moved_to_another_account_fails_the_call() {
        let integration = sheets(Duration::ZERO, succeeded());
        let runner = runner(integration.clone(), Duration::from_secs(5));
        let anns = sealed_for(&sealer(), b"ann-token", IntegrationAccountId::new()).await;
        let in_sams = SealedAt {
            secret: anns.secret,
            place: account_place(IntegrationAccountId::new()),
        };

        let outcome = runner
            .run(
                &tenant(),
                &call("sheets", "append-row"),
                CallCredential::Account(&in_sams),
            )
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert!(integration.handed.lock().unwrap().is_empty());
    }

    /// A call exceeding its timeout produces a failed outcome even when the
    /// integration's delayed answer would turn it away.
    #[tokio::test]
    async fn a_call_past_its_limit_fails_and_is_not_turned_away() {
        let turned = ActionOutcome::TurnedAway(UntrustedText::record("busy"));
        let integration = sheets(Duration::from_secs(5), turned);
        let runner = runner(integration, Duration::from_millis(50));

        let outcome = runner
            .run(
                &tenant(),
                &call("sheets", "status"),
                CallCredential::Nothing,
            )
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
    }

    /// An integration that turned the call away is reported as turned away,
    /// so the step tries again later.
    #[tokio::test]
    async fn a_call_turned_away_is_reported_so() {
        let turned = ActionOutcome::TurnedAway(UntrustedText::record("busy"));
        let integration = sheets(Duration::ZERO, turned.clone());
        let runner = runner(integration, Duration::from_secs(5));

        let outcome = runner
            .run(
                &tenant(),
                &call("sheets", "status"),
                CallCredential::Nothing,
            )
            .await
            .outcome;

        assert_eq!(outcome, turned);
    }

    /// Jira hands out a new refresh grant with each call and the old one
    /// stops working. The runner seals the new one for the same account,
    /// so it opens there and the next call goes through.
    #[tokio::test]
    async fn a_renewed_credential_is_sealed_for_its_account() {
        let integration = sheets(Duration::ZERO, succeeded()).renewing("the new grant");
        let runner = runner(integration, Duration::from_secs(5));
        let account = IntegrationAccountId::new();
        let sealed = sealed_for(&sealer(), b"the old grant", account).await;

        let run = runner
            .run(
                &tenant(),
                &call("sheets", "append-row"),
                CallCredential::Account(&sealed),
            )
            .await;

        let Renewal::Renewed(renewed) = run.renewal else {
            panic!("the renewed credential was not kept");
        };
        let opened = sealer().decrypt(&renewed, &sealed.place).await.unwrap();
        assert_eq!(opened, b"the new grant");
        assert_eq!(run.outcome, succeeded());
    }

    /// A malformed credential produces the runner's fixed opening-failure reason.
    #[tokio::test]
    async fn a_garbled_credential_reports_the_runners_words() {
        let sealed = SealedAt {
            secret: SealedSecret::new("s2.k1.not-a-sealed-value").unwrap(),
            place: account_place(IntegrationAccountId::new()),
        };
        let integration = sheets(Duration::ZERO, succeeded());
        let runner = runner(integration, Duration::from_secs(5));

        let outcome = runner
            .run(
                &tenant(),
                &call("sheets", "append-row"),
                CallCredential::Account(&sealed),
            )
            .await
            .outcome;

        assert_eq!(
            reason(&outcome),
            "the account's credential could not be opened"
        );
    }

    /// An integration declaring what Protected apps declares, each
    /// operation acting as the run's person.
    fn apps() -> Arc<Recording> {
        let declared = ProtectedApps::new(AppSettings {
            gateway: url::Url::parse("http://gateway.internal:8082").unwrap(),
            link: InternalLink::PlainInDevelopment,
            timeout: Duration::from_secs(1),
            most_answer: 1024,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap();
        Arc::new(Recording {
            profile: profile_of("apps"),
            guides: declared.guides().to_vec(),
            operations: declared.operations().to_vec(),
            delay: Duration::ZERO,
            outcome: succeeded(),
            renews: None,
            handed: Mutex::new(Vec::new()),
        })
    }

    /// Ann's run reads her orders app: the pass made for the call is what
    /// the integration is handed.
    #[tokio::test]
    async fn a_pass_reaches_an_operation_acting_as_the_run_s_person() {
        let integration = apps();
        let runner = runner(integration.clone(), Duration::from_secs(5));
        let pass = Secret::new("a pass for one call");

        let outcome = runner
            .run(&tenant(), &call("apps", "get"), CallCredential::Pass(&pass))
            .await
            .outcome;

        assert_eq!(outcome, succeeded());
        assert_eq!(
            *integration.handed.lock().unwrap(),
            [Some("a pass for one call".to_owned())]
        );
    }

    /// Swapping account credentials and run passes makes both calls fail without
    /// invoking either integration.
    #[tokio::test]
    async fn a_pass_and_an_account_are_never_handed_in_each_other_s_place() {
        let (apps, sheets) = (apps(), sheets(Duration::ZERO, succeeded()));
        let sealed = sealed_for(&sealer(), b"sheets-api-token", IntegrationAccountId::new()).await;
        let pass = Secret::new("a pass for one call");

        let app = runner(apps.clone(), Duration::from_secs(5))
            .run(
                &tenant(),
                &call("apps", "get"),
                CallCredential::Account(&sealed),
            )
            .await
            .outcome;
        let sheet = runner(sheets.clone(), Duration::from_secs(5))
            .run(
                &tenant(),
                &call("sheets", "append-row"),
                CallCredential::Pass(&pass),
            )
            .await
            .outcome;

        assert!(matches!(app, ActionOutcome::Failed(_)));
        assert!(matches!(sheet, ActionOutcome::Failed(_)));
        assert!(apps.handed.lock().unwrap().is_empty());
        assert!(sheets.handed.lock().unwrap().is_empty());
    }
}
