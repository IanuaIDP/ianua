//! Starting to set up a second factor whose codes are sent: mailed to the
//! account's address, or texted to a number the person gives. The first
//! code goes out at once; typing it back confirms the factor through
//! [`ConfirmUseCase`](crate::use_cases::authentication::mfa::ConfirmUseCase).

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    EnrolledFactor, MfaEnrollment, MfaMethod,
};
use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, PrincipalId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::MfaEnrollmentStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::codes::sent::{
    CodeFor, CodeSent, SentCodePolicy, SentCodePorts,
};
use crate::use_cases::authentication::mfa::enrollment::setup_proof::{
    FactorSetter, NewFactor, SetterPorts, SetupLeave, SetupProof, abandon_enrollment,
    begun_enrollment, offered,
};

/// Where a person wants their codes sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentFactorChoice {
    /// Mailed to the account's address.
    Mail,
    /// Texted to this number, which the first code proves reaches them.
    Text(PhoneNumber),
}

impl SentFactorChoice {
    /// The factor this choice sets up.
    fn factor(self) -> EnrolledFactor {
        match self {
            Self::Mail => EnrolledFactor::EmailCode,
            Self::Text(number) => EnrolledFactor::SmsCode(number),
        }
    }

    /// The kind of factor this choice sets up.
    fn method(&self) -> MfaMethod {
        match self {
            Self::Mail => MfaMethod::EmailCode,
            Self::Text(_) => MfaMethod::SmsCode,
        }
    }
}

/// The factor to set up, and what lets the setter set it up now.
pub struct CodeFactorRequest {
    /// Where the codes go.
    pub choice: SentFactorChoice,
    /// What lets the setter set up a factor now.
    pub proof: SetupProof,
}

/// The ports [`CodeFactorBeginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CodeFactorBeginPorts {
    /// Where enrollments are kept.
    pub enrollment_store: Arc<dyn MfaEnrollmentStore>,
    /// Makes, keeps and sends the first code, and says whether codes can be
    /// texted or mailed here at all.
    pub codes: SentCodePorts,
    /// The tenant, for the factors it offers.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Who sets the factor up, and what lets them.
    pub setter: SetterPorts,
}

/// Starts setting up a factor whose codes are mailed or texted.
pub struct CodeFactorBeginUseCase {
    policy: SentCodePolicy,
    ports: CodeFactorBeginPorts,
}

/// A factor about to be set up: where, for whom and on what leave.
struct CodeSetup<'a> {
    /// The tenant the account is in.
    tenant: &'a ScopedTenant,
    /// The account setting it up.
    account: &'a User<ResolvedTenant>,
    /// What lets them set it up now.
    leave: &'a SetupLeave,
}

impl CodeFactorBeginUseCase {
    /// A use case sending codes under `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: SentCodePolicy, ports: CodeFactorBeginPorts) -> Self {
        Self { policy, ports }
    }

    /// Gives up the account's setup still waiting to be confirmed, so the
    /// new one replaces it. A factor in force is a conflict.
    async fn clear_the_way(&self, setup: &CodeSetup<'_>) -> Result<(), AppError> {
        let held = self
            .ports
            .enrollment_store
            .hold_by_user(setup.tenant, setup.account.id())
            .await
            .or_internal()?;
        let Some(mut enrollment) = held else {
            return Ok(());
        };
        if enrollment.is_active() {
            return Err(AppError::Conflict(message!(
                "authentication-mfa-is-already-enrolled",
                "MFA is already enrolled"
            )));
        }
        if !enrollment.is_pending() {
            return Ok(());
        }
        abandon_enrollment(&mut enrollment, setup.leave)?;
        self.ports
            .enrollment_store
            .save(setup.tenant, &enrollment)
            .await
            .or_internal()
    }

    /// The new pending factor, saved, with its start recorded by the
    /// account's holder.
    async fn begun(
        &self,
        auditor: &RequestAuditor,
        setup: &CodeSetup<'_>,
        new: NewFactor<'_>,
    ) -> Result<MfaEnrollment<ResolvedTenant>, AppError> {
        let subject = PrincipalId::from(*setup.account.id());
        let mut enrollment = begun_enrollment(subject, new, setup.leave)?;
        self.ports
            .enrollment_store
            .save(setup.tenant, &enrollment)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::User(*setup.account.id()),
                enrollment.take_events(setup.tenant),
            )
            .await
            .or_internal()?;
        Ok(enrollment)
    }

    /// Sends the first code for `enrollment` to the account `setup` names,
    /// and records that it went out.
    ///
    /// # Errors
    ///
    /// - `AppError::TooManyRequests` when a code went out moments ago.
    /// - `AppError::Internal` on storage, sending or audit failure.
    async fn first_code_sent(
        &self,
        auditor: &RequestAuditor,
        setup: &CodeSetup<'_>,
        enrollment: &MfaEnrollment<ResolvedTenant>,
    ) -> Result<CodeSent, AppError> {
        let to = CodeFor {
            tenant: setup.tenant,
            account: setup.account,
            factor: enrollment,
        };
        let (sent, events) = self.ports.codes.send(to, self.policy).await?;
        auditor.dispatch(&events).await.or_internal()?;
        Ok(sent)
    }
}

impl Command for CodeFactorBeginUseCase {
    type Caller = FactorSetter;
    type Input = CodeFactorRequest;
    type Output = Result<CodeSent, AppError>;

    /// Starts setting up `setter`'s mailed or texted codes on `request.proof`
    /// and sends the first code, recording
    /// `authentication.mfa_enrollment_started` and
    /// `authentication.mfa_code_sent`.
    ///
    /// A setup still waiting to be confirmed is given up first. Only a kind
    /// of factor the tenant offers, and that reaches its baseline, is set up:
    /// Ann's tenant asks for AAL2, so mailed codes, which reach AAL1, are not
    /// offered there.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid setter session; `Forbidden` for an unoffered/undeliverable factor or inadequate setup proof.
    /// - `AppError::StepUpRequired` when a held factor's code is needed.
    /// - `AppError::NotFound` for a missing tenant, account or waiting session; `Conflict` for an active factor.
    /// - `AppError::TooManyRequests` when a code was just sent; `Internal` on storage, delivery or audit failure.
    async fn execute(
        &self,
        setter: &FactorSetter,
        auditor: &RequestAuditor,
        request: CodeFactorRequest,
    ) -> Result<CodeSent, AppError> {
        let CodeFactorRequest { choice, proof } = request;
        let (tenant, account) = self.ports.setter.accounts().account(setter).await?;
        let workspace = existing_tenant(self.ports.tenant_store.as_ref(), &tenant).await?;
        let offer = offered(&workspace, choice.method())?;
        self.ports
            .codes
            .channels()
            .ensure_deliverable(choice.method())?;
        let leave = self
            .ports
            .setter
            .leaves()
            .leave(setter, &account, proof)
            .await?;
        let setup = CodeSetup {
            tenant: &tenant,
            account: &account,
            leave: &leave,
        };
        self.clear_the_way(&setup).await?;
        let new = NewFactor {
            factor: choice.factor(),
            offer: &offer,
        };
        let enrollment = self.begun(auditor, &setup, new).await?;
        self.first_code_sent(auditor, &setup, &enrollment).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::MfaPolicy;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::types::Lifetime;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeSentCodeStore, FakeTextMessaging, RecordingCodeSender,
        SENT_CODE, right_password, test_caller_id, wrong_password,
    };
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{
        FakeEventDispatcher, FakeMailSetup, block_on, test_auditor, test_ctx,
    };

    /// Acme's tenant: second factors optional, offering mailed and texted
    /// codes besides an authenticator app.
    fn offering_codes() -> Arc<dyn TenantStore> {
        tenant_store_signing_in_with(TenantAuthSettings {
            mfa_policy: MfaPolicy::Optional,
            second_factors: vec![MfaMethod::Totp, MfaMethod::EmailCode, MfaMethod::SmsCode],
            ..TenantAuthSettings::default()
        })
    }

    fn policy() -> SentCodePolicy {
        SentCodePolicy {
            lifetime: Lifetime::seconds(300).unwrap(),
            resend_after: time::Duration::seconds(30),
        }
    }

    struct Fixture {
        enrollments: Arc<FakeMfaEnrollmentStore>,
        sent: Arc<FakeSentCodeStore>,
        sender: Arc<RecordingCodeSender>,
        audit: Arc<FakeEventDispatcher>,
        ports: CodeFactorBeginPorts,
    }

    impl Fixture {
        fn over(enrollments: FakeMfaEnrollmentStore) -> Self {
            let enrollments = Arc::new(enrollments);
            let sent = Arc::new(FakeSentCodeStore::empty());
            let sender = Arc::new(RecordingCodeSender::default());
            Self {
                ports: CodeFactorBeginPorts {
                    enrollment_store: enrollments.clone(),
                    codes: SentCodePorts {
                        sent_codes: sent.clone(),
                        sender: sender.clone(),
                        ..SentCodePorts::fakes()
                    },
                    tenant_store: offering_codes(),
                    ..CodeFactorBeginPorts::fakes()
                },
                enrollments,
                sent,
                sender,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn begin(
            self,
            choice: SentFactorChoice,
            proof: SetupProof,
        ) -> (Result<CodeSent, AppError>, Self) {
            let use_case = CodeFactorBeginUseCase::new(policy(), self.ports);
            let setter = FactorSetter::SignedIn(Box::new(test_ctx()));
            let request = CodeFactorRequest { choice, proof };
            let result =
                block_on(use_case.execute(&setter, &test_auditor(self.audit.clone()), request));
            let fixture = Self {
                ports: use_case.ports,
                ..self
            };
            (result, fixture)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn texts_to(number: &str) -> SentFactorChoice {
        SentFactorChoice::Text(PhoneNumber::new(number).unwrap())
    }

    fn reentered() -> SetupProof {
        SetupProof::Reentered(right_password())
    }

    /// Ann, who typed her password again, sets up texted codes to her
    /// number. A pending factor keeps the number, the first code is texted
    /// there, and both are recorded.
    #[test]
    fn a_texted_factor_starts_with_a_code_to_its_number() {
        let (result, fixture) = Fixture::over(FakeMfaEnrollmentStore::empty())
            .begin(texts_to("+4930123456"), reentered());

        result.unwrap();
        let pending = fixture.enrollments.enrollment_of(test_caller_id()).unwrap();
        assert!(pending.is_pending());
        assert_eq!(pending.method(), MfaMethod::SmsCode);
        let messages = fixture.sender.messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].to, "+4930123456");
        assert_eq!(messages[0].code, SENT_CODE);
        assert!(fixture.sent.latest_of(test_caller_id()).is_some());
        assert_eq!(
            fixture.recorded(),
            [
                "authentication.mfa_enrollment_started",
                "authentication.mfa_code_sent"
            ]
        );
    }

    /// Ann sets up mailed codes. The first code goes to the address her
    /// account holds.
    #[test]
    fn a_mailed_factor_sends_its_first_code_to_the_accounts_address() {
        let (result, fixture) = Fixture::over(FakeMfaEnrollmentStore::empty())
            .begin(SentFactorChoice::Mail, reentered());

        result.unwrap();
        let messages = fixture.sender.messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].to, "caller@example.test");
        assert_eq!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .unwrap()
                .method(),
            MfaMethod::EmailCode
        );
    }

    /// When the tenant offers only authenticator and texted codes, mailed
    /// factor setup is refused without storing enrollment or sending a code.
    #[test]
    fn a_kind_the_tenant_does_not_offer_is_refused() {
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::empty());
        fixture.ports.tenant_store = tenant_store_signing_in_with(TenantAuthSettings {
            mfa_policy: MfaPolicy::Optional,
            second_factors: vec![MfaMethod::Totp, MfaMethod::SmsCode],
            ..TenantAuthSettings::default()
        });

        let (result, fixture) = fixture.begin(SentFactorChoice::Mail, reentered());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .is_none()
        );
        assert!(fixture.sender.messages().is_empty());
    }

    /// Without a text provider, texted factor setup is refused before any
    /// enrollment, message or audit event is saved.
    #[test]
    fn a_texted_factor_is_refused_where_nothing_texts() {
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::empty());
        fixture.ports.codes.text_messaging = FakeTextMessaging::not_set_up();

        let (result, fixture) = fixture.begin(texts_to("+4930123456"), reentered());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .is_none()
        );
        assert!(fixture.sender.messages().is_empty());
        assert!(fixture.recorded().is_empty());
    }

    /// Without mail delivery, mailed factor setup is refused before any
    /// enrollment, message or audit event is saved.
    #[test]
    fn a_mailed_factor_is_refused_where_nothing_is_mailed() {
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::empty());
        fixture.ports.codes.mail = FakeMailSetup::not_set_up();

        let (result, fixture) = fixture.begin(SentFactorChoice::Mail, reentered());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .is_none()
        );
        assert!(fixture.sender.messages().is_empty());
        assert!(fixture.recorded().is_empty());
    }

    /// A wrong password cannot start a texted factor; no enrollment, code
    /// message or audit event is saved.
    #[test]
    fn a_wrong_password_is_refused() {
        let (result, fixture) = Fixture::over(FakeMfaEnrollmentStore::empty()).begin(
            texts_to("+15550100"),
            SetupProof::Reentered(wrong_password()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .is_none()
        );
        assert!(fixture.sender.messages().is_empty());
        assert!(fixture.recorded().is_empty());
    }

    /// Ann already has an authenticator in force. Setting up texted codes as
    /// well is a conflict; she turns the app off first.
    #[test]
    fn a_factor_in_force_is_a_conflict() {
        let (result, fixture) = Fixture::over(FakeMfaEnrollmentStore::active_for(test_caller_id()))
            .begin(texts_to("+4930123456"), reentered());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(fixture.sender.messages().is_empty());
    }

    /// A signed-out caller cannot begin mailed factor enrollment.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::empty());
        fixture.ports.setter.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = fixture.begin(SentFactorChoice::Mail, reentered());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
