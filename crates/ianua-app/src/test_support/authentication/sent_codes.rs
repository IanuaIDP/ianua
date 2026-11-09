//! Fakes for codes sent for a second factor: the store keeping the latest
//! one, the generator making them, and a sender that records what it sent.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::mfa::one_time_code::{OneTimeCode, OneTimeCodeRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Lifetime, Locale, Preference, PrincipalId, TokenHash, Usage, UserId};

use crate::ports::TenantScoped;
use crate::ports::authentication::{
    CodeDestination, FactorCodeSender, OutgoingCode, SentCodeGenerator, SentCodeStore,
    TextAvailability, TextMessaging,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authentication::Plane;

/// The code [`FakeSentCodeGenerator`] makes every time.
pub const SENT_CODE: &str = "246810";

/// Makes [`SENT_CODE`] every time and hashes a code as `sent_` followed by
/// it, so a test can tell a right code from a wrong one by its hash.
pub struct FakeSentCodeGenerator;

impl SentCodeGenerator for FakeSentCodeGenerator {
    fn generate(&self) -> Result<Secret, DomainError> {
        Ok(Secret::new(SENT_CODE))
    }

    fn hash(&self, code: &Secret) -> TokenHash {
        TokenHash::from_stored(format!("sent_{}", code.expose()))
    }
}

/// In-memory store of the latest code sent for each person, kept as its
/// row, so wrong tries and spending persist between calls.
#[derive(Default)]
pub struct FakeSentCodeStore {
    codes: Mutex<Vec<(Plane, OneTimeCodeRow)>>,
}

impl FakeSentCodeStore {
    /// No code was sent to anyone.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The test tenant holds [`SENT_CODE`], just sent for `factor` and good
    /// for five minutes.
    ///
    /// # Panics
    ///
    /// Panics if `factor` takes no sent code, which no test passes.
    #[must_use]
    pub fn sent_for(factor: &MfaEnrollment<ResolvedTenant>) -> Self {
        let lifetime = Lifetime::seconds(300).expect("five minutes is a lifetime");
        let hash = FakeSentCodeGenerator.hash(&Secret::new(SENT_CODE));
        let code =
            OneTimeCode::issue(factor, hash, lifetime).expect("a test sends for a sent factor");
        let store = Self::default();
        store.put(Plane::test_tenant(), &code);
        store
    }

    /// The latest code kept for `user_id` in the test tenant.
    #[must_use]
    pub fn latest_of(&self, user_id: UserId) -> Option<OneTimeCode<ResolvedTenant>> {
        self.find(Plane::test_tenant(), user_id.into())
    }

    fn put(&self, plane: Plane, code: &OneTimeCode<ResolvedTenant>) {
        let mut codes = self.codes.lock().unwrap();
        codes.retain(|(held_on, row)| !(*held_on == plane && row.subject_id == code.subject_id()));
        codes.push((plane, row_of(code)));
    }

    fn find(&self, plane: Plane, subject: PrincipalId) -> Option<OneTimeCode<ResolvedTenant>> {
        self.codes
            .lock()
            .unwrap()
            .iter()
            .find(|(held_on, row)| *held_on == plane && row.subject_id == subject)
            .map(|(_, row)| OneTimeCode::reconstitute(copy_row(row)).expect("a kept code rebuilds"))
    }
}

/// The row storage would keep for `code`.
fn row_of(code: &OneTimeCode<ResolvedTenant>) -> OneTimeCodeRow {
    OneTimeCodeRow {
        subject_id: code.subject_id(),
        enrolled_at: code.enrolled_at(),
        method: code.method(),
        code_hash: code.code_hash().clone(),
        issued_at: code.issued_at(),
        expires_at: code.expires_at(),
        wrong_tries: code.wrong_tries(),
        usage: Usage::from_stored(code.spent_at()),
    }
}

/// A copy of `row`, which does not implement `Clone`.
fn copy_row(row: &OneTimeCodeRow) -> OneTimeCodeRow {
    OneTimeCodeRow {
        subject_id: row.subject_id,
        enrolled_at: row.enrolled_at,
        method: row.method,
        code_hash: row.code_hash.clone(),
        issued_at: row.issued_at,
        expires_at: row.expires_at,
        wrong_tries: row.wrong_tries,
        usage: row.usage,
    }
}

impl TenantScoped for FakeSentCodeStore {}

#[async_trait]
impl SentCodeStore for FakeSentCodeStore {
    async fn latest(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<OneTimeCode<ResolvedTenant>>, DomainError> {
        Ok(self.find(Plane::of(tenant_id), (*user_id).into()))
    }

    async fn hold_latest(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<OneTimeCode<ResolvedTenant>>, DomainError> {
        Ok(self.find(Plane::of(tenant_id), (*user_id).into()))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        code: &OneTimeCode<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.put(Plane::of(tenant_id), code);
        Ok(())
    }
}

/// One message a [`RecordingCodeSender`] handed over: where it went and the
/// code it carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMessage {
    /// The address or number it went to.
    pub to: String,
    /// The code it carried.
    pub code: String,
    /// The language it was written in.
    pub locale: Preference<Locale>,
}

/// Records every code it is asked to send, and sends nothing.
#[derive(Default)]
pub struct RecordingCodeSender {
    /// What was sent, in order.
    pub sent: Mutex<Vec<SentMessage>>,
}

impl RecordingCodeSender {
    /// What was sent so far.
    #[must_use]
    pub fn messages(&self) -> Vec<SentMessage> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl FactorCodeSender for RecordingCodeSender {
    async fn send(
        &self,
        to: CodeDestination<'_>,
        outgoing: OutgoingCode<'_>,
    ) -> Result<(), DomainError> {
        let to = match to {
            CodeDestination::Mail(email) => email.as_str().to_owned(),
            CodeDestination::Text(number) => number.as_str().to_owned(),
        };
        self.sent.lock().unwrap().push(SentMessage {
            to,
            code: outgoing.code.expose().to_owned(),
            locale: outgoing.locale.clone(),
        });
        Ok(())
    }
}

/// A sender whose provider never answers in time.
pub struct UnreachableCodeSender;

#[async_trait]
impl FactorCodeSender for UnreachableCodeSender {
    async fn send(
        &self,
        _to: CodeDestination<'_>,
        _outgoing: OutgoingCode<'_>,
    ) -> Result<(), DomainError> {
        Err(DomainError::infra_msg(
            "the provider did not answer in time",
        ))
    }
}

impl Fake for Arc<dyn SentCodeStore> {
    fn fake() -> Self {
        Arc::new(FakeSentCodeStore::empty())
    }
}

impl Fake for Arc<dyn SentCodeGenerator> {
    fn fake() -> Self {
        Arc::new(FakeSentCodeGenerator)
    }
}

impl Fake for Arc<dyn FactorCodeSender> {
    fn fake() -> Self {
        Arc::new(RecordingCodeSender::default())
    }
}

/// A deployment that can text codes, or one with no provider set up.
pub struct FakeTextMessaging(pub TextAvailability);

impl FakeTextMessaging {
    /// A deployment with no text message provider.
    #[must_use]
    pub fn not_set_up() -> Arc<dyn TextMessaging> {
        Arc::new(Self(TextAvailability::NotSetUp))
    }
}

impl TextMessaging for FakeTextMessaging {
    fn availability(&self) -> TextAvailability {
        self.0
    }
}

impl Fake for Arc<dyn TextMessaging> {
    fn fake() -> Self {
        Arc::new(FakeTextMessaging(TextAvailability::Available))
    }
}
