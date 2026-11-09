//! Fakes for passkeys: the `WebAuthn` verifier, the stored keys and the
//! ceremonies in flight.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::passkey::{
    AuthenticatorType, KeyAttestation, PasskeyCredential, PasskeyCredentialRow, PasskeyPlane,
};
use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
    CeremonySubject, OpenCeremonyParams, PasskeyCeremony, PasskeyCeremonyRow, TargetedPurpose,
};
use ianua_domain::domains::authentication::credentials::password_rules::PasswordDue;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::{Enrolment, SecondFactor};
use ianua_domain::domains::authentication::operations::password_login::LoginCandidate;
use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
use ianua_domain::domains::authentication::sessions::session::{
    Session, SessionOrigin, SessionRow,
};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::identity::account::address::AddressStanding;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::identity::account::vouching::Vouching;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::builders::label;
use ianua_domain::types::{
    CeremonyId, CredentialChange, Email, Fact, Lifetime, PasskeyCredentialId, PasskeyId,
    PasswordHash, SessionId, TenantId, TokenHash, Usage, UserId,
};

use crate::ports::TenantScoped;
use crate::ports::authentication::{
    PasskeyAuthenticationResult, PasskeyCeremonyStore, PasskeyRegistrationResult, PasskeyStore,
    PasskeyVerifier, StartedCeremony,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::{Fake, ReadBeforeWrite, block_on, test_ctx};

/// The state [`FakePasskeyVerifier`] hands the server at the start of every
/// ceremony, and the only state it accepts a response against.
pub const PASSKEY_CEREMONY_STATE: &[u8] = b"server-only-ceremony-state";

/// The bytes of the credential id every key the fakes make or verify has.
pub const PASSKEY_CREDENTIAL_ID: [u8; 4] = [1, 2, 3, 4];

/// [`PASSKEY_CREDENTIAL_ID`] as a credential id.
///
/// # Panics
///
/// Never in practice: the id is four fixed bytes.
#[must_use]
pub fn passkey_credential_id() -> PasskeyCredentialId {
    PasskeyCredentialId::new(PASSKEY_CREDENTIAL_ID.to_vec()).expect("four bytes are a valid id")
}

/// Which verification routine settled a sign-in ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedAs {
    /// Against the keys of a user named up front.
    BoundToUser,
    /// Against whichever key the authenticator offered.
    Discoverable,
}

/// Whether a [`FakePasskeyVerifier`] accepts what it is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Verdict {
    #[default]
    Accepts,
    Refuses,
    AcceptsAStandingCounter,
}

/// `WebAuthn` verifier that accepts any response against
/// [`PASSKEY_CEREMONY_STATE`], the way real verification refuses a signature
/// over another challenge, and records which routine settled each sign-in.
#[derive(Default)]
pub struct FakePasskeyVerifier {
    verdict: Verdict,
    verified_as: Mutex<Vec<VerifiedAs>>,
}

impl FakePasskeyVerifier {
    /// A verifier accepting every response to its own ceremonies.
    #[must_use]
    pub fn succeeding() -> Self {
        Self::default()
    }

    /// A verifier refusing every registration and every sign-in.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            verdict: Verdict::Refuses,
            ..Self::default()
        }
    }

    /// A verifier accepting every sign-in from a copied authenticator: the
    /// signature holds, but the counter it reports never goes up.
    #[must_use]
    pub fn copied_authenticator() -> Self {
        Self {
            verdict: Verdict::AcceptsAStandingCounter,
            ..Self::default()
        }
    }

    /// The routines that settled sign-ins, in order.
    #[must_use]
    pub fn verified_as(&self) -> Vec<VerifiedAs> {
        self.verified_as.lock().unwrap().clone()
    }

    fn ensure_accepted(&self, server_state: &[u8]) -> Result<(), DomainError> {
        if self.verdict == Verdict::Refuses {
            return Err(DomainError::invalid("verification failed"));
        }
        if server_state != PASSKEY_CEREMONY_STATE {
            return Err(DomainError::invalid(
                "the response does not match this ceremony",
            ));
        }
        Ok(())
    }

    fn settle(
        &self,
        how: VerifiedAs,
        server_state: &[u8],
        sign_count: u32,
    ) -> Result<PasskeyAuthenticationResult, DomainError> {
        self.verified_as.lock().unwrap().push(how);
        self.ensure_accepted(server_state)?;
        let new_sign_count = match self.verdict {
            Verdict::AcceptsAStandingCounter => sign_count,
            Verdict::Accepts | Verdict::Refuses => sign_count + 1,
        };
        Ok(PasskeyAuthenticationResult {
            credential_id: passkey_credential_id(),
            new_sign_count,
        })
    }
}

/// A ceremony started with `client_byte` as its public payload.
fn started(client_byte: u8) -> StartedCeremony {
    StartedCeremony {
        client_payload: vec![client_byte; 32],
        server_state: PASSKEY_CEREMONY_STATE.to_vec(),
    }
}

#[async_trait]
impl PasskeyVerifier for FakePasskeyVerifier {
    async fn start_registration(
        &self,
        _: &UserId,
        _: &Email,
    ) -> Result<StartedCeremony, DomainError> {
        Ok(started(0xAA))
    }

    async fn start_authentication(&self, _: &[Vec<u8>]) -> Result<StartedCeremony, DomainError> {
        Ok(started(0xBB))
    }

    async fn start_decoy_authentication(&self, _: &Email) -> Result<StartedCeremony, DomainError> {
        Ok(started(0xBB))
    }

    async fn verify_registration(
        &self,
        server_state: &[u8],
        _: &[u8],
    ) -> Result<PasskeyRegistrationResult, DomainError> {
        self.ensure_accepted(server_state)?;
        Ok(PasskeyRegistrationResult {
            credential_id: passkey_credential_id(),
            public_key: vec![5, 6, 7, 8],
            sign_count: 0,
            authenticator_type: AuthenticatorType::CrossPlatform,
            attestation: KeyAttestation::Unattested,
        })
    }

    async fn verify_authentication(
        &self,
        server_state: &[u8],
        _: &[u8],
        _: &[u8],
        sign_count: u32,
    ) -> Result<PasskeyAuthenticationResult, DomainError> {
        self.settle(VerifiedAs::BoundToUser, server_state, sign_count)
    }

    async fn start_discoverable_authentication(&self) -> Result<StartedCeremony, DomainError> {
        Ok(started(0xDD))
    }

    async fn verify_discoverable_authentication(
        &self,
        server_state: &[u8],
        _: &[u8],
        _: &[u8],
        sign_count: u32,
    ) -> Result<PasskeyAuthenticationResult, DomainError> {
        self.settle(VerifiedAs::Discoverable, server_state, sign_count)
    }
}

/// What a stored passkey is made of, for [`stored_passkey`].
struct StoredKey {
    credential_id: PasskeyCredentialId,
    public_key: Vec<u8>,
    authenticator_type: AuthenticatorType,
    attestation: KeyAttestation,
    name: String,
}

/// A passkey of `owner` registered a moment ago and never used, as
/// storage would hold it.
fn stored_passkey<S: PasskeyPlane>(owner: S::Owner, key: StoredKey) -> PasskeyCredential<S> {
    PasskeyCredential::reconstitute(PasskeyCredentialRow {
        id: PasskeyId::new(),
        user_id: owner,
        credential_id: key.credential_id,
        public_key: key.public_key,
        sign_count: 0,
        authenticator_type: key.authenticator_type,
        attestation: key.attestation,
        name: label(&key.name),
        last_used_at: None,
        created_at: clock::now(),
    })
    .expect("a fresh passkey row rebuilds")
}

/// In-memory passkey store, keeping every credential in its tenant as it
/// was last saved.
#[derive(Default)]
pub struct FakePasskeyStore {
    credentials: Mutex<Vec<(TenantId, PasskeyCredential<ResolvedTenant>)>>,
}

impl FakePasskeyStore {
    /// A store with no passkeys.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store where `user_id` holds, in the test tenant, one cross-platform
    /// key, a "YubiKey", under [`PASSKEY_CREDENTIAL_ID`].
    #[must_use]
    pub fn with_passkey(user_id: UserId) -> Self {
        Self::holding([yubikey(user_id, KeyAttestation::Unattested)])
    }

    /// As [`Self::with_passkey`], but the key's attestation showed it is a
    /// hardware security key.
    #[must_use]
    pub fn with_hardware_key(user_id: UserId) -> Self {
        Self::holding([yubikey(user_id, KeyAttestation::HardwareKey)])
    }

    /// A store where `user_id` holds, in the test tenant, `count` platform
    /// keys named `key_0`, `key_1` and so on.
    ///
    /// # Panics
    ///
    /// Never in practice: each key's id is three fixed bytes.
    #[must_use]
    pub fn with_passkeys(user_id: UserId, count: u8) -> Self {
        Self::holding((0..count).map(|i| {
            stored_passkey(
                user_id,
                StoredKey {
                    credential_id: PasskeyCredentialId::new(vec![i, i, i])
                        .expect("three bytes are a valid id"),
                    public_key: vec![i],
                    authenticator_type: AuthenticatorType::Platform,
                    attestation: KeyAttestation::Unattested,
                    name: format!("key_{i}"),
                },
            )
        }))
    }

    /// A store holding `credentials` in the test tenant.
    #[must_use]
    pub fn holding(
        credentials: impl IntoIterator<Item = PasskeyCredential<ResolvedTenant>>,
    ) -> Self {
        let tenant_id = test_ctx().tenant_id();
        let store = Self::default();
        store
            .credentials
            .lock()
            .unwrap()
            .extend(credentials.into_iter().map(|key| (tenant_id, key)));
        store
    }

    /// How many passkeys are stored, across tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.credentials.lock().unwrap().len()
    }

    /// The id of the first passkey stored.
    ///
    /// # Panics
    ///
    /// Panics if no passkey is stored.
    #[must_use]
    pub fn first_id(&self) -> PasskeyId {
        *self.credentials.lock().unwrap()[0].1.id()
    }

    fn select(
        &self,
        tenant_id: &ScopedTenant,
        matches: impl Fn(&PasskeyCredential<ResolvedTenant>) -> bool,
    ) -> Vec<PasskeyCredential<ResolvedTenant>> {
        self.credentials
            .lock()
            .unwrap()
            .iter()
            .filter(|(held_in, key)| held_in == &**tenant_id && matches(key))
            .map(|(_, key)| copy_passkey(key))
            .collect()
    }
}

/// `owner`'s cross-platform "YubiKey" under [`PASSKEY_CREDENTIAL_ID`],
/// attested as `attestation` says, never used.
///
/// # Panics
///
/// Never in practice: the key's fields are fixed and valid.
#[must_use]
pub fn yubikey<S: PasskeyPlane>(
    owner: S::Owner,
    attestation: KeyAttestation,
) -> PasskeyCredential<S> {
    stored_passkey(
        owner,
        StoredKey {
            credential_id: passkey_credential_id(),
            public_key: vec![5, 6, 7, 8],
            authenticator_type: AuthenticatorType::CrossPlatform,
            attestation,
            name: "YubiKey".to_owned(),
        },
    )
}

/// A second YubiKey of `owner`, unattested: a key of its own, so its
/// credential id differs from [`yubikey`]'s, as no two authenticators
/// share one.
///
/// # Panics
///
/// Never: four bytes are a valid credential id.
#[must_use]
pub fn another_yubikey<S: PasskeyPlane>(owner: S::Owner) -> PasskeyCredential<S> {
    stored_passkey(
        owner,
        StoredKey {
            credential_id: PasskeyCredentialId::new(vec![9, 9, 9, 9])
                .expect("four bytes are a valid id"),
            public_key: vec![5, 6, 7, 8],
            authenticator_type: AuthenticatorType::CrossPlatform,
            attestation: KeyAttestation::Unattested,
            name: "YubiKey".to_owned(),
        },
    )
}

/// A copy of `credential`, which does not implement `Clone`.
pub(crate) fn copy_passkey<S: PasskeyPlane>(
    credential: &PasskeyCredential<S>,
) -> PasskeyCredential<S> {
    PasskeyCredential::reconstitute(PasskeyCredentialRow {
        id: *credential.id(),
        user_id: *credential.user_id(),
        credential_id: credential.credential_id().clone(),
        public_key: credential.public_key().to_vec(),
        sign_count: credential.sign_count(),
        authenticator_type: credential.authenticator_type(),
        attestation: credential.attestation(),
        name: credential.name().clone(),
        last_used_at: credential.last_used_at(),
        created_at: credential.created_at(),
    })
    .expect("a live passkey's own row rebuilds")
}

impl TenantScoped for FakePasskeyStore {}

#[async_trait]
impl PasskeyStore for FakePasskeyStore {
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<PasskeyCredential<ResolvedTenant>>, DomainError> {
        Ok(self.select(tenant_id, |key| key.user_id() == user_id))
    }

    async fn find_by_credential_id(
        &self,
        tenant_id: &ScopedTenant,
        credential_id: &PasskeyCredentialId,
    ) -> Result<Option<PasskeyCredential<ResolvedTenant>>, DomainError> {
        Ok(self
            .select(tenant_id, |key| key.credential_id() == credential_id)
            .pop())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        credential: &PasskeyCredential<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut credentials = self.credentials.lock().unwrap();
        credentials.retain(|(_, held)| held.id() != credential.id());
        credentials.push((**tenant_id, copy_passkey(credential)));
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &PasskeyId) -> Result<(), DomainError> {
        self.credentials
            .lock()
            .unwrap()
            .retain(|(held_in, key)| !(held_in == &**tenant_id && key.id() == id));
        Ok(())
    }
}

/// In-memory store for in-flight `WebAuthn` ceremonies.
///
/// Mirrors the real store's two guarantees: a lookup is confined to one
/// tenant, and `mark_consumed` settles a ceremony exactly once, the check a
/// test needs to prove a challenge cannot be replayed.
#[derive(Default)]
pub struct FakePasskeyCeremonyStore {
    ceremonies: Mutex<Vec<PasskeyCeremony>>,
}

impl FakePasskeyCeremonyStore {
    /// A store with nothing in flight.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many ceremonies are being held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ceremonies.lock().unwrap().len()
    }

    /// Whether nothing is in flight.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl PasskeyCeremonyStore for FakePasskeyCeremonyStore {
    async fn save(&self, ceremony: &PasskeyCeremony) -> Result<(), DomainError> {
        self.ceremonies
            .lock()
            .unwrap()
            .push(clone_ceremony(ceremony));
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &TenantId,
        id: &CeremonyId,
    ) -> Result<Option<PasskeyCeremony>, DomainError> {
        Ok(self
            .ceremonies
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.id() == id && held.tenant_id() == tenant_id)
            .map(clone_ceremony))
    }

    async fn mark_consumed(&self, ceremony: &PasskeyCeremony) -> Result<(), DomainError> {
        let mut held = self.ceremonies.lock().unwrap();
        let Some(stored) = held
            .iter_mut()
            .find(|held| held.id() == ceremony.id() && held.tenant_id() == ceremony.tenant_id())
        else {
            return Err(DomainError::invalid("unknown challenge"));
        };
        if stored.consumed_at().is_some() {
            return Err(DomainError::invalid("this challenge has already been used"));
        }
        *stored = clone_ceremony(ceremony);
        Ok(())
    }

    async fn purge_expired(&self) -> Result<u64, DomainError> {
        let mut held = self.ceremonies.lock().unwrap();
        let before = held.len();
        let now = clock::now();
        held.retain(|ceremony| ceremony.consumed_at().is_some() || ceremony.expires_at() >= now);
        Ok(u64::try_from(before - held.len()).unwrap_or(u64::MAX))
    }
}

/// Two answers to one ceremony arriving together: both find it open, and
/// only one may settle it.
#[async_trait]
impl PasskeyCeremonyStore for ReadBeforeWrite<FakePasskeyCeremonyStore> {
    async fn save(&self, ceremony: &PasskeyCeremony) -> Result<(), DomainError> {
        self.live.save(ceremony).await
    }

    async fn find_by_id(
        &self,
        tenant_id: &TenantId,
        id: &CeremonyId,
    ) -> Result<Option<PasskeyCeremony>, DomainError> {
        self.seen.find_by_id(tenant_id, id).await
    }

    async fn mark_consumed(&self, ceremony: &PasskeyCeremony) -> Result<(), DomainError> {
        self.live.mark_consumed(ceremony).await
    }

    async fn purge_expired(&self) -> Result<u64, DomainError> {
        self.live.purge_expired().await
    }
}

/// A copy of `ceremony`, which does not implement `Clone`.
fn clone_ceremony(ceremony: &PasskeyCeremony) -> PasskeyCeremony {
    PasskeyCeremony::reconstitute(PasskeyCeremonyRow {
        id: *ceremony.id(),
        tenant_id: *ceremony.tenant_id(),
        subject: CeremonySubject::from_stored(ceremony.user_id().copied()),
        purpose: ceremony.purpose(),
        state: ceremony.state_for_storage().to_vec(),
        created_at: ceremony.created_at(),
        expires_at: ceremony.expires_at(),
        usage: Usage::from_stored(ceremony.consumed_at()),
    })
    .expect("a live ceremony's own row rebuilds")
}

impl Fake for Arc<dyn PasskeyStore> {
    fn fake() -> Self {
        Arc::new(FakePasskeyStore::empty())
    }
}

impl Fake for Arc<dyn PasskeyVerifier> {
    fn fake() -> Self {
        Arc::new(FakePasskeyVerifier::succeeding())
    }
}

impl Fake for Arc<dyn PasskeyCeremonyStore> {
    fn fake() -> Self {
        Arc::new(FakePasskeyCeremonyStore::new())
    }
}

/// How long the ceremonies tests open last: five minutes.
///
/// # Panics
///
/// Never: five minutes is a valid lifetime.
#[must_use]
pub fn ceremony_lifetime() -> Lifetime {
    Lifetime::seconds(300).expect("five minutes is a valid lifetime")
}

/// A ceremony opened in the test tenant for `user_id`, for `purpose`, over
/// [`PASSKEY_CEREMONY_STATE`].
#[must_use]
pub fn targeted_ceremony(user_id: UserId, purpose: TargetedPurpose) -> PasskeyCeremony {
    PasskeyCeremony::open(OpenCeremonyParams {
        tenant_id: test_ctx().tenant_id(),
        user_id,
        purpose,
        state: PASSKEY_CEREMONY_STATE.to_vec(),
        ttl: ceremony_lifetime(),
    })
}

/// A sign-in ceremony opened in the test tenant for nobody, over
/// [`PASSKEY_CEREMONY_STATE`].
#[must_use]
pub fn discoverable_ceremony() -> PasskeyCeremony {
    PasskeyCeremony::open_discoverable(
        test_ctx().tenant_id(),
        PASSKEY_CEREMONY_STATE.to_vec(),
        ceremony_lifetime(),
    )
}

/// Keeps `ceremony` in `store` and hands back its id.
///
/// # Panics
///
/// Never: the fake store keeps every ceremony.
#[must_use]
pub fn kept_ceremony(store: &FakePasskeyCeremonyStore, ceremony: &PasskeyCeremony) -> CeremonyId {
    let id = *ceremony.id();
    block_on(store.save(ceremony)).expect("the fake store keeps every ceremony");
    id
}

/// What a sign-in by address finds for `user_id`, holding `email`: an
/// active account with a verified address and a passkey.
///
/// # Panics
///
/// If `email` is not a valid address. Tests pass literals that are.
#[must_use]
pub fn passkey_owner(user_id: UserId, email: &str) -> (Email, LoginCandidate) {
    let candidate = LoginCandidate {
        user_id,
        password_hash: PasswordHash::from_stored("hash".to_owned()),
        status: UserStatus::Active,
        email_standing: AddressStanding::Verified,
        enrolment: Enrolment::Enrolled,
        vouching: Vouching::Absent,
        password_due: PasswordDue::Current,
    };
    (Email::new(email).expect("a valid address"), candidate)
}

/// The refresh token of [`sign_in_waiting_for_a_factor`], as the browser
/// holds it.
pub const WAITING_REFRESH_TOKEN: &str = "fake_refresh_waiting";

/// The hash the session store keeps of [`WAITING_REFRESH_TOKEN`], as the
/// fake token generator makes it.
#[must_use]
pub fn waiting_refresh_hash() -> TokenHash {
    TokenHash::from_stored("fake_hash_waiting".to_owned())
}

/// `user_id`'s password sign-in, just begun in the test tenant, waiting
/// for them to set up the second factor the workspace requires.
///
/// # Panics
///
/// Never: a fresh sign-in owing a factor to set up is a consistent row.
#[must_use]
pub fn sign_in_waiting_for_a_factor(user_id: UserId) -> Session<ResolvedTenant> {
    let now = clock::now();
    Session::reconstitute(SessionRow {
        id: SessionId::new(),
        user_id,
        refresh_token_hash: waiting_refresh_hash(),
        parent_id: SessionOrigin::SignIn,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        signed_in_from: Fact::Unknown,
        progress: SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::Enrol,
        },
        status: SessionStatus::Active,
        channel: SessionChannel::Dashboard,
        signed_in_at: now,
        created_at: now,
        last_active_at: now,
        expires_at: now + time::Duration::hours(8),
        kept_through: CredentialChange::Never,
        last_use: Fact::Unknown,
    })
    .expect("a fresh sign-in owing a factor to set up is a consistent row")
}
