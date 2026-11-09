//! In-memory second factors of organization members: their passkeys, the
//! passkey ceremonies still open, and their recovery codes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::passkey::{
    KeyAttestation, PasskeyCredential,
};
use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
    CeremonySubject, TargetedPurpose,
};
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::recovery::codes::{
    RecoveryCode, RecoveryCodeRow, RecoveryCodeSet, RecoveryCodeSetRow,
};
use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::organization::access::passkey::{
    OrgPasskeyCeremony, OrgPasskeyCeremonyRow,
};
use ianua_domain::domains::organization::access::session::{
    OrgSession, OrgSessionRow, SessionPlace,
};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CeremonyId, CredentialChange, Fact, OrgUserId, OrganizationId, PasskeyCredentialId, PasskeyId,
    PrincipalId, SessionId, TenantId, TokenHash, Usage,
};

use crate::ports::organization::{OrgPasskeyCeremonyStore, OrgPasskeyStore, OrgRecoveryCodeStore};
use crate::test_support::authentication::{
    PASSKEY_CEREMONY_STATE, ceremony_lifetime, copy_passkey, waiting_refresh_hash, yubikey,
};
use crate::test_support::{Fake, block_on};

/// A ceremony opened for `member`, for `purpose`, over
/// [`PASSKEY_CEREMONY_STATE`].
#[must_use]
pub fn member_ceremony(member: OrgUserId, purpose: TargetedPurpose) -> OrgPasskeyCeremony {
    OrgPasskeyCeremony::open(
        member,
        purpose,
        PASSKEY_CEREMONY_STATE.to_vec(),
        ceremony_lifetime(),
    )
}

/// A sign-in ceremony opened for nobody, over [`PASSKEY_CEREMONY_STATE`].
#[must_use]
pub fn discoverable_member_ceremony() -> OrgPasskeyCeremony {
    OrgPasskeyCeremony::open_discoverable(PASSKEY_CEREMONY_STATE.to_vec(), ceremony_lifetime())
}

/// Keeps `ceremony` in `store` and hands back its id.
///
/// # Panics
///
/// Never: the fake store keeps every ceremony it is handed.
#[must_use]
pub fn kept_member_ceremony(
    store: &FakeOrgPasskeyCeremonyStore,
    ceremony: &OrgPasskeyCeremony,
) -> CeremonyId {
    let kept = *ceremony.id();
    block_on(store.save(ceremony)).expect("the fake ceremony store keeps what it is handed");
    kept
}

/// `member`'s password sign-in to `tenant_id`, just begun, waiting for
/// them to set up the second factor the organization requires. Its
/// refresh token is the waiting one the passkey fakes name.
///
/// # Panics
///
/// Never: a fresh sign-in owing a factor to set up is a consistent row.
#[must_use]
pub fn member_sign_in_waiting_for_a_factor(member: &OrgUser, tenant_id: TenantId) -> OrgSession {
    let now = clock::now();
    OrgSession::reconstitute(OrgSessionRow {
        id: SessionId::new(),
        org_user_id: *member.id(),
        organization_id: *member.organization_id(),
        place: SessionPlace::Tenant(tenant_id),
        refresh_token_hash: waiting_refresh_hash(),
        progress: SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::Enrol,
        },
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        status: SessionStatus::Active,
        created_at: now,
        last_active_at: now,
        expires_at: now + time::Duration::hours(8),
        kept_through: CredentialChange::Never,
    })
    .expect("a fresh member sign-in owing a factor to set up is a consistent row")
}

/// A copy of `ceremony`, read back the way storage reads it.
fn copy_ceremony(ceremony: &OrgPasskeyCeremony) -> Result<OrgPasskeyCeremony, DomainError> {
    OrgPasskeyCeremony::reconstitute(OrgPasskeyCeremonyRow {
        id: *ceremony.id(),
        subject: CeremonySubject::from_stored(ceremony.org_user_id().copied()),
        purpose: ceremony.purpose(),
        state: ceremony.state_for_storage().to_vec(),
        created_at: ceremony.created_at(),
        expires_at: ceremony.expires_at(),
        usage: Usage::from_stored(ceremony.consumed_at()),
    })
}

/// In-memory store for the passkey ceremonies members have open. Settling
/// one twice is refused, as the real store refuses it.
#[derive(Default)]
pub struct FakeOrgPasskeyCeremonyStore {
    ceremonies: Mutex<Vec<OrgPasskeyCeremony>>,
}

impl FakeOrgPasskeyCeremonyStore {
    /// A store holding no ceremony.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many ceremonies are held, settled ones included.
    #[must_use]
    pub fn count(&self) -> usize {
        self.ceremonies.lock().unwrap().len()
    }
}

#[async_trait]
impl OrgPasskeyCeremonyStore for FakeOrgPasskeyCeremonyStore {
    async fn save(&self, ceremony: &OrgPasskeyCeremony) -> Result<(), DomainError> {
        let copy = copy_ceremony(ceremony)?;
        self.ceremonies.lock().unwrap().push(copy);
        Ok(())
    }

    async fn find_by_id(&self, id: &CeremonyId) -> Result<Option<OrgPasskeyCeremony>, DomainError> {
        self.ceremonies
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.id() == id)
            .map(copy_ceremony)
            .transpose()
    }

    async fn mark_consumed(&self, ceremony: &OrgPasskeyCeremony) -> Result<(), DomainError> {
        let copy = copy_ceremony(ceremony)?;
        let mut ceremonies = self.ceremonies.lock().unwrap();
        let Some(held) = ceremonies
            .iter_mut()
            .find(|held| held.id() == ceremony.id())
        else {
            return Err(DomainError::invalid("unknown challenge"));
        };
        if held.consumed_at().is_some() {
            return Err(DomainError::invalid("this challenge has already been used"));
        }
        *held = copy;
        Ok(())
    }
}

/// A passkey a member registered, with the organization it belongs to.
struct HeldPasskey {
    organization_id: OrganizationId,
    credential: PasskeyCredential<ResolvedOrganization>,
}

/// In-memory store that keeps every passkey members register.
#[derive(Default)]
pub struct FakeOrgPasskeyStore {
    passkeys: Mutex<Vec<HeldPasskey>>,
    member_reads: AtomicUsize,
}

impl FakeOrgPasskeyStore {
    /// How many reads list members' passkeys, including batched reads.
    #[must_use]
    pub fn member_reads(&self) -> usize {
        self.member_reads.load(Ordering::SeqCst)
    }

    /// A store holding no passkey.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding one never-used security key for `org_user_id` of
    /// `organization_id`, under the credential id the passkey fakes use.
    #[must_use]
    pub fn with_passkey(organization_id: OrganizationId, org_user_id: OrgUserId) -> Self {
        Self::holding(
            organization_id,
            [yubikey(org_user_id, KeyAttestation::Unattested)],
        )
    }

    /// A store holding `passkeys`, of members of `organization_id`.
    #[must_use]
    pub fn holding(
        organization_id: OrganizationId,
        passkeys: impl IntoIterator<Item = PasskeyCredential<ResolvedOrganization>>,
    ) -> Self {
        let held = passkeys
            .into_iter()
            .map(|credential| HeldPasskey {
                organization_id,
                credential,
            })
            .collect();
        Self {
            passkeys: Mutex::new(held),
            member_reads: AtomicUsize::default(),
        }
    }

    /// How many passkeys are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.passkeys.lock().unwrap().len()
    }

    /// How many passkeys the members of `organization_id` hold.
    #[must_use]
    pub fn count_in(&self, organization_id: &OrganizationId) -> usize {
        self.passkeys
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.organization_id == *organization_id)
            .count()
    }

    /// The passkey stored under `id`, as last saved.
    #[must_use]
    pub fn stored(&self, id: &PasskeyId) -> Option<PasskeyCredential<ResolvedOrganization>> {
        self.passkeys
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.credential.id() == id)
            .map(|held| copy_passkey(&held.credential))
    }
}

#[async_trait]
impl OrgPasskeyStore for FakeOrgPasskeyStore {
    async fn list_by_users(
        &self,
        org_user_ids: &[OrgUserId],
    ) -> Result<Vec<PasskeyCredential<ResolvedOrganization>>, DomainError> {
        self.member_reads.fetch_add(1, Ordering::SeqCst);
        let mut keys: Vec<_> = self
            .passkeys
            .lock()
            .unwrap()
            .iter()
            .filter(|held| org_user_ids.contains(held.credential.user_id()))
            .map(|held| copy_passkey(&held.credential))
            .collect();
        keys.sort_by_key(|key| (key.created_at(), *key.id().as_uuid()));
        Ok(keys)
    }

    async fn list_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<PasskeyCredential<ResolvedOrganization>>, DomainError> {
        self.member_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .passkeys
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.credential.user_id() == org_user_id)
            .map(|held| copy_passkey(&held.credential))
            .collect())
    }

    async fn find_by_credential_id(
        &self,
        credential_id: &PasskeyCredentialId,
    ) -> Result<Option<PasskeyCredential<ResolvedOrganization>>, DomainError> {
        Ok(self
            .passkeys
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.credential.credential_id() == credential_id)
            .map(|held| copy_passkey(&held.credential)))
    }

    async fn save(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        credential: &PasskeyCredential<ResolvedOrganization>,
    ) -> Result<(), DomainError> {
        if credential.user_id() != org_user_id {
            return Err(DomainError::invalid(
                "a passkey is saved for the member it belongs to",
            ));
        }
        let mut passkeys = self.passkeys.lock().unwrap();
        let taken = passkeys.iter().any(|held| {
            held.credential.credential_id() == credential.credential_id()
                && held.credential.id() != credential.id()
        });
        if taken {
            return Err(DomainError::conflict("this passkey is registered already"));
        }
        passkeys.retain(|held| held.credential.id() != credential.id());
        passkeys.push(HeldPasskey {
            organization_id: *organization_id,
            credential: copy_passkey(credential),
        });
        Ok(())
    }

    async fn delete(&self, id: &PasskeyId) -> Result<(), DomainError> {
        self.passkeys
            .lock()
            .unwrap()
            .retain(|held| held.credential.id() != id);
        Ok(())
    }
}

/// A copy of `codes`, read back the way storage reads it.
fn copy_code_set(
    codes: &RecoveryCodeSet<ResolvedOrganization>,
) -> Result<RecoveryCodeSet<ResolvedOrganization>, DomainError> {
    RecoveryCodeSet::reconstitute(RecoveryCodeSetRow {
        subject_id: codes.subject_id(),
        codes: codes.codes().to_vec(),
        generated_at: codes.generated_at(),
    })
}

/// Refuses `codes` kept under `org_user_id` when they are another person's,
/// as the real store refuses them.
fn ensure_owned_by(
    org_user_id: &OrgUserId,
    codes: &RecoveryCodeSet<ResolvedOrganization>,
) -> Result<(), DomainError> {
    if codes.subject_id() != PrincipalId::from(*org_user_id) {
        return Err(DomainError::invalid(
            "recovery codes are saved for the member they belong to",
        ));
    }
    Ok(())
}

/// In-memory store holding each member's recovery codes, one set each.
#[derive(Default)]
pub struct FakeOrgRecoveryCodeStore {
    sets: Mutex<Vec<(OrgUserId, RecoveryCodeSet<ResolvedOrganization>)>>,
}

impl FakeOrgRecoveryCodeStore {
    /// A store holding no codes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store holding `codes` as `org_user_id`'s.
    #[must_use]
    pub fn holding(org_user_id: OrgUserId, codes: RecoveryCodeSet<ResolvedOrganization>) -> Self {
        Self {
            sets: Mutex::new(vec![(org_user_id, codes)]),
        }
    }

    /// A store where `org_user_id` holds a fresh set of unused codes with
    /// these hashes.
    ///
    /// # Panics
    ///
    /// Panics if `hashes` is empty or names a hash twice, which no set may.
    #[must_use]
    pub fn with_codes(org_user_id: OrgUserId, hashes: &[&str]) -> Self {
        let codes = hashes
            .iter()
            .map(|hash| {
                RecoveryCode::reconstitute(RecoveryCodeRow {
                    hash: TokenHash::from_stored((*hash).to_owned()),
                    usage: Usage::Unused,
                })
                .expect("an unused code rebuilds")
            })
            .collect();
        let set = RecoveryCodeSet::reconstitute(RecoveryCodeSetRow {
            subject_id: org_user_id.into(),
            codes,
            generated_at: clock::now(),
        })
        .expect("a test passes distinct hashes");
        Self::holding(org_user_id, set)
    }

    /// Whether `org_user_id` holds a set of codes.
    #[must_use]
    pub fn holds_codes(&self, org_user_id: &OrgUserId) -> bool {
        self.sets
            .lock()
            .unwrap()
            .iter()
            .any(|(owner, _)| owner == org_user_id)
    }

    /// How many of `org_user_id`'s codes are still unused.
    #[must_use]
    pub fn remaining(&self, org_user_id: &OrgUserId) -> usize {
        self.sets
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, _)| owner == org_user_id)
            .map_or(0, |(_, codes)| codes.remaining())
    }
}

#[async_trait]
impl OrgRecoveryCodeStore for FakeOrgRecoveryCodeStore {
    async fn find_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<RecoveryCodeSet<ResolvedOrganization>>, DomainError> {
        self.sets
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, _)| owner == org_user_id)
            .map(|(_, codes)| copy_code_set(codes))
            .transpose()
    }

    async fn save(
        &self,
        org_user_id: &OrgUserId,
        codes: &RecoveryCodeSet<ResolvedOrganization>,
    ) -> Result<(), DomainError> {
        ensure_owned_by(org_user_id, codes)?;
        let copy = copy_code_set(codes)?;
        let mut sets = self.sets.lock().unwrap();
        sets.retain(|(owner, _)| owner != org_user_id);
        sets.push((*org_user_id, copy));
        Ok(())
    }

    async fn spend(
        &self,
        org_user_id: &OrgUserId,
        codes: &RecoveryCodeSet<ResolvedOrganization>,
        hash: &TokenHash,
    ) -> Result<bool, DomainError> {
        ensure_owned_by(org_user_id, codes)?;
        let spent_here = codes
            .codes()
            .iter()
            .any(|code| code.hash() == hash && code.is_used());
        if !spent_here {
            return Err(DomainError::invalid(
                "the code to record is not spent in this set",
            ));
        }
        let copy = copy_code_set(codes)?;
        let mut sets = self.sets.lock().unwrap();
        let unused = sets
            .iter()
            .find(|(owner, _)| owner == org_user_id)
            .is_some_and(|(_, stored)| {
                stored
                    .codes()
                    .iter()
                    .any(|code| code.hash() == hash && !code.is_used())
            });
        if !unused {
            return Ok(false);
        }
        sets.retain(|(owner, _)| owner != org_user_id);
        sets.push((*org_user_id, copy));
        Ok(true)
    }
}

impl Fake for Arc<dyn OrgPasskeyCeremonyStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgPasskeyCeremonyStore::new())
    }
}

impl Fake for Arc<dyn OrgPasskeyStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgPasskeyStore::empty())
    }
}

impl Fake for Arc<dyn OrgRecoveryCodeStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgRecoveryCodeStore::new())
    }
}
