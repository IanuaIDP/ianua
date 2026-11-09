use std::fmt;
use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::events::credential::{
    PasskeyRegistered, PasskeyRemoved, PasskeyRenamed,
};
use crate::domains::authentication::keeper::{AccountKeeper, ChangedBy, FactorWithdrawal};
use crate::domains::authentication::sessions::fresh_sign_in::FactorSetupProof;
use crate::domains::identity::account::control::AccountAction;
use crate::domains::identity::sealed::Sealed;
use crate::isolation::SecurityScope;
use crate::isolation::organization::scope::ResolvedOrganization;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{Label, OrgUserId, PasskeyCredentialId, PasskeyId, PrincipalId, UserId};

/// A plane whose accounts hold passkeys, and the id a passkey there names
/// its owner by.
///
/// A tenant's passkeys belong to its users, and an organization's to its
/// members. Naming the owner by the plane's own id keeps the two apart: a
/// tenant passkey never names an organization member, so it never signs
/// one in.
pub trait PasskeyPlane: SecurityScope {
    /// The id of an account on this plane.
    type Owner: Copy + Eq + std::fmt::Debug + Into<PrincipalId> + Send + Sync + 'static;

    /// What a passkey on this plane keeps of what happened to it until it
    /// is saved.
    type Record: PasskeyRecord<Self::Owner>;
}

impl<T: TenantScope> PasskeyPlane for T {
    type Owner = UserId;
    type Record = Raised<T>;
}

impl PasskeyPlane for ResolvedOrganization {
    type Owner = OrgUserId;
    type Record = KeptByTheOrganization;
}

/// How a passkey on one plane records being registered, renamed and
/// removed.
///
/// A tenant's passkey raises the tenant's events, which the application
/// takes once the change is saved. Only the planes of this crate answer it,
/// so no caller swaps in a record that forgets.
pub trait PasskeyRecord<Owner>: Sealed + Default + fmt::Debug {
    /// The passkey `credential_id`, on an `authenticator` of that kind, was
    /// registered.
    fn record_registration(
        &mut self,
        credential_id: &PasskeyCredentialId,
        authenticator: AuthenticatorType,
    );

    /// The passkey `credential_id` of `owner` was renamed.
    fn record_rename(&mut self, owner: Owner, credential_id: &PasskeyCredentialId);

    /// The passkey `credential_id`, on an `authenticator` of that kind, was
    /// removed, as `by` says whose doing it was.
    fn record_removal(
        &mut self,
        credential_id: &PasskeyCredentialId,
        authenticator: AuthenticatorType,
        by: ChangedBy<Owner>,
    );
}

impl<T: TenantScope> Sealed for Raised<T> {}

impl<T: TenantScope> PasskeyRecord<UserId> for Raised<T> {
    fn record_registration(
        &mut self,
        credential_id: &PasskeyCredentialId,
        authenticator: AuthenticatorType,
    ) {
        self.raise(PasskeyRegistered {
            credential_id: credential_id.clone(),
            authenticator,
            occurred_at: crate::shared::clock::now(),
        });
    }

    fn record_rename(&mut self, owner: UserId, credential_id: &PasskeyCredentialId) {
        self.raise(PasskeyRenamed {
            user_id: owner,
            credential_id: credential_id.clone(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    fn record_removal(
        &mut self,
        credential_id: &PasskeyCredentialId,
        authenticator: AuthenticatorType,
        by: ChangedBy<UserId>,
    ) {
        self.raise(PasskeyRemoved {
            credential_id: credential_id.clone(),
            authenticator,
            by,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

/// The record of an organization member's passkey: nothing kept on the
/// passkey, since the organization records its members' passkeys itself.
#[derive(Debug, Default)]
pub struct KeptByTheOrganization;

impl Sealed for KeptByTheOrganization {}

impl PasskeyRecord<OrgUserId> for KeptByTheOrganization {
    fn record_registration(&mut self, _: &PasskeyCredentialId, _: AuthenticatorType) {}

    fn record_rename(&mut self, _: OrgUserId, _: &PasskeyCredentialId) {}

    fn record_removal(
        &mut self,
        _: &PasskeyCredentialId,
        _: AuthenticatorType,
        _: ChangedBy<OrgUserId>,
    ) {
    }
}

/// What the registration ceremony proved about where the key lives.
///
/// Only an attestation the `WebAuthn` adapter checked at registration says a
/// key is hardware. A key nobody attested may be a copy synced to a phone or
/// a password manager, so it counts as one software factor, AAL2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeyAttestation {
    /// No attestation was checked. The key may be a synced copy.
    Unattested,
    /// An attestation showed a hardware security key, which cannot be
    /// copied off the device.
    HardwareKey,
}

/// Where the browser said the passkey lives, as reported at registration.
///
/// The client can report anything here. A phone passkey synced across
/// devices reports `CrossPlatform` too. So the value is shown to the person
/// and never read as proof of a hardware key. Only a verified attestation
/// could prove that, and this value is not one. A passkey with only this
/// value counts as one software factor, AAL2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthenticatorType {
    /// An authenticator built into the device, such as Touch ID, Windows
    /// Hello or Android biometrics.
    Platform,

    /// A roaming authenticator, such as a USB, NFC or Bluetooth key, or a
    /// phone used from another device.
    CrossPlatform,
}

impl AuthenticatorType {
    /// The name the audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::CrossPlatform => "cross_platform",
        }
    }
}

/// A registered `WebAuthn` credential, or passkey, for an account on plane
/// `S`.
///
/// A passkey signs its owner in without a password, using public-key
/// cryptography. The private key never leaves the owner's device. Only the
/// public key is stored on the server.
///
/// A tenant user's passkey belongs to one tenant, and is read and written
/// only through stores opened for it. An organization member's belongs to
/// the organization plane. See [`crate::isolation`].
#[derive(Debug)]
pub struct PasskeyCredential<S: PasskeyPlane> {
    id: PasskeyId,
    user_id: S::Owner,
    credential_id: PasskeyCredentialId,
    public_key: Vec<u8>,
    sign_count: u32,
    authenticator_type: AuthenticatorType,
    attestation: KeyAttestation,
    name: Label,
    last_used_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    raised: S::Record,
    _scope: PhantomData<S>,
}

/// Parameters for registering a new passkey, for an account named by
/// `Owner`.
pub struct RegisterPasskeyParams<Owner = UserId> {
    /// The account registering the passkey.
    pub user_id: Owner,
    /// The `WebAuthn` credential ID from the authenticator.
    pub credential_id: PasskeyCredentialId,
    /// The public key from the authenticator.
    pub public_key: Vec<u8>,
    /// Whether this is a platform or roaming authenticator.
    pub authenticator_type: AuthenticatorType,
    /// What the registration ceremony's attestation showed.
    pub attestation: KeyAttestation,
    /// The passkey's name, such as "`MacBook` Touch ID" or "`YubiKey` 5".
    pub name: Label,
}

/// Persisted state for repository hydration, for a passkey whose owner is
/// named by `Owner`.
pub struct PasskeyCredentialRow<Owner = UserId> {
    /// Internal credential identifier.
    pub id: PasskeyId,
    /// The account that owns the passkey.
    pub user_id: Owner,
    /// The `WebAuthn` credential ID the authenticator presents.
    pub credential_id: PasskeyCredentialId,
    /// The public key used to verify authentication assertions.
    pub public_key: Vec<u8>,
    /// The authenticator's signature counter, used to detect cloned keys.
    pub sign_count: u32,
    /// Whether this is a platform or roaming authenticator.
    pub authenticator_type: AuthenticatorType,
    /// What the registration ceremony's attestation showed.
    pub attestation: KeyAttestation,
    /// The name the user gave the passkey.
    pub name: Label,
    /// When the passkey was last used to sign in, if ever.
    pub last_used_at: Option<OffsetDateTime>,
    /// When the passkey was registered.
    pub created_at: OffsetDateTime,
}

impl<S: PasskeyPlane> PasskeyCredential<S> {
    /// Registers a new passkey from a `WebAuthn` registration ceremony, for
    /// a person who proved who they are just now.
    ///
    /// A passkey signs in on its own. Mallory steals Ann's session and
    /// registers her own passkey on Ann's account. Without this check she
    /// keeps the account long after the session ends. So registering asks
    /// for the same fresh proof as changing the address, or the leave a
    /// sign-in gives to set up the factor it owes.
    ///
    /// A tenant's passkey raises `authentication.passkey_registered`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `proof` does not let the account the
    ///   passkey is for set up a factor now.
    pub fn register(
        params: RegisterPasskeyParams<S::Owner>,
        proof: &impl FactorSetupProof,
    ) -> Result<Self, DomainError> {
        if !proof.lets_set_up(&params.user_id.into()) {
            return Err(DomainError::forbidden(message!(
                "authentication-adding-a-passkey-needs-the-person",
                "adding a passkey needs the person to prove who they are again"
            )));
        }
        let mut passkey = Self {
            id: PasskeyId::new(),
            user_id: params.user_id,
            credential_id: params.credential_id,
            public_key: params.public_key,
            sign_count: 0,
            authenticator_type: params.authenticator_type,
            attestation: params.attestation,
            name: params.name,
            last_used_at: None,
            created_at: crate::shared::clock::now(),
            raised: S::Record::default(),
            _scope: PhantomData,
        };
        passkey
            .raised
            .record_registration(&passkey.credential_id, passkey.authenticator_type);
        Ok(passkey)
    }

    /// Rebuilds a passkey from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the passkey was
    ///   used before it was registered.
    /// - [`DomainError::Infrastructure`] when the row has a sign count but
    ///   no last use.
    pub fn reconstitute(row: PasskeyCredentialRow<S::Owner>) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            credential_id: row.credential_id,
            public_key: row.public_key,
            sign_count: row.sign_count,
            authenticator_type: row.authenticator_type,
            attestation: row.attestation,
            name: row.name,
            last_used_at: row.last_used_at,
            created_at: row.created_at,
            raised: S::Record::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &PasskeyCredentialRow<S::Owner>) -> Result<(), DomainError> {
        RowCheck::of("passkey")
            .in_order_if(
                row.created_at,
                row.last_used_at,
                "used before it was registered",
            )
            .holds(
                row.sign_count == 0 || row.last_used_at.is_some(),
                "a sign count with no sign-in that set it",
            )
            .finish()
    }

    /// Internal credential identifier.
    #[must_use]
    pub fn id(&self) -> &PasskeyId {
        &self.id
    }

    /// The account that owns this passkey.
    #[must_use]
    pub fn user_id(&self) -> &S::Owner {
        &self.user_id
    }

    /// The `WebAuthn` credential ID used to identify this key during authentication.
    #[must_use]
    pub fn credential_id(&self) -> &PasskeyCredentialId {
        &self.credential_id
    }

    /// The public key used to verify authentication assertions.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The authenticator's signature counter, used to detect cloned keys. If
    /// the counter goes backwards, the key may have been copied.
    #[must_use]
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    /// Whether this is a platform or roaming authenticator.
    #[must_use]
    pub fn authenticator_type(&self) -> AuthenticatorType {
        self.authenticator_type
    }

    /// What the registration ceremony's attestation showed.
    #[must_use]
    pub fn attestation(&self) -> KeyAttestation {
        self.attestation
    }

    /// Passkey name shown in the user's security settings.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// When this passkey was last used for authentication.
    #[must_use]
    pub fn last_used_at(&self) -> Option<OffsetDateTime> {
        self.last_used_at
    }

    /// When this passkey was registered.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Records the new sign counter and the last-used time after a
    /// successful authentication.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when the stored counter is above zero
    ///   and the new counter is not above it. The authenticator may be a
    ///   clone, so the sign-in is refused.
    pub fn update_sign_count(&mut self, new_count: u32) -> Result<(), DomainError> {
        if new_count <= self.sign_count && self.sign_count > 0 {
            return Err(DomainError::unauthorized(message!(
                "authentication-the-sign-counter-did-not-go",
                "the sign counter did not go up, so the key may be a copy"
            )));
        }
        self.sign_count = new_count;
        self.last_used_at = Some(crate::shared::clock::now());
        Ok(())
    }

    /// Renames a passkey for its holder or an authorized account administrator.
    /// Organization members act through their own sign-in. Tenant passkeys raise
    /// `authentication.passkey_renamed`; the name distinguishes keys during revocation.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] when [`AccountKeeper::ensure_may`] refuses changes
    /// to the account's sign-in methods.
    pub fn rename(&mut self, name: Label, by: &impl AccountKeeper<S>) -> Result<(), DomainError> {
        by.ensure_may(&self.user_id.into(), AccountAction::ChangeSignIn)?;
        self.name = name;
        self.raised.record_rename(self.user_id, &self.credential_id);
        Ok(())
    }

    /// Removes this passkey, as its holder or an admin acting on their
    /// account decides. The caller deletes it next.
    ///
    /// A passkey signs in on its own, so taking one away changes how the
    /// account signs in. Sam may only view users. Without this, he removes
    /// the key Ann signs in with in the middle of an incident.
    ///
    /// A tenant's passkey raises `authentication.passkey_removed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in the cases
    ///   [`AccountKeeper::ensure_may`] lists, for changing how the account
    ///   signs in.
    pub fn remove(&mut self, by: &impl AccountKeeper<S>) -> Result<(), DomainError> {
        by.ensure_may(&self.user_id.into(), AccountAction::ChangeSignIn)?;
        let changed_by = ChangedBy::of::<S>(by, self.user_id);
        self.raised
            .record_removal(&self.credential_id, self.authenticator_type, changed_by);
        Ok(())
    }

    /// Refuses removing this passkey as `by` takes away an account's ways
    /// in, unless it is that account's. The caller deletes it next.
    ///
    /// Bob's account is reopened for whoever answers a new invitation to his
    /// address. Without this, his phone still signs in to it once they set
    /// a password.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the passkey is another account's.
    pub fn ensure_withdrawn_by(&self, by: &impl FactorWithdrawal<S>) -> Result<(), DomainError> {
        if by.withdraws_from(&self.user_id.into()) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "authentication-the-passkey-belongs-to-another-account-2",
            "the passkey belongs to another account than the one withdrawn"
        )))
    }
}

impl<T: TenantScope> Raises for PasskeyCredential<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Runs the `WebAuthn` ceremonies.
///
/// Infrastructure implements the `WebAuthn` protocol with a library such as
/// `webauthn-rs`.
pub trait PasskeyVerifier: Send + Sync {
    /// A registration challenge for a new passkey.
    ///
    /// It holds the challenge and options for the client's
    /// `navigator.credentials.create()` call.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the challenge cannot be generated.
    fn generate_registration_challenge(
        &self,
        user_id: &UserId,
        user_name: &str,
    ) -> Result<Vec<u8>, DomainError>;

    /// An authentication challenge for an existing passkey.
    ///
    /// It goes to the client's `navigator.credentials.get()` call.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the challenge cannot be generated.
    fn generate_authentication_challenge(
        &self,
        credential_ids: &[Vec<u8>],
    ) -> Result<Vec<u8>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of;
    use crate::domains::authentication::sessions::sign_in_progress::finished_sign_in_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};

    fn params_for<Owner>(user_id: Owner) -> RegisterPasskeyParams<Owner> {
        RegisterPasskeyParams {
            user_id,
            credential_id: PasskeyCredentialId::new(vec![1, 2, 3, 4]).unwrap(),
            public_key: vec![5, 6, 7, 8],
            authenticator_type: AuthenticatorType::CrossPlatform,
            attestation: KeyAttestation::Unattested,
            name: label("YubiKey 5"),
        }
    }

    fn test_passkey() -> PasskeyCredential<ResolvedTenant> {
        let user = UserId::new();
        PasskeyCredential::register(params_for(user), &fresh_proof_of(user.into())).unwrap()
    }

    /// A fresh proof for Mallory's account cannot authorize adding a passkey to Ann's.
    #[test]
    fn a_passkey_is_not_added_without_a_fresh_proof_of_its_account() {
        let ann = UserId::new();
        let mallory = UserId::new();

        let refused = PasskeyCredential::<ResolvedTenant>::register(
            params_for(ann),
            &fresh_proof_of(mallory.into()),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Ann registers a key whose attestation showed a hardware key. The
    /// passkey keeps that, so a sign-in with it can count as one.
    #[test]
    fn a_passkey_keeps_what_its_attestation_showed() {
        let ann = UserId::new();
        let params = RegisterPasskeyParams {
            attestation: KeyAttestation::HardwareKey,
            ..params_for(ann)
        };

        let pk: PasskeyCredential<ResolvedTenant> =
            PasskeyCredential::register(params, &fresh_proof_of(ann.into())).unwrap();

        assert_eq!(pk.attestation(), KeyAttestation::HardwareKey);
    }

    /// Ann registers a `YubiKey`. The new passkey keeps her name for it,
    /// starts at a sign counter of 0 and has never been used.
    #[test]
    fn register_creates_credential() {
        let pk = test_passkey();

        assert_eq!(pk.name().as_str(), "YubiKey 5");
        assert_eq!(pk.sign_count(), 0);
        assert_eq!(pk.authenticator_type(), AuthenticatorType::CrossPlatform);
        assert!(pk.last_used_at().is_none());
        assert_eq!(pk.credential_id().as_bytes(), [1, 2, 3, 4]);
    }

    /// Ann signs in twice with counters 1 and then 5. Each higher counter is
    /// stored and the passkey records when it was last used.
    #[test]
    fn update_sign_count_increments() {
        let mut pk = test_passkey();

        pk.update_sign_count(1).unwrap();
        assert_eq!(pk.sign_count(), 1);
        assert!(pk.last_used_at().is_some());

        pk.update_sign_count(5).unwrap();
        assert_eq!(pk.sign_count(), 5);
    }

    /// A counter of five is refused after ten, leaving the stored counter at ten.
    #[test]
    fn backwards_sign_count_detects_clone() {
        let mut pk = test_passkey();
        pk.update_sign_count(10).unwrap();

        let result = pk.update_sign_count(5);

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
        assert_eq!(pk.sign_count(), 10);
    }

    /// Repeating an accepted counter is unauthorized.
    #[test]
    fn same_sign_count_detects_clone() {
        let mut pk = test_passkey();
        pk.update_sign_count(10).unwrap();

        let result = pk.update_sign_count(10);

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// A counter that does not go up is refused with a message saying the
    /// counter did not rise and the key may be a copy.
    #[test]
    fn a_counter_that_does_not_rise_is_refused_in_plain_words() {
        let mut pk = test_passkey();
        pk.update_sign_count(10).unwrap();

        let Err(DomainError::Unauthorized(refusal)) = pk.update_sign_count(10) else {
            panic!("a counter that does not rise must be refused");
        };

        assert_eq!(
            refusal.as_str(),
            "the sign counter did not go up, so the key may be a copy"
        );
    }

    /// Some authenticators never count and always report 0. A passkey at 0
    /// that signs in with 0 is accepted, so those keys keep working.
    #[test]
    fn zero_to_zero_is_allowed() {
        let mut pk = test_passkey();
        assert!(pk.update_sign_count(0).is_ok());
    }

    /// Ann registers a passkey. It hands back her user id and the exact
    /// public key bytes, because sign-in signatures are checked against
    /// those bytes.
    #[test]
    fn a_passkey_reports_the_public_key_and_owner_it_was_registered_with() {
        let user = UserId::new();

        let pk: PasskeyCredential<ResolvedTenant> =
            PasskeyCredential::register(params_for(user), &fresh_proof_of(user.into())).unwrap();

        assert_eq!(pk.public_key(), &[5, 6, 7, 8]);
        assert_eq!(pk.user_id(), &user);
        assert!(!pk.id().as_uuid().is_nil(), "a passkey carries its own id");
    }

    /// Ann renames her `YubiKey` to "Work laptop". The passkey is listed
    /// under the new name, so she can tell her keys apart when revoking one.
    #[test]
    fn renaming_a_passkey_changes_the_name_it_is_listed_under() {
        let mut pk = test_passkey();
        let ann = finished_sign_in_of::<ResolvedTenant>((*pk.user_id()).into());

        pk.rename(label("Work laptop"), &ann).unwrap();

        assert_eq!(pk.name().as_str(), "Work laptop");
    }

    /// Mallory cannot rename Ann's passkey, which retains its original name.
    #[test]
    fn someone_else_does_not_rename_a_passkey() {
        let mut pk = test_passkey();
        let mallory = finished_sign_in_of::<ResolvedTenant>(UserId::new().into());

        let refused = pk.rename(label("lost phone"), &mallory);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(pk.name().as_str(), "YubiKey 5");
    }

    /// Ann, a member of Acme's organization, renames her passkey from her
    /// own organization sign-in. Mallory, signed in as another member, is
    /// refused.
    #[test]
    fn an_organization_member_renames_only_her_own_passkey() {
        let ann = OrgUserId::new();
        let mut pk = PasskeyCredential::<ResolvedOrganization>::register(
            params_for(ann),
            &fresh_proof_of(ann.into()),
        )
        .unwrap();
        let mallory = finished_sign_in_of::<ResolvedOrganization>(OrgUserId::new().into());
        let by_ann = finished_sign_in_of::<ResolvedOrganization>(ann.into());

        let by_mallory = pk.rename(label("lost phone"), &mallory);
        pk.rename(label("Work laptop"), &by_ann).unwrap();

        assert!(matches!(by_mallory, Err(DomainError::Forbidden(_))));
        assert_eq!(pk.name().as_str(), "Work laptop");
    }

    /// A stored row says the passkey was last used one second before it was
    /// registered. Loading it is refused as corrupt instead of trusted.
    #[test]
    fn a_stored_passkey_used_before_it_was_registered_is_refused() {
        let passkey = test_passkey();
        let row = PasskeyCredentialRow {
            id: *passkey.id(),
            user_id: *passkey.user_id(),
            credential_id: passkey.credential_id().clone(),
            public_key: passkey.public_key().to_vec(),
            sign_count: passkey.sign_count(),
            authenticator_type: passkey.authenticator_type(),
            attestation: passkey.attestation(),
            name: passkey.name().clone(),
            last_used_at: Some(passkey.created_at() - time::Duration::SECOND),
            created_at: passkey.created_at(),
        };

        assert!(refused_as_corrupt(
            &PasskeyCredential::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored counter of seven without a last-use time is corrupt.
    #[test]
    fn a_stored_passkey_with_a_sign_count_and_no_last_use_is_refused() {
        let passkey = test_passkey();
        let row = PasskeyCredentialRow {
            id: *passkey.id(),
            user_id: *passkey.user_id(),
            credential_id: passkey.credential_id().clone(),
            public_key: passkey.public_key().to_vec(),
            sign_count: 7,
            authenticator_type: passkey.authenticator_type(),
            attestation: passkey.attestation(),
            name: passkey.name().clone(),
            last_used_at: None,
            created_at: passkey.created_at(),
        };

        assert!(refused_as_corrupt(
            &PasskeyCredential::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Ann registers her `YubiKey`. It raises
    /// `authentication.passkey_registered` with the key's credential id.
    #[test]
    fn registering_raises_the_registration() {
        let mut pk = test_passkey();

        let events = raised(&mut pk);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.passkey_registered"
        );
        assert_eq!(
            events[0].payload().get("credential_id"),
            Some(pk.credential_id().to_string().as_str())
        );
    }

    /// Ann renames her `YubiKey`. It raises
    /// `authentication.passkey_renamed`.
    #[test]
    fn renaming_raises_the_rename() {
        let mut pk = test_passkey();
        raised_names(&mut pk);
        let ann = finished_sign_in_of::<ResolvedTenant>((*pk.user_id()).into());

        pk.rename(label("Work laptop"), &ann).unwrap();

        assert_eq!(raised_names(&mut pk), ["authentication.passkey_renamed"]);
    }

    /// Ann removes her `YubiKey` from her own sign-in. It raises
    /// `authentication.passkey_removed`.
    #[test]
    fn removing_raises_the_removal() {
        let mut pk = test_passkey();
        raised_names(&mut pk);
        let ann = finished_sign_in_of::<ResolvedTenant>((*pk.user_id()).into());

        pk.remove(&ann).unwrap();

        assert_eq!(raised_names(&mut pk), ["authentication.passkey_removed"]);
    }

    /// Another account cannot rename or remove Ann's passkey; neither refusal raises an event.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut pk = test_passkey();
        raised_names(&mut pk);
        let mallory = finished_sign_in_of::<ResolvedTenant>(UserId::new().into());

        let renamed = pk.rename(label("lost phone"), &mallory);
        let removed = pk.remove(&mallory);

        assert!(renamed.is_err() && removed.is_err());
        assert!(raised(&mut pk).is_empty());
    }

    /// Ann's passkey is read back from storage. It has raised nothing.
    #[test]
    fn a_passkey_read_back_has_raised_nothing() {
        let mut pk = test_passkey();
        let row = PasskeyCredentialRow {
            id: *pk.id(),
            user_id: *pk.user_id(),
            credential_id: pk.credential_id().clone(),
            public_key: pk.public_key().to_vec(),
            sign_count: pk.sign_count(),
            authenticator_type: pk.authenticator_type(),
            attestation: pk.attestation(),
            name: pk.name().clone(),
            last_used_at: pk.last_used_at(),
            created_at: pk.created_at(),
        };
        raised_names(&mut pk);

        let mut read_back = PasskeyCredential::<ResolvedTenant>::reconstitute(row).unwrap();

        assert!(raised(&mut read_back).is_empty());
    }
}
