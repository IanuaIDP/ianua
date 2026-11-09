/// How a tenant's directory moves an account.
pub mod directory;
mod import;
mod profile;
mod records;
mod status;

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::identity::account::address::{AccountAddress, AddressStanding};
use crate::domains::identity::account::admin_password_reset::AdminPasswordReset;
use crate::domains::identity::account::control::{AccountAction, AccountControlCheck};
use crate::domains::identity::account::creator::{AccountCreator, AccountOpening};
use crate::domains::identity::account::row_rules::ensure_consistent;
use crate::domains::identity::account::user_profile::UserProfile;
use crate::domains::identity::account::user_status::{InvalidUserTransition, UserStatus};
use crate::domains::identity::account::verified_email::{VerificationRefused, VerifiedEmail};
use crate::domains::identity::account::vouching::Vouching;
use crate::domains::identity::events::account::{
    UserEmailVerified, UserPasswordReset, UserRegistered,
};
use crate::domains::identity::events::invitations::UserInvited;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::raised::Raised;
use crate::shared::model::aggregate::Aggregate;
use crate::types::{
    CredentialChange, DisplayName, Email, Joining, Locale, Preference, Timezone, UserId,
};

/// A person's account in one tenant.
///
/// It is read and written only through stores opened for its tenant. See
/// [`crate::isolation`].
#[derive(Debug)]
pub struct User<T: TenantScope> {
    id: UserId,
    address: AccountAddress,
    display_name: DisplayName,
    status: UserStatus,
    locale: Preference<Locale>,
    timezone: Preference<Timezone>,
    /// What it records about its holder beyond the name it shows.
    profile: UserProfile,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    last_login_at: Option<OffsetDateTime>,
    /// Whether it has joined, and when it first did.
    joining: Joining,
    credentials_changed_at: CredentialChange,
    vouching: Vouching,
    origin: Origin,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// Where this copy of an account came from, which decides what its status
/// moves record. It is never stored.
#[derive(Debug, Clone, Copy)]
enum Origin {
    /// Created without loading a stored account. Its status moves belong to
    /// the creation event rather than separate status events.
    Opened,
    /// Read back from storage at this status, or settled at it since by a
    /// directory's change.
    Stored(UserStatus),
}

/// A user as storage keeps it, checked again by [`User::reconstitute`].
pub struct UserRow {
    /// The user's id.
    pub id: UserId,
    /// The user's email address, unique in the tenant.
    pub email: Email,
    /// The name shown in admin screens and greetings.
    pub display_name: DisplayName,
    /// Where the account stands.
    pub status: UserStatus,
    /// Whether the user was shown to hold `email`.
    pub email_standing: AddressStanding,
    /// The locale they chose, or that they follow the tenant's.
    pub locale: Preference<Locale>,
    /// The timezone they chose, or that they follow the tenant's.
    pub timezone: Preference<Timezone>,
    /// Their own details and the directory's records about them.
    pub profile: UserProfile,
    /// When this user was created.
    pub created_at: OffsetDateTime,
    /// When this user was last modified.
    pub updated_at: OffsetDateTime,
    /// When this user last signed in, or `None` if never.
    pub last_login_at: Option<OffsetDateTime>,
    /// Whether it has joined, and when it first did.
    pub joining: Joining,
    /// When this user last changed how they sign in, or that they never have.
    pub credentials_changed_at: CredentialChange,
    /// Whether an accepted invitation still vouches for the next sign-in.
    pub vouching: Vouching,
}

impl<T: TenantScope> User<T> {
    /// Registers a new user in the tenant.
    ///
    /// The user starts in `PendingVerification` with an unverified email and
    /// cannot sign in yet. Confirming the address through
    /// [`verify_email`](Self::verify_email) activates the account. A caller
    /// that already proved the address another way calls `verify_email`
    /// right after.
    ///
    /// Use [`invite`](Self::invite) instead when the user is asked to claim
    /// the account through an invitation. Raises `identity.user_registered`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `creator` may not register
    ///   accounts. See [`AccountCreator`].
    pub fn register(
        id: UserId,
        email: Email,
        display_name: DisplayName,
        creator: &impl AccountCreator<T>,
    ) -> Result<Self, DomainError> {
        creator.ensure_may_open(AccountOpening::Registration)?;
        let mut user = Self::opened(
            id,
            AccountAddress::unverified(email),
            display_name,
            UserStatus::PendingVerification,
        );
        user.raised.raise(UserRegistered {
            email: user.email().clone(),
            occurred_at: user.created_at,
        });
        Ok(user)
    }

    /// Creates the account of a person who was shown to hold `address`, such
    /// as through an identity provider trusted for it.
    ///
    /// The account is active and its address verified from the start. The
    /// proof is what [`register`](Self::register) waits for. Only a
    /// [`VerifiedEmail`] is accepted, so an address someone typed in never
    /// lands on an account as verified. Raises nothing: the sign-in that
    /// provisions it records it.
    #[must_use]
    pub fn provision(id: UserId, address: VerifiedEmail, display_name: DisplayName) -> Self {
        Self::opened(
            id,
            AccountAddress::verified(address),
            display_name,
            UserStatus::Active,
        )
    }

    /// Creates a user who is asked to claim the account through an
    /// invitation.
    ///
    /// The user starts `Invited` with an unverified email. They cannot sign
    /// in until the account is activated, such as by accepting the
    /// invitation. Raises `identity.user_invited`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `creator` may not invite people.
    ///   See [`AccountCreator`].
    pub fn invite(
        id: UserId,
        email: Email,
        display_name: DisplayName,
        creator: &impl AccountCreator<T>,
    ) -> Result<Self, DomainError> {
        creator.ensure_may_open(AccountOpening::Invitation)?;
        let mut user = Self::opened(
            id,
            AccountAddress::unverified(email),
            display_name,
            UserStatus::Invited,
        );
        user.raised.raise(UserInvited {
            user_id: user.id,
            email: user.email().clone(),
            occurred_at: user.created_at,
        });
        Ok(user)
    }

    /// A new account at `address`, starting at `status`. Only an active
    /// account has joined.
    fn opened(
        id: UserId,
        address: AccountAddress,
        display_name: DisplayName,
        status: UserStatus,
    ) -> Self {
        let now = crate::shared::clock::now();
        let joining = if status == UserStatus::Active {
            Joining::Joined { at: now }
        } else {
            Joining::NotYet
        };
        Self {
            id,
            address,
            display_name,
            status,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            profile: UserProfile::default(),
            created_at: now,
            updated_at: now,
            last_login_at: None,
            joining,
            credentials_changed_at: CredentialChange::Never,
            vouching: Vouching::Absent,
            origin: Origin::Opened,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds a user from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row has joined while still
    ///   invited or unverified, or is active or locked with no join date.
    /// - [`DomainError::Infrastructure`] when the row waits on verification
    ///   but its address is already verified.
    /// - [`DomainError::Infrastructure`] when the row says the account
    ///   changed, signed in, joined or changed how it signs in before it was
    ///   created.
    /// - [`DomainError::Infrastructure`] when the row names the account as
    ///   its own manager.
    /// - [`DomainError::Infrastructure`] when an invitation vouches for the
    ///   row's next sign-in while it never joined.
    pub fn reconstitute(row: UserRow) -> Result<Self, DomainError> {
        ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            address: AccountAddress::stored(row.email, row.email_standing),
            display_name: row.display_name,
            status: row.status,
            locale: row.locale,
            timezone: row.timezone,
            profile: row.profile,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_login_at: row.last_login_at,
            joining: row.joining,
            credentials_changed_at: row.credentials_changed_at,
            vouching: row.vouching,
            origin: Origin::Stored(row.status),
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The user's id.
    #[must_use]
    pub fn id(&self) -> &UserId {
        &self.id
    }

    /// The user's email address, unique in the tenant.
    #[must_use]
    pub fn email(&self) -> &Email {
        self.address.email()
    }

    /// The address with its standing.
    #[must_use]
    pub fn address(&self) -> &AccountAddress {
        &self.address
    }

    /// The name shown in admin screens and greetings.
    #[must_use]
    pub fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    /// Where the account stands.
    #[must_use]
    pub fn status(&self) -> UserStatus {
        self.status
    }

    /// Whether the user has confirmed their email address.
    #[must_use]
    pub fn email_verified(&self) -> bool {
        self.address.is_verified()
    }

    /// The locale they chose, or that they follow the tenant's.
    #[must_use]
    pub fn locale(&self) -> &Preference<Locale> {
        &self.locale
    }

    /// The timezone they chose, or that they follow the tenant's.
    #[must_use]
    pub fn timezone(&self) -> &Preference<Timezone> {
        &self.timezone
    }

    /// What the account records about its holder beyond the name it shows:
    /// their own details and the directory's records.
    #[must_use]
    pub fn profile(&self) -> &UserProfile {
        &self.profile
    }

    /// When this user was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this user was last modified.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// When this user last signed in, or `None` if never.
    #[must_use]
    pub fn last_login_at(&self) -> Option<OffsetDateTime> {
        self.last_login_at
    }

    /// When this user first became active, or `None` until they do.
    #[must_use]
    pub fn joined_at(&self) -> Option<OffsetDateTime> {
        self.joining.joined_at()
    }

    /// When this user last changed how they sign in, or that they never have.
    ///
    /// A change is a password set or reset, or a second factor added or
    /// removed. A device remembered before it does not skip the second
    /// factor. See `DeviceTrustRules`.
    #[must_use]
    pub fn credentials_changed_at(&self) -> CredentialChange {
        self.credentials_changed_at
    }

    /// Whether an accepted invitation still vouches for the next sign-in.
    /// It does from accepting until the first sign-in after it.
    #[must_use]
    pub fn vouching(&self) -> Vouching {
        self.vouching
    }

    /// Whether this user may sign in now.
    #[must_use]
    pub fn can_authenticate(&self) -> bool {
        self.status.can_authenticate()
    }

    /// Verifies the current address using [`VerifiedEmail`] from mailbox or trusted-provider proof.
    /// Pending verification becomes active with a join time; other statuses remain unchanged.
    /// Raises `identity.email_verified`, after `identity.user_status_changed` if activated.
    ///
    /// # Errors
    /// [`VerificationRefused::OtherAddress`] for proof of a different address.
    /// [`VerificationRefused::Transition`] if status rules refuse activation.
    pub fn verify_email(
        &mut self,
        proof: &VerifiedEmail,
    ) -> Result<(), VerificationRefused<InvalidUserTransition>> {
        self.address.confirm(proof)?;
        self.touch();
        self.finish_onboarding()?;
        self.raised.raise(UserEmailVerified {
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Activates an account that was waiting only on a proven address, and
    /// raises the move as `identity.user_status_changed`, as every other
    /// status change of a stored account is.
    fn finish_onboarding(&mut self) -> Result<(), InvalidUserTransition> {
        if self.status != UserStatus::PendingVerification {
            return Ok(());
        }
        self.apply_transition(UserStatus::Active)?;
        self.status_moved(UserStatus::PendingVerification);
        Ok(())
    }

    /// Replaces the address on administrator or directory authority and marks it unverified.
    /// Raises `identity.email_changed` with both addresses. A holder's proven replacement
    /// instead uses [`Self::change_verified_email`].
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another account's control, missing authority,
    /// or an account holding permissions the actor lacks.
    pub fn change_email(
        &mut self,
        email: Email,
        control: &impl AccountControlCheck,
    ) -> Result<(), DomainError> {
        control.ensure_allowed(&self.id, AccountAction::ChangeSignIn)?;
        let previous = std::mem::replace(&mut self.address, AccountAddress::unverified(email));
        self.touch();
        self.email_moved(&previous);
        Ok(())
    }

    /// Replaces the address with a proven [`VerifiedEmail`] without an unverified interval.
    /// Raises `identity.email_changed` with both addresses. Pending verification becomes
    /// active as in [`Self::verify_email`], raising `identity.user_status_changed` first.
    ///
    /// # Errors
    /// [`InvalidUserTransition`] if the status rules refuse activation.
    pub fn change_verified_email(
        &mut self,
        email: VerifiedEmail,
    ) -> Result<(), InvalidUserTransition> {
        let previous = std::mem::replace(&mut self.address, AccountAddress::verified(email));
        self.touch();
        self.finish_onboarding()?;
        self.email_moved(&previous);
        Ok(())
    }

    /// Records that the user changed how they sign in, at the current time.
    ///
    /// A change is a password set or reset, or a second factor added or
    /// removed. Every device they remembered before now stops counting.
    pub fn record_credential_change(&mut self) {
        self.credentials_changed_at = CredentialChange::At {
            at: crate::shared::clock::now(),
        };
        self.touch();
    }

    /// Lets someone acting on this account replace its password, and records
    /// that change. Raises `identity.password_reset`, naming the account by
    /// name and address.
    ///
    /// Whoever sets the password signs in as the account. So `control` must
    /// show that the person acting holds all the account holds. Sam may edit
    /// users. Without this check, Sam resets the password of Ann, an admin,
    /// signs in as her and holds what she holds. A deactivated account is
    /// refused, since nobody signs in to it again.
    ///
    /// The change is recorded as in
    /// [`record_credential_change`](Self::record_credential_change), so a
    /// device remembered before it stops skipping the second factor.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses it: it was made
    ///   for another account, the person acting lacks the right, or the
    ///   account holds more than them.
    /// - [`DomainError::Conflict`] when the account is deactivated.
    pub fn allow_password_reset(
        &mut self,
        control: &impl AccountControlCheck,
    ) -> Result<AdminPasswordReset<T>, DomainError> {
        control.ensure_allowed(&self.id, AccountAction::ChangeSignIn)?;
        if self.status == UserStatus::Deactivated {
            return Err(DomainError::conflict(message!(
                "identity-a-deactivated-account-s-password-is",
                "a deactivated account's password is not reset"
            )));
        }
        self.record_credential_change();
        self.raised.raise(UserPasswordReset {
            user_id: self.id,
            user_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(AdminPasswordReset::for_account(self.id))
    }

    /// Deletes the account and all its data, once `control` shows the person
    /// acting may erase it. Raises `identity.user_deleted`, naming the
    /// account by the address it had; take it once the account is removed
    /// from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses it: it was made
    ///   for another account, the person acting lacks the right, or the
    ///   account holds more than them.
    /// - [`DomainError::Conflict`] when it is the tenant's last
    ///   administrator.
    pub fn delete(&mut self, control: &impl AccountControlCheck) -> Result<(), DomainError> {
        control.ensure_allowed(&self.id, AccountAction::Erase)?;
        self.record_deletion();
        Ok(())
    }

    /// Records that the user signed in, at the current time. The sign-in
    /// spends whatever an accepted invitation vouched for.
    pub fn record_login(&mut self) {
        self.last_login_at = Some(crate::shared::clock::now());
        self.vouching = Vouching::Absent;
        self.touch();
    }

    /// Moves the status to `target` when the status rules allow it.
    ///
    /// Reaching `Active` is joining. It counts the same whether the user
    /// accepted an invitation, verified an email or was activated by an
    /// admin. So the join time is recorded here on every move to `Active`,
    /// not at each caller. Only the first join is kept.
    fn apply_transition(
        &mut self,
        target: UserStatus,
    ) -> Result<UserStatus, InvalidUserTransition> {
        let new_status = self.status.try_transition(target)?;
        self.status = new_status;
        if new_status == UserStatus::Active {
            self.joining = self.joining.join_at(crate::shared::clock::now());
        }
        self.touch();
        Ok(new_status)
    }

    /// Sets the change time to now.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

/// A user is the root of its own aggregate in one tenant. It owns its
/// address, status and preferences.
impl<T: TenantScope> Aggregate for User<T> {
    /// A user is known by its [`UserId`].
    type Id = UserId;

    /// The user's id.
    fn id(&self) -> &Self::Id {
        &self.id
    }

    /// When this user was registered, invited or provisioned.
    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this user was last modified.
    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::domains::authentication::mfa::owed::SecondFactor;
    use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use crate::domains::authentication::sessions::sign_in_progress::{
        LocalMethod, SignInProgress, SignedIn,
    };
    use crate::domains::authorization::granter::{AccountControl, Handout, HeldByGranter};
    use crate::domains::authorization::permission::{RoleAction, SystemPermission, UserAction};
    use crate::domains::identity::account::user::directory::DirectorySwitch;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::DomainLimits;
    use crate::shared::events::event::DomainEvent;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::{anyone_holding, user_adder};
    use crate::test_support::events::{raised, raised_names};

    fn cfg() -> DomainLimits {
        DomainLimits::default()
    }

    fn test_user() -> User<ResolvedTenant> {
        let c = cfg();
        User::<ResolvedTenant>::register(
            UserId::new(),
            Email::new("alice@example.com").unwrap(),
            DisplayName::new("Alice Smith", &c.display_name).unwrap(),
            &user_adder(),
        )
        .unwrap()
    }

    /// A user past onboarding: registered, verified, and able to sign in.
    fn active_user() -> User<ResolvedTenant> {
        let mut user = test_user();
        user.verify_email(&proof_of(user.email())).unwrap();
        user
    }

    fn invited_user() -> User<ResolvedTenant> {
        let c = cfg();
        User::<ResolvedTenant>::invite(
            UserId::new(),
            Email::new("bob@example.com").unwrap(),
            DisplayName::new("Bob Jones", &c.display_name).unwrap(),
            &user_adder(),
        )
        .unwrap()
    }

    /// User-view authority cannot register or invite an account, while
    /// user-creation authority permits both operations.
    #[test]
    fn only_someone_who_may_add_users_opens_an_account() {
        let c = cfg();
        let sam = HeldByGranter::assumed(&[SystemPermission::Users(UserAction::View)], &[]);
        let open = |creator: &HeldByGranter<'_>| {
            let email = || Email::new("sam.second@example.com").unwrap();
            let name = || DisplayName::new("Sam Two", &c.display_name).unwrap();
            (
                User::<ResolvedTenant>::register(UserId::new(), email(), name(), creator),
                User::<ResolvedTenant>::invite(UserId::new(), email(), name(), creator),
            )
        };

        let (registered, invited) = open(&sam);
        let (by_adder_registered, by_adder_invited) = open(&user_adder());

        assert!(matches!(registered, Err(DomainError::Forbidden(_))));
        assert!(matches!(invited, Err(DomainError::Forbidden(_))));
        assert!(by_adder_registered.is_ok() && by_adder_invited.is_ok());
    }

    /// Alice registers with alice@example.com. She waits on verification,
    /// her address is unverified and she has never signed in.
    #[test]
    fn register_creates_an_unverified_user_awaiting_confirmation() {
        let user = test_user();

        assert_eq!(user.status(), UserStatus::PendingVerification);
        assert!(!user.email_verified());
        assert_eq!(user.email().as_str(), "alice@example.com");
        assert_eq!(user.display_name().as_str(), "Alice Smith");
        assert!(user.last_login_at().is_none());
    }

    /// An admin invites Bob. His account starts invited with bob@example.com
    /// unverified.
    #[test]
    fn invite_creates_invited_unverified_user() {
        let user = invited_user();

        assert_eq!(user.status(), UserStatus::Invited);
        assert!(!user.email_verified());
        assert_eq!(user.email().as_str(), "bob@example.com");
    }

    /// A new account is stamped with the time it was registered. Its change
    /// time starts equal to its creation time.
    #[test]
    fn register_sets_timestamps() {
        let before = crate::shared::clock::now();
        let user = test_user();
        let after = crate::shared::clock::now();

        assert!(user.created_at() >= before);
        assert!(user.created_at() <= after);
        assert_eq!(user.created_at(), user.updated_at());
    }

    /// An admin who holds all Bob holds activates his invited account. It is
    /// now active.
    #[test]
    fn invited_user_can_activate() {
        let mut user = invited_user();

        user.activate(&control_over(&user)).unwrap();

        assert_eq!(user.status(), UserStatus::Active);
    }

    /// An admin withdraws Bob before he accepts. His invited account can be
    /// deactivated directly.
    #[test]
    fn invited_user_can_deactivate() {
        let mut user = invited_user();

        user.deactivate(&control_over(&user)).unwrap();

        assert_eq!(user.status(), UserStatus::Deactivated);
    }

    /// Bob has not accepted his invitation yet. Locking his account is
    /// refused, since only an active account can be locked.
    #[test]
    fn invited_user_cannot_lock() {
        let mut user = invited_user();

        assert!(user.lock(&control_over(&user)).is_err());
    }

    /// An admin locks Alice's active account. It is now locked.
    #[test]
    fn active_user_can_lock() {
        let mut user = active_user();

        user.lock(&control_over(&user)).unwrap();

        assert_eq!(user.status(), UserStatus::Locked);
    }

    /// An admin deactivates Alice's active account. It is now deactivated.
    #[test]
    fn active_user_can_deactivate() {
        let mut user = active_user();

        user.deactivate(&control_over(&user)).unwrap();

        assert_eq!(user.status(), UserStatus::Deactivated);
    }

    /// Alice is locked out and an admin unlocks her. Her account is active
    /// again.
    #[test]
    fn locked_user_can_unlock() {
        let mut user = active_user();
        user.lock(&control_over(&user)).unwrap();

        user.unlock(&control_over(&user)).unwrap();

        assert_eq!(user.status(), UserStatus::Active);
    }

    /// Alice is locked out and an admin deactivates her without unlocking
    /// first. The account is deactivated.
    #[test]
    fn locked_user_can_deactivate() {
        let mut user = active_user();
        user.lock(&control_over(&user)).unwrap();

        user.deactivate(&control_over(&user)).unwrap();

        assert_eq!(user.status(), UserStatus::Deactivated);
    }

    /// Alice's account was switched off by mistake. Locking and unlocking it
    /// are refused. An admin activates it, and it keeps the date she first
    /// joined.
    #[test]
    fn a_deactivated_user_comes_back_only_by_activation() {
        let mut user = active_user();
        let joined = user.joined_at();
        user.deactivate(&control_over(&user)).unwrap();

        assert!(user.lock(&control_over(&user)).is_err());
        assert!(user.unlock(&control_over(&user)).is_err());
        assert!(matches!(
            user.activate(&control_over(&user)),
            Ok(UserStatus::Active)
        ));
        assert_eq!(user.joined_at(), joined);
    }

    /// User-update authority cannot deactivate Carol or reactivate her
    /// after an administrator deactivates her. She remains deactivated.
    #[test]
    fn shutting_out_and_letting_in_both_need_the_right_to_deactivate() {
        let mut carol = active_user();
        let updater = AccountControl::assumed(
            anyone_holding(&[SystemPermission::Users(UserAction::Update)]),
            *carol.id(),
            crate::domains::authorization::stewardship::Stewardship::OthersAdminister,
            Handout::NOTHING,
        );

        let shut_out = carol.deactivate(&updater);
        carol.deactivate(&control_over(&carol)).unwrap();
        let let_in = carol.activate(&updater);

        assert!(matches!(shut_out, Err(DomainError::Forbidden(_))));
        assert!(matches!(let_in, Err(DomainError::Forbidden(_))));
        assert_eq!(carol.status(), UserStatus::Deactivated);
    }

    /// Authority bound to Bob cannot change Ann's email address, which
    /// remains unchanged after the refusal.
    #[test]
    fn a_check_for_another_account_changes_nothing() {
        let mut ann = active_user();
        let bob = active_user();
        let before = ann.email().clone();

        let result = ann.change_email(Email::new("x@example.com").unwrap(), &control_over(&bob));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.email(), &before);
    }

    /// Only an active account may sign in. Invited, unverified, locked and
    /// deactivated accounts may not.
    #[test]
    fn only_active_can_authenticate() {
        assert!(active_user().can_authenticate());
        assert!(!invited_user().can_authenticate());
        assert!(!test_user().can_authenticate());

        let mut locked = active_user();
        locked.lock(&control_over(&locked)).unwrap();
        assert!(!locked.can_authenticate());

        let mut deactivated = active_user();
        deactivated.deactivate(&control_over(&deactivated)).unwrap();
        assert!(!deactivated.can_authenticate());
    }

    /// Alice follows the link sent to her own address. Her address is now
    /// verified.
    #[test]
    fn verify_email_sets_flag() {
        let mut user = test_user();

        user.verify_email(&proof_of(user.email())).unwrap();

        assert!(user.email_verified());
    }

    /// Alice's verified address is corrected by an admin to
    /// alice-new@example.com. Nobody proved the new one, so it is unverified.
    #[test]
    fn change_email_resets_verification() {
        let mut user = test_user();
        user.verify_email(&proof_of(user.email())).unwrap();

        user.change_email(
            Email::new("alice-new@example.com").unwrap(),
            &control_over(&user),
        )
        .unwrap();

        assert_eq!(user.email().as_str(), "alice-new@example.com");
        assert!(!user.email_verified());
    }

    /// Alice confirms a change to alice-new@example.com. The account moves
    /// to that address and it is verified.
    #[test]
    fn change_verified_email_stays_verified() {
        let mut user = test_user();
        assert!(!user.email_verified());

        user.change_verified_email(VerifiedEmail::proven(
            Email::new("alice-new@example.com").unwrap(),
        ))
        .unwrap();

        assert_eq!(user.email().as_str(), "alice-new@example.com");
        assert!(user.email_verified());
    }

    /// Alice has not verified her first address and confirms a change to a
    /// new one. The proved address finishes onboarding, so she becomes
    /// active and gets a join time.
    #[test]
    fn a_proven_address_change_finishes_onboarding() {
        let mut user = test_user();

        user.change_verified_email(VerifiedEmail::proven(
            Email::new("alice-new@example.com").unwrap(),
        ))
        .unwrap();

        assert_eq!(user.status(), UserStatus::Active);
        assert!(user.joined_at().is_some());
    }

    /// A stored account waits on verification but its address is already
    /// verified. That cannot happen, so the row is refused as corrupt.
    #[test]
    fn a_stored_account_waiting_on_an_address_it_has_proven_is_refused() {
        let row = UserRow {
            email_standing: AddressStanding::Verified,
            ..stored_user(UserStatus::PendingVerification, Joining::NotYet)
        };

        assert!(refused_as_corrupt(&User::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// A stored account is still invited, yet an invitation vouches for its
    /// next sign-in. Only accepting vouches, and accepting joins, so the row
    /// is refused as corrupt.
    #[test]
    fn a_stored_account_vouched_for_before_it_joined_is_refused() {
        let row = UserRow {
            vouching: Vouching::Fresh,
            ..stored_user(UserStatus::Invited, Joining::NotYet)
        };

        assert!(refused_as_corrupt(&User::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// Alice Smith renames herself Alice Johnson from her own sign-in. The
    /// account shows the new name.
    #[test]
    fn the_holder_renames_their_own_account() {
        let c = cfg();
        let mut user = test_user();
        let alice = holder_of(&user);

        user.rename(
            DisplayName::new("Alice Johnson", &c.display_name).unwrap(),
            &alice,
        )
        .unwrap();

        assert_eq!(user.display_name().as_str(), "Alice Johnson");
    }

    /// An admin who may update users fixes the spelling of Alice's name and
    /// sets her language and timezone. All three are kept.
    #[test]
    fn an_admin_with_the_right_edits_someone_elses_profile() {
        let c = cfg();
        let mut user = active_user();
        let admin = control_over(&user);

        user.rename(
            DisplayName::new("Alice Smyth", &c.display_name).unwrap(),
            &admin,
        )
        .unwrap();
        user.change_locale(Preference::Own(Locale::new("de-DE").unwrap()), &admin)
            .unwrap();
        user.change_timezone(
            Preference::Own(Timezone::new("Europe/Berlin").unwrap()),
            &admin,
        )
        .unwrap();

        assert_eq!(user.display_name().as_str(), "Alice Smyth");
        assert_eq!(user.locale().value().unwrap().as_str(), "de-DE");
        assert_eq!(user.timezone().value().unwrap().as_str(), "Europe/Berlin");
    }

    /// Another person's sign-in cannot change Ann's name, locale or
    /// timezone; all three retain their original values.
    #[test]
    fn someone_else_signed_in_cannot_edit_a_profile() {
        let c = cfg();
        let mut ann = active_user();
        let bob = signed_in_as::<ResolvedTenant>(UserId::new());

        let renamed = ann.rename(
            DisplayName::new("Former employee", &c.display_name).unwrap(),
            &bob,
        );
        let relocalized = ann.change_locale(Preference::Own(Locale::new("de-DE").unwrap()), &bob);
        let moved = ann.change_timezone(
            Preference::Own(Timezone::new("Europe/Berlin").unwrap()),
            &bob,
        );

        assert!(matches!(renamed, Err(DomainError::Forbidden(_))));
        assert!(matches!(relocalized, Err(DomainError::Forbidden(_))));
        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.display_name().as_str(), "Alice Smith");
        assert_eq!(ann.locale(), &Preference::Inherited);
        assert_eq!(ann.timezone(), &Preference::Inherited);
    }

    /// User-view authority cannot rename Ann, whose display name remains
    /// unchanged after the forbidden response.
    #[test]
    fn someone_without_the_right_cannot_edit_a_profile() {
        let c = cfg();
        let mut ann = active_user();
        let sam = AccountControl::assumed(
            anyone_holding(&[SystemPermission::Users(UserAction::View)]),
            *ann.id(),
            crate::domains::authorization::stewardship::Stewardship::OthersAdminister,
            Handout::NOTHING,
        );

        let renamed = ann.rename(
            DisplayName::new("Former employee", &c.display_name).unwrap(),
            &sam,
        );

        assert!(matches!(renamed, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.display_name().as_str(), "Alice Smith");
    }

    /// Alice has never signed in. After a sign-in is recorded, the account
    /// has a last sign-in time.
    #[test]
    fn record_login_sets_last_login() {
        let mut user = test_user();
        assert!(user.last_login_at().is_none());

        user.record_login();

        assert!(user.last_login_at().is_some());
    }

    /// Proof of another mailbox is refused and leaves Alice's address
    /// unverified and her account waiting for verification.
    #[test]
    fn a_proof_for_another_address_does_not_verify_the_account() {
        let mut user = test_user();

        let refused = user.verify_email(&proof_of(&Email::new("someone@else.example").unwrap()));

        assert_eq!(refused, Err(VerificationRefused::OtherAddress));
        assert!(!user.email_verified());
        assert_eq!(user.status(), UserStatus::PendingVerification);
    }

    /// A trusted provider vouches for alice@acme.com and her account is
    /// provisioned. It starts active and verified, with a join time.
    #[test]
    fn a_provisioned_account_is_active_with_its_proven_address_verified() {
        let c = cfg();
        let address = Email::new("alice@acme.com").unwrap();

        let user = User::<ResolvedTenant>::provision(
            UserId::new(),
            VerifiedEmail::proven(address.clone()),
            DisplayName::new("Alice", &c.display_name).unwrap(),
        );

        assert_eq!(user.email(), &address);
        assert!(user.email_verified());
        assert_eq!(user.status(), UserStatus::Active);
        assert!(user.joined_at().is_some());
    }

    /// A registered or invited account has never changed how it signs in, so
    /// no remembered device is cut off yet.
    #[test]
    fn a_new_user_has_never_changed_credentials() {
        assert!(test_user().credentials_changed_at() == CredentialChange::Never);
        assert!(invited_user().credentials_changed_at() == CredentialChange::Never);
    }

    /// Alice resets her password with the clock frozen. The change is
    /// recorded at that exact time.
    #[test]
    fn a_credential_change_is_recorded_at_the_moment_it_happens() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let mut user = test_user();

        let _frozen = crate::shared::clock::freeze(now);
        user.record_credential_change();

        assert_eq!(user.credentials_changed_at().changed_at(), Some(now));
    }

    /// Verifying the address moves the account's change time forward.
    #[test]
    fn verify_email_updates_timestamp() {
        let mut user = test_user();
        let before = user.updated_at();

        user.verify_email(&proof_of(user.email())).unwrap();

        assert!(user.updated_at() >= before);
    }

    /// Locking the account moves its change time forward.
    #[test]
    fn lock_updates_timestamp() {
        let mut user = active_user();
        let before = user.updated_at();

        user.lock(&control_over(&user)).unwrap();

        assert!(user.updated_at() >= before);
    }

    /// A verified, locked account whose join, sign-in and credential change share a time.
    fn locked_row(id: UserId, email: Email, name: DisplayName, now: OffsetDateTime) -> UserRow {
        UserRow {
            id,
            email,
            display_name: name,
            status: UserStatus::Locked,
            email_standing: AddressStanding::Verified,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            profile: UserProfile::default(),
            created_at: now,
            updated_at: now,
            last_login_at: Some(now),
            joining: Joining::from_stored(Some(now)),
            credentials_changed_at: CredentialChange::from_stored(Some(now)),
            vouching: Vouching::Absent,
        }
    }

    /// A locked, verified account with a sign-in time is loaded from
    /// storage. Every field reads back as it was stored.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let c = cfg();
        let id = UserId::new();
        let email = Email::new("alice@example.com").unwrap();
        let name = DisplayName::new("Alice", &c.display_name).unwrap();
        let now = crate::shared::clock::now();
        let login = Some(now);

        let row = locked_row(id, email.clone(), name.clone(), now);
        let user = User::<ResolvedTenant>::reconstitute(row).unwrap();

        assert_eq!(user.credentials_changed_at().changed_at(), login);
        assert_eq!(*user.id(), id);
        assert_eq!(user.email(), &email);
        assert_eq!(user.display_name(), &name);
        assert_eq!(user.status(), UserStatus::Locked);
        assert!(user.email_verified());
        assert_eq!(user.created_at(), now);
        assert_eq!(user.updated_at(), now);
        assert_eq!(user.last_login_at(), login);
        assert_eq!(user.joined_at(), login);
    }

    /// A registered or invited account has not joined yet, so it has no
    /// join time.
    #[test]
    fn factories_leave_joined_at_none() {
        assert!(test_user().joined_at().is_none());
        assert!(invited_user().joined_at().is_none());
    }

    /// Bob joins, is locked out and is let back in. His join time stays the
    /// first one, since he has not joined twice.
    #[test]
    fn returning_to_active_keeps_the_original_join() {
        let mut user = invited_user();
        user.activate(&control_over(&user)).unwrap();
        let first = user.joined_at().expect("joined on activation");

        user.lock(&control_over(&user)).unwrap();
        user.unlock(&control_over(&user)).unwrap();

        assert_eq!(user.joined_at(), Some(first));
    }

    /// Bob is invited and deactivated before he accepts. He never became
    /// active, so he has no join time.
    #[test]
    fn a_user_who_never_reached_active_has_not_joined() {
        let mut user = invited_user();

        user.deactivate(&control_over(&user)).unwrap();

        assert!(user.joined_at().is_none());
    }

    /// Alice registers and has not followed her link. She waits on
    /// verification and may not sign in.
    #[test]
    fn a_registered_user_waits_on_verification_and_cannot_authenticate() {
        let user = test_user();

        assert_eq!(user.status(), UserStatus::PendingVerification);
        assert!(!user.email_verified());
        assert!(!user.can_authenticate());
    }

    /// Alice follows her verification link. With no separate step she is
    /// active, verified, may sign in and has a join time.
    #[test]
    fn verifying_the_email_activates_a_pending_user_and_records_the_join() {
        let mut user = test_user();

        user.verify_email(&proof_of(user.email())).unwrap();

        assert_eq!(user.status(), UserStatus::Active);
        assert!(user.email_verified());
        assert!(user.can_authenticate());
        assert!(user.joined_at().is_some());
    }

    /// Verifying a replacement address on a deactivated account does not
    /// reactivate it.
    #[test]
    fn verifying_an_email_does_not_revive_a_deactivated_account() {
        let mut user = test_user();
        user.verify_email(&proof_of(user.email())).unwrap();
        user.deactivate(&control_over(&user)).unwrap();
        user.change_email(Email::new("new@example.com").unwrap(), &control_over(&user))
            .unwrap();

        user.verify_email(&proof_of(user.email())).unwrap();

        assert_eq!(user.status(), UserStatus::Deactivated);
    }

    /// Verifying an address again leaves the account locked.
    #[test]
    fn verifying_an_email_does_not_unlock_a_locked_account() {
        let mut user = test_user();
        user.verify_email(&proof_of(user.email())).unwrap();
        user.lock(&control_over(&user)).unwrap();

        user.verify_email(&proof_of(user.email())).unwrap();

        assert_eq!(user.status(), UserStatus::Locked);
    }

    /// Bob's invited account is activated. Leaving invited for active is
    /// joining, so he gets a join time.
    #[test]
    fn activating_an_invited_user_records_the_join() {
        let mut user = invited_user();

        user.activate(&control_over(&user)).unwrap();

        assert!(
            user.joined_at().is_some(),
            "leaving Invited for Active is joining"
        );
    }

    /// Bob's invited account is deactivated. That is not joining, so he has
    /// no join time.
    #[test]
    fn deactivating_an_invited_user_does_not_record_a_join() {
        let mut user = invited_user();

        user.deactivate(&control_over(&user)).unwrap();

        assert!(user.joined_at().is_none());
    }

    /// Unlocking an account that is still invited is refused; it retains
    /// invited status and has no join time.
    #[test]
    fn unlocking_an_account_that_never_finished_onboarding_is_refused() {
        let mut invited = invited_user();

        let result = invited.unlock(&control_over(&invited));

        assert!(result.is_err());
        assert_eq!(invited.status(), UserStatus::Invited);
        assert!(invited.joined_at().is_none());
    }

    /// Bob joins, is locked and is unlocked. Unlocking keeps his first join
    /// time.
    #[test]
    fn unlocking_does_not_overwrite_the_original_join() {
        let mut user = invited_user();
        user.activate(&control_over(&user)).unwrap();
        let joined = user.joined_at();
        user.lock(&control_over(&user)).unwrap();

        user.unlock(&control_over(&user)).unwrap();

        assert_eq!(user.joined_at(), joined);
    }

    /// Alice starts on the tenant's locale and timezone, then picks de-DE
    /// and Europe/Berlin. Her choices read back, so she is not shown the
    /// tenant's language instead.
    #[test]
    fn a_user_keeps_the_locale_and_timezone_they_chose() {
        let mut user = test_user();
        let alice = holder_of(&user);

        assert_eq!(user.locale(), &Preference::Inherited);
        assert_eq!(user.timezone(), &Preference::Inherited);

        user.change_locale(Preference::Own(Locale::new("de-DE").unwrap()), &alice)
            .unwrap();
        user.change_timezone(
            Preference::Own(Timezone::new("Europe/Berlin").unwrap()),
            &alice,
        )
        .unwrap();

        assert_eq!(user.locale().value().unwrap().as_str(), "de-DE");
        assert_eq!(user.timezone().value().unwrap().as_str(), "Europe/Berlin");
    }

    /// Alice keeps the id she was registered with, which sessions, roles and
    /// audit lines refer to. Renaming her five minutes later moves the change
    /// time to then and leaves the creation time alone.
    #[test]
    fn a_user_carries_their_id_and_moves_the_timestamp_when_edited() {
        let c = cfg();
        let id = UserId::new();
        let mut user = User::<ResolvedTenant>::register(
            id,
            Email::new("alice@example.com").unwrap(),
            DisplayName::new("Alice Smith", &c.display_name).unwrap(),
            &user_adder(),
        )
        .unwrap();
        let created = user.created_at();
        let later = user.updated_at() + time::Duration::minutes(5);

        assert_eq!(*user.id(), id);
        assert_eq!(Aggregate::id(&user), user.id());

        let _frozen = crate::shared::clock::freeze(later);
        user.rename(
            DisplayName::new("Alice S.", &c.display_name).unwrap(),
            &holder_of(&user),
        )
        .unwrap();

        assert_eq!(user.updated_at(), later);
        assert_eq!(user.created_at(), created);
    }

    fn stored_user(status: UserStatus, joining: Joining) -> UserRow {
        let now = crate::shared::clock::now();
        UserRow {
            id: UserId::new(),
            email: Email::new("alice@example.com").unwrap(),
            display_name: DisplayName::new("Alice", &cfg().display_name).unwrap(),
            status,
            email_standing: AddressStanding::Unverified,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            profile: UserProfile::default(),
            created_at: now,
            updated_at: now,
            last_login_at: None,
            joining,
            credentials_changed_at: CredentialChange::Never,
            vouching: Vouching::Absent,
        }
    }

    /// A stored account is still invited but says it already joined. It is
    /// refused as corrupt, so it cannot skip the activation it waits for.
    #[test]
    fn a_stored_user_joined_while_still_invited_is_refused() {
        let row = stored_user(
            UserStatus::Invited,
            Joining::Joined {
                at: crate::shared::clock::now(),
            },
        );

        assert!(refused_as_corrupt(&User::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// A stored account says it signed in one second before it was created.
    /// It is refused as corrupt.
    #[test]
    fn a_stored_user_signed_in_before_it_was_created_is_refused() {
        let mut row = stored_user(UserStatus::Active, Joining::NotYet);
        row.joining = Joining::Joined { at: row.created_at };
        row.last_login_at = Some(row.created_at - time::Duration::SECOND);

        assert!(refused_as_corrupt(&User::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// Alice picked de-DE and then switches back. She follows the tenant's
    /// locale again.
    #[test]
    fn a_user_can_go_back_to_the_tenants_locale() {
        let mut user = test_user();
        let alice = holder_of(&user);
        user.change_locale(Preference::Own(Locale::new("de-DE").unwrap()), &alice)
            .unwrap();

        user.change_locale(Preference::Inherited, &alice).unwrap();

        assert_eq!(user.locale(), &Preference::Inherited);
    }

    /// Stored active and locked accounts without a join date are rejected
    /// as corrupt.
    #[test]
    fn a_stored_active_or_locked_user_with_no_join_date_is_refused() {
        for status in [UserStatus::Active, UserStatus::Locked] {
            let row = stored_user(status, Joining::NotYet);

            assert!(
                refused_as_corrupt(&User::<ResolvedTenant>::reconstitute(row)),
                "{status:?}"
            );
        }
    }

    /// Proof that the holder of `account` finished signing in to tenant `T`.
    pub(crate) fn signed_in_as<T: TenantScope>(account: UserId) -> SignedIn<T> {
        let progress = SignInProgress::begin(
            LocalMethod::Password,
            SecondFactor::NotOwed,
            &StepUpPolicy::relaxed(),
        )
        .unwrap();
        SignedIn::of(account.into(), progress)
    }

    /// Proof that the holder of `user` is the one signed in now.
    fn holder_of(user: &User<ResolvedTenant>) -> SignedIn<ResolvedTenant> {
        signed_in_as(*user.id())
    }

    /// An admin who may manage users, acting on `user`, which holds nothing.
    /// For tests whose subject is not who may act.
    pub(crate) fn control_over<T: TenantScope>(user: &User<T>) -> AccountControl<'static> {
        AccountControl::assumed(
            anyone_holding(&[SystemPermission::Users(UserAction::Manage)]),
            *user.id(),
            crate::domains::authorization::stewardship::Stewardship::OthersAdminister,
            Handout::NOTHING,
        )
    }

    /// Sam, who may edit users, acting on Ann, who may also manage roles.
    fn sam_on(ann: &User<ResolvedTenant>) -> AccountControl<'static> {
        AccountControl::assumed(
            anyone_holding(&[SystemPermission::Users(UserAction::Update)]),
            *ann.id(),
            crate::domains::authorization::stewardship::Stewardship::OthersAdminister,
            Handout {
                system: &[
                    SystemPermission::Users(UserAction::Update),
                    SystemPermission::Roles(RoleAction::Manage),
                ],
                custom: &[],
            },
        )
    }

    /// An editor holding less than Ann cannot reset her password; her
    /// credential-change marker remains unset.
    #[test]
    fn a_password_reset_by_someone_holding_less_is_refused() {
        let mut ann = active_user();

        let result = ann.allow_password_reset(&sam_on(&ann));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(ann.credentials_changed_at() == CredentialChange::Never);
    }

    /// An admin who holds all Alice holds resets her password. The leave
    /// names her account, and the change is recorded so her remembered
    /// devices stop skipping the second factor.
    #[test]
    fn a_password_reset_by_a_peer_names_the_account_and_records_the_change() {
        let mut alice = active_user();

        let reset = alice.allow_password_reset(&control_over(&alice)).unwrap();

        assert_eq!(reset.user_id(), alice.id());
        assert!(alice.credentials_changed_at().changed_at().is_some());
    }

    /// Resetting a deactivated account's password returns a conflict even
    /// for an administrator.
    #[test]
    fn a_deactivated_account_gets_no_password_reset() {
        let mut alice = active_user();
        alice.deactivate(&control_over(&alice)).unwrap();

        let result = alice.allow_password_reset(&control_over(&alice));

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// An editor holding less than Ann cannot replace her email; the
    /// original address remains verified.
    #[test]
    fn an_address_change_by_someone_holding_less_is_refused() {
        let mut ann = active_user();
        let before = ann.email().clone();

        let result = ann.change_email(Email::new("sam@example.com").unwrap(), &sam_on(&ann));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.email(), &before);
        assert!(ann.email_verified());
    }

    /// An editor holding less than Ann cannot lock her account, which
    /// remains active.
    #[test]
    fn locking_an_account_that_holds_more_is_refused() {
        let mut ann = active_user();

        let result = ann.lock(&sam_on(&ann));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.status(), UserStatus::Active);
    }

    /// An editor holding less than Ann cannot unlock her account, which
    /// remains locked.
    #[test]
    fn unlocking_an_account_that_holds_more_is_refused() {
        let mut ann = active_user();
        ann.lock(&control_over(&ann)).unwrap();

        let result = ann.unlock(&sam_on(&ann));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.status(), UserStatus::Locked);
    }

    /// An editor holding less than Ann cannot deactivate her account,
    /// which remains active.
    #[test]
    fn deactivating_an_account_that_holds_more_is_refused() {
        let mut ann = active_user();

        let result = ann.deactivate(&sam_on(&ann));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.status(), UserStatus::Active);
    }

    /// An editor holding less than the invitee cannot activate the
    /// account, which remains invited.
    #[test]
    fn activating_an_account_that_holds_more_is_refused() {
        let mut ann = invited_user();

        let result = ann.activate(&sam_on(&ann));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(ann.status(), UserStatus::Invited);
    }

    /// Alice's account as storage keeps it, active since it joined.
    fn stored_active() -> User<ResolvedTenant> {
        let mut row = stored_user(UserStatus::Active, Joining::NotYet);
        row.joining = Joining::Joined { at: row.created_at };
        User::reconstitute(row).unwrap()
    }

    /// The label an event names the user under.
    fn user_label_of(event: &DomainEvent) -> String {
        match event.payload().value("user") {
            Some(crate::shared::events::data::FieldValue::Reference(reference)) => {
                reference.label().to_owned()
            }
            other => panic!("user is not a reference: {other:?}"),
        }
    }

    /// Alice registers and Bob is invited. Each opening is raised.
    #[test]
    fn opening_an_account_raises_how_it_was_opened() {
        let mut alice = test_user();
        let mut bob = invited_user();

        assert_eq!(raised_names(&mut alice), ["identity.user_registered"]);
        assert_eq!(raised_names(&mut bob), ["identity.user_invited"]);
    }

    /// An admin registers Alice and lets her in straight away. The move is
    /// part of opening her account, so only the registration is raised.
    #[test]
    fn a_status_move_of_an_account_opened_in_the_same_change_is_not_raised() {
        let mut alice = test_user();

        alice.activate(&control_over(&alice)).unwrap();

        assert_eq!(raised_names(&mut alice), ["identity.user_registered"]);
    }

    /// An admin locks Alice and unlocks her again. Each move is raised,
    /// naming her by name and address.
    #[test]
    fn an_admins_status_moves_are_raised_one_by_one() {
        let mut alice = stored_active();
        let admin = control_over(&alice);

        alice.lock(&admin).unwrap();
        alice.unlock(&admin).unwrap();

        let events = raised(&mut alice);
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event.event_type().to_string() == "identity.user_status_changed")
        );
        assert_eq!(user_label_of(&events[0]), "Alice (alice@example.com)");
    }

    /// The directory switches Alice off and back on in one change. Neither
    /// move is raised on its own, and as her status ends where it began,
    /// closing the change raises nothing either.
    #[test]
    fn a_directory_change_that_ends_where_it_began_raises_nothing() {
        let mut alice = stored_active();
        let admin = control_over(&alice);

        alice
            .switch_by_directory(DirectorySwitch::ShutOut, &admin)
            .unwrap();
        alice
            .switch_by_directory(DirectorySwitch::LetIn, &admin)
            .unwrap();
        alice.close_directory_change();

        assert!(raised_names(&mut alice).is_empty());
    }

    /// The directory switches Alice off. Closing its change raises the one
    /// move, naming her by address, the way the directory knows her.
    #[test]
    fn closing_a_directory_change_raises_the_whole_move_by_address() {
        let mut alice = stored_active();

        alice
            .switch_by_directory(DirectorySwitch::ShutOut, &control_over(&alice))
            .unwrap();
        alice.close_directory_change();

        let events = raised(&mut alice);
        assert_eq!(events.len(), 1);
        assert_eq!(user_label_of(&events[0]), "alice@example.com");
        assert_eq!(alice.status(), UserStatus::Locked);
    }

    /// Alice follows her link and confirms her address. That is raised.
    #[test]
    fn confirming_an_address_is_raised() {
        let mut alice = test_user();
        raised_names(&mut alice);

        alice.verify_email(&proof_of(alice.email())).unwrap();

        assert_eq!(raised_names(&mut alice), ["identity.email_verified"]);
    }

    /// Alice's account, read back from storage, waits for her address.
    /// Confirming it moves her to active, and that move is raised as every
    /// other status change is, before the confirmation.
    #[test]
    fn confirming_the_address_of_a_waiting_account_raises_its_activation() {
        let mut alice = User::<ResolvedTenant>::reconstitute(stored_user(
            UserStatus::PendingVerification,
            Joining::NotYet,
        ))
        .unwrap();

        alice.verify_email(&proof_of(alice.email())).unwrap();

        assert_eq!(alice.status(), UserStatus::Active);
        assert_eq!(
            raised_names(&mut alice),
            ["identity.user_status_changed", "identity.email_verified"]
        );
    }

    /// An admin moves Alice to a new address, renames her and sets her
    /// language. Each change is raised, in order.
    #[test]
    fn profile_and_address_changes_are_raised_in_order() {
        let c = cfg();
        let mut alice = stored_active();
        let admin = control_over(&alice);

        alice
            .change_email(Email::new("alice@new.example").unwrap(), &admin)
            .unwrap();
        alice
            .rename(
                DisplayName::new("Alice Smyth", &c.display_name).unwrap(),
                &admin,
            )
            .unwrap();
        alice
            .change_preferences(
                Some(Preference::Own(Locale::new("de-DE").unwrap())),
                None,
                &admin,
            )
            .unwrap();

        assert_eq!(
            raised_names(&mut alice),
            [
                "identity.email_changed",
                "identity.user_renamed",
                "identity.user_preferences_updated",
            ]
        );
    }

    /// An admin resets Alice's password and later deletes her account; the
    /// directory deletes Bob's. Each is raised.
    #[test]
    fn a_password_reset_and_deletions_are_raised() {
        let mut alice = stored_active();
        let mut bob = stored_active();
        let admin = control_over(&alice);

        alice.allow_password_reset(&admin).unwrap();
        alice.delete(&admin).unwrap();
        bob.delete_by_directory(&control_over(&bob)).unwrap();

        assert_eq!(
            raised_names(&mut alice),
            ["identity.password_reset", "identity.user_deleted"]
        );
        assert_eq!(raised_names(&mut bob), ["identity.user_deleted"]);
    }

    /// A link to confirm Alice's address and her welcome mail go out. Each
    /// is raised, and nothing about her account changes.
    #[test]
    fn mail_that_went_out_is_raised() {
        let mut alice = stored_active();
        let changed = alice.updated_at();

        alice.note_verification_mailed();
        alice.note_welcome_mailed();

        assert_eq!(
            raised_names(&mut alice),
            [
                "identity.verification_email_sent",
                "identity.welcome_email_sent",
            ]
        );
        assert_eq!(alice.updated_at(), changed);
    }

    /// Locking and password reset by a lesser editor, and renaming from
    /// another person's session, are refused without raising events.
    #[test]
    fn a_refused_account_change_raises_nothing() {
        let c = cfg();
        let mut ann = stored_active();
        let bob = signed_in_as::<ResolvedTenant>(UserId::new());

        let locked = ann.lock(&sam_on(&ann));
        let reset = ann.allow_password_reset(&sam_on(&ann));
        let renamed = ann.rename(DisplayName::new("Former", &c.display_name).unwrap(), &bob);

        assert!(locked.is_err() && reset.is_err() && renamed.is_err());
        assert!(raised_names(&mut ann).is_empty());
    }

    /// Alice's account is read back from storage. Loading it raises
    /// nothing.
    #[test]
    fn an_account_read_back_from_storage_has_raised_nothing() {
        let mut alice = stored_active();

        assert!(raised_names(&mut alice).is_empty());
    }
}
