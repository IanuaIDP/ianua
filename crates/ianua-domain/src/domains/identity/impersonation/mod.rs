//! A tenant admin acting as one of the tenant's people for a short while,
//! to see what they see and put it right.
//!
//! Acting as someone is holding all they hold, so the admin needs full
//! control of users and must hold at least what the person holds. It has a
//! reason, which the audit trail keeps, and a window of at most an hour.
//! The tenant decides whether the person must approve first. Either side
//! may end it early.

/// Where a request stands, its window and whether the person agrees first.
pub mod state;

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::identity::account::control::{
    AccountAction, AccountControlCheck, SignedInPerson, ensure_holder,
};
use crate::domains::identity::account::user::User;
use crate::domains::identity::events::impersonation::{
    SupportImpersonationDeclined, SupportImpersonationEnded, SupportImpersonationRequested,
    SupportImpersonationStarted,
};
use crate::domains::identity::impersonation::state::{
    ImpersonationConsent, ImpersonationState, ImpersonationStatus, ImpersonationWindow,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{SupportImpersonationId, Text, UserId};

/// How long a request waits for the person to approve before it lapses.
pub const CONSENT_WAIT: Duration = Duration::hours(24);

/// What an admin asks for.
pub struct SupportImpersonationTerms {
    /// The admin who will act as the person. They must be the one signed in.
    pub admin: UserId,
    /// Why, kept in the audit trail.
    pub reason: Text,
    /// How long they may act once it starts.
    pub window: ImpersonationWindow,
    /// Whether the person must approve first, as the tenant decides.
    pub consent: ImpersonationConsent,
}

/// A tenant admin's request to act as one person, and the window it gives.
#[derive(Debug)]
pub struct SupportImpersonation<T: TenantScope> {
    id: SupportImpersonationId,
    admin: UserId,
    user_id: UserId,
    reason: Text,
    window: ImpersonationWindow,
    consent: ImpersonationConsent,
    state: ImpersonationState,
    requested_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// A support impersonation as storage keeps it, checked again by
/// [`SupportImpersonation::reconstitute`].
pub struct SupportImpersonationRow {
    /// The request's id.
    pub id: SupportImpersonationId,
    /// The admin who acts as the person.
    pub admin: UserId,
    /// The person acted as.
    pub user_id: UserId,
    /// Why, kept in the audit trail.
    pub reason: Text,
    /// How long the admin may act once it starts.
    pub window: ImpersonationWindow,
    /// Whether the person had to approve first.
    pub consent: ImpersonationConsent,
    /// Where it stands. See [`ImpersonationState::from_stored`].
    pub state: ImpersonationState,
    /// When it was asked for.
    pub requested_at: OffsetDateTime,
}

impl<T: TenantScope> SupportImpersonation<T> {
    /// Asks to act as `account`, for the admin `signed_in` shows is the one
    /// `terms` names, as `control` allows acting as the account. Raises
    /// `identity.support_impersonation_requested`, and
    /// `identity.support_impersonation_started` too when the tenant lets
    /// admins start at once.
    ///
    /// Sam may update users but holds less than Ann, an admin. Without the
    /// checks, he acts as her and does all she may. Nobody acts as
    /// themselves, and nobody acts as an account that may not sign in now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the admin `terms` names is not the
    ///   one signed in, or is the account itself.
    /// - [`DomainError::Forbidden`] when `control` refuses it: it was made
    ///   for another account, the admin lacks full control of users, or
    ///   the account holds more than them.
    /// - [`DomainError::Conflict`] when the account may not sign in now.
    pub fn request(
        terms: SupportImpersonationTerms,
        account: &User<T>,
        signed_in: &impl SignedInPerson<T>,
        control: &impl AccountControlCheck,
    ) -> Result<Self, DomainError> {
        ensure_may_act_as(&terms.admin, account, signed_in, control)?;
        let now = crate::shared::clock::now();
        let mut request = Self {
            id: SupportImpersonationId::new(),
            admin: terms.admin,
            user_id: *account.id(),
            reason: terms.reason,
            window: terms.window,
            consent: terms.consent,
            state: ImpersonationState::AwaitingConsent,
            requested_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        request.raised.raise(SupportImpersonationRequested {
            user_id: request.user_id,
            reason: request.reason.clone(),
            consent: request.consent,
            occurred_at: now,
        });
        if request.consent == ImpersonationConsent::AdminDecides {
            request.start(now)?;
        }
        Ok(request)
    }

    /// Rebuilds a support impersonation from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row names the admin as
    ///   the person acted as, or says it started, was declined or ended
    ///   before it was asked for.
    pub fn reconstitute(row: SupportImpersonationRow) -> Result<Self, DomainError> {
        RowCheck::of("support impersonation")
            .holds(row.admin != row.user_id, "an admin acting as themselves")
            .in_order_if(
                row.requested_at,
                row.state.since(),
                "moved before it was asked for",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            admin: row.admin,
            user_id: row.user_id,
            reason: row.reason,
            window: row.window,
            consent: row.consent,
            state: row.state,
            requested_at: row.requested_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The request's id.
    #[must_use]
    pub fn id(&self) -> &SupportImpersonationId {
        &self.id
    }

    /// The admin who acts as the person.
    #[must_use]
    pub fn admin(&self) -> &UserId {
        &self.admin
    }

    /// The person acted as.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Why, kept in the audit trail.
    #[must_use]
    pub fn reason(&self) -> &Text {
        &self.reason
    }

    /// How long the admin may act once it starts.
    #[must_use]
    pub fn window(&self) -> ImpersonationWindow {
        self.window
    }

    /// Whether the person had to approve first.
    #[must_use]
    pub fn consent(&self) -> ImpersonationConsent {
        self.consent
    }

    /// Where it stands, with the time its status began.
    #[must_use]
    pub fn state(&self) -> ImpersonationState {
        self.state
    }

    /// Where it stands.
    #[must_use]
    pub fn status(&self) -> ImpersonationStatus {
        self.state.status()
    }

    /// When it was asked for.
    #[must_use]
    pub fn requested_at(&self) -> OffsetDateTime {
        self.requested_at
    }

    /// When the admin's window ends, once it has started.
    #[must_use]
    pub fn ends_at(&self) -> Option<OffsetDateTime> {
        match self.state {
            ImpersonationState::Active { since } => {
                Some(since.saturating_add(self.window.as_duration()))
            }
            ImpersonationState::AwaitingConsent
            | ImpersonationState::Declined { .. }
            | ImpersonationState::Ended { .. } => None,
        }
    }

    /// Lets the admin act as the person from `now`, by the person's own
    /// approval. Raises `identity.support_impersonation_started`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone other than the person is
    ///   signed in.
    /// - [`DomainError::Conflict`] when the request waited longer than
    ///   [`CONSENT_WAIT`].
    /// - [`DomainError::InvalidTransition`] when it does not await consent.
    pub fn approve(
        &mut self,
        by: &impl SignedInPerson<T>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        ensure_holder(by, &self.user_id)?;
        self.ensure_not_lapsed(now)?;
        self.start(now)
    }

    /// Refuses the request, by the person. Raises
    /// `identity.support_impersonation_declined`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone other than the person is
    ///   signed in.
    /// - [`DomainError::InvalidTransition`] when it does not await consent.
    pub fn decline(
        &mut self,
        by: &impl SignedInPerson<T>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        ensure_holder(by, &self.user_id)?;
        self.move_to(ImpersonationState::Declined { at: now })?;
        self.raised.raise(SupportImpersonationDeclined {
            user_id: self.user_id,
            occurred_at: now,
        });
        Ok(())
    }

    /// Ends it early, or withdraws it before it starts, by the admin or the
    /// person. Raises `identity.support_impersonation_ended`.
    ///
    /// Ann sees from her notification that support is acting as her and
    /// did not expect it. She ends it at once from her own sign-in.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when neither the admin nor the person
    ///   is signed in.
    /// - [`DomainError::InvalidTransition`] when it was already declined or
    ///   ended.
    pub fn end(
        &mut self,
        by: &impl SignedInPerson<T>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if !(by.is_holder_of(&self.admin) || by.is_holder_of(&self.user_id)) {
            return Err(DomainError::forbidden(message!(
                "identity-only-the-admin-or-the-person",
                "only the admin or the person ends it"
            )));
        }
        self.move_to(ImpersonationState::Ended { at: now })?;
        self.raised.raise(SupportImpersonationEnded {
            user_id: self.user_id,
            occurred_at: now,
        });
        Ok(())
    }

    /// Refuses the admin acting as `account` at `now` unless this request
    /// lets them: it is active and its window is still open, the admin is
    /// the one signed in, and the account is the one named and may sign in.
    ///
    /// Every use checks again, so a window that ran out, an end the person
    /// asked for, or a lock put on the account stops the admin at once.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in each of those cases.
    pub fn ensure_usable(
        &self,
        admin: &impl SignedInPerson<T>,
        account: &User<T>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        ensure_holder(admin, &self.admin)?;
        if *account.id() != self.user_id || !account.can_authenticate() {
            return Err(DomainError::forbidden(message!(
                "identity-the-account-is-not-the-one",
                "the account is not the one named, or may not act now"
            )));
        }
        let open = self.ends_at().is_some_and(|ends| now < ends);
        if !open {
            return Err(DomainError::forbidden(message!(
                "identity-the-impersonation-is-not-active-or",
                "the impersonation is not active, or its window is over"
            )));
        }
        Ok(())
    }

    /// Refuses an approval after the request waited too long.
    fn ensure_not_lapsed(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        if now >= self.requested_at.saturating_add(CONSENT_WAIT) {
            return Err(DomainError::conflict(message!(
                "identity-the-request-waited-too-long-and",
                "the request waited too long and lapsed; ask again"
            )));
        }
        Ok(())
    }

    /// Starts the window at `now`.
    fn start(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        self.move_to(ImpersonationState::Active { since: now })?;
        self.raised.raise(SupportImpersonationStarted {
            user_id: self.user_id,
            ends_at: now.saturating_add(self.window.as_duration()),
            occurred_at: now,
        });
        Ok(())
    }

    fn move_to(&mut self, to: ImpersonationState) -> Result<(), DomainError> {
        self.status().try_transition(to.status())?;
        self.state = to;
        Ok(())
    }
}

impl<T: TenantScope> Raises for SupportImpersonation<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses `admin` acting as `account` unless they are the one signed in,
/// are someone else, `control` lets them, and the account may sign in now.
///
/// # Errors
///
/// As [`SupportImpersonation::request`] lists.
fn ensure_may_act_as<T: TenantScope>(
    admin: &UserId,
    account: &User<T>,
    signed_in: &impl SignedInPerson<T>,
    control: &impl AccountControlCheck,
) -> Result<(), DomainError> {
    ensure_holder(signed_in, admin)?;
    if admin == account.id() {
        return Err(DomainError::forbidden(message!(
            "identity-nobody-acts-as-themselves",
            "nobody acts as themselves"
        )));
    }
    control.ensure_allowed(account.id(), AccountAction::Impersonate)?;
    if !account.can_authenticate() {
        return Err(DomainError::conflict(message!(
            "identity-an-account-that-may-not-sign",
            "an account that may not sign in is acted as by nobody"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::fixtures::Records;
    use crate::domains::authorization::granter::{AccountControl, Handout};
    use crate::domains::authorization::permission::{RoleAction, SystemPermission, UserAction};
    use crate::domains::authorization::stewardship::Stewardship;
    use crate::domains::authorization::support_acting::acting_as;
    use crate::domains::identity::account::user::tests::{control_over, signed_in_as};
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::user;
    use crate::test_support::events::raised_names;
    use crate::types::HumanAccount;

    /// Ann's active account.
    fn ann() -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), "ann@example.com");
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    fn terms(admin: UserId, consent: ImpersonationConsent) -> SupportImpersonationTerms {
        SupportImpersonationTerms {
            admin,
            reason: Text::new("reason", "Ann cannot see her invoices").unwrap(),
            window: ImpersonationWindow::minutes(30).unwrap(),
            consent,
        }
    }

    /// Support, signed in as `admin`, asks to act as `account` under
    /// `consent`.
    fn asked(
        admin: UserId,
        account: &User<ResolvedTenant>,
        consent: ImpersonationConsent,
    ) -> SupportImpersonation<ResolvedTenant> {
        SupportImpersonation::request(
            terms(admin, consent),
            account,
            &signed_in_as::<ResolvedTenant>(admin),
            &control_over(account),
        )
        .unwrap()
    }

    /// The tenant lets admins start at once. Support asks and may act as
    /// Ann for thirty minutes, and both steps are recorded.
    #[test]
    fn an_admin_starts_at_once_when_the_tenant_lets_them() {
        let account = ann();
        let admin = UserId::new();

        let mut request = asked(admin, &account, ImpersonationConsent::AdminDecides);

        assert_eq!(request.status(), ImpersonationStatus::Active);
        let now = crate::shared::clock::now();
        assert!(
            request
                .ensure_usable(&signed_in_as(admin), &account, now)
                .is_ok()
        );
        assert_eq!(
            raised_names(&mut request),
            [
                "identity.support_impersonation_requested",
                "identity.support_impersonation_started"
            ]
        );
    }

    /// The tenant asks people first. Support waits until Ann approves, and
    /// may act as her only then.
    #[test]
    fn the_person_approves_first_when_the_tenant_asks_them() {
        let account = ann();
        let admin = UserId::new();
        let mut request = asked(admin, &account, ImpersonationConsent::HolderApproves);
        let now = crate::shared::clock::now();

        let early = request.ensure_usable(&signed_in_as(admin), &account, now);
        request.approve(&signed_in_as(*account.id()), now).unwrap();

        assert!(matches!(early, Err(DomainError::Forbidden(_))));
        assert!(
            request
                .ensure_usable(&signed_in_as(admin), &account, now)
                .is_ok()
        );
    }

    /// Support cannot approve its own request, which remains awaiting Ann's consent.
    #[test]
    fn only_the_person_approves() {
        let account = ann();
        let admin = UserId::new();
        let mut request = asked(admin, &account, ImpersonationConsent::HolderApproves);

        let refused = request.approve(&signed_in_as(admin), crate::shared::clock::now());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(request.status(), ImpersonationStatus::AwaitingConsent);
    }

    /// Ann cannot approve a request once the one-day consent period has elapsed.
    #[test]
    fn an_old_request_cannot_be_approved() {
        let account = ann();
        let mut request = asked(
            UserId::new(),
            &account,
            ImpersonationConsent::HolderApproves,
        );
        let later = request.requested_at() + CONSENT_WAIT;

        let refused = request.approve(&signed_in_as(*account.id()), later);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// Ann declines. Support may not act as her, and the refusal is
    /// recorded.
    #[test]
    fn the_person_declines() {
        let account = ann();
        let admin = UserId::new();
        let mut request = asked(admin, &account, ImpersonationConsent::HolderApproves);
        raised_names(&mut request);
        let now = crate::shared::clock::now();

        request.decline(&signed_in_as(*account.id()), now).unwrap();

        assert_eq!(request.status(), ImpersonationStatus::Declined);
        assert!(
            request
                .ensure_usable(&signed_in_as(admin), &account, now)
                .is_err()
        );
        assert_eq!(
            raised_names(&mut request),
            ["identity.support_impersonation_declined"]
        );
    }

    /// Support's authority to act as Ann expires at the end of its granted window.
    #[test]
    fn the_window_closes_on_time() {
        let account = ann();
        let admin = UserId::new();
        let request = asked(admin, &account, ImpersonationConsent::AdminDecides);
        let Some(ends) = request.ends_at() else {
            panic!("an active request has an end");
        };

        let late = request.ensure_usable(&signed_in_as(admin), &account, ends);

        assert!(matches!(late, Err(DomainError::Forbidden(_))));
    }

    /// Ann ends it early from her own sign-in. Support is stopped at once.
    #[test]
    fn the_person_ends_it_early() {
        let account = ann();
        let admin = UserId::new();
        let mut request = asked(admin, &account, ImpersonationConsent::AdminDecides);
        let now = crate::shared::clock::now();

        request.end(&signed_in_as(*account.id()), now).unwrap();

        assert_eq!(request.status(), ImpersonationStatus::Ended);
        assert!(
            request
                .ensure_usable(&signed_in_as(admin), &account, now)
                .is_err()
        );
    }

    /// A person outside the request cannot end support's work on Ann's account.
    #[test]
    fn a_stranger_cannot_end_it() {
        let account = ann();
        let mut request = asked(UserId::new(), &account, ImpersonationConsent::AdminDecides);

        let refused = request.end(&signed_in_as(UserId::new()), crate::shared::clock::now());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Permission to update users does not authorize Sam to act as Ann.
    #[test]
    fn acting_as_someone_needs_full_control_of_users() {
        let account = ann();
        let sam = UserId::new();
        let control = AccountControl::assumed(
            anyone_holding(&[SystemPermission::Users(UserAction::Update)]),
            *account.id(),
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        );

        let refused = SupportImpersonation::request(
            terms(sam, ImpersonationConsent::AdminDecides),
            &account,
            &signed_in_as::<ResolvedTenant>(sam),
            &control,
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Sam cannot act as Ann when her role-management rights exceed his own.
    #[test]
    fn nobody_acts_as_someone_holding_more_than_them() {
        let account = ann();
        let sam = UserId::new();
        let control = AccountControl::assumed(
            anyone_holding(&[SystemPermission::Users(UserAction::Manage)]),
            *account.id(),
            Stewardship::OthersAdminister,
            Handout {
                system: &[SystemPermission::Roles(RoleAction::Manage)],
                custom: &[],
            },
        );

        let refused = SupportImpersonation::request(
            terms(sam, ImpersonationConsent::AdminDecides),
            &account,
            &signed_in_as::<ResolvedTenant>(sam),
            &control,
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A request cannot name an admin other than the person signed in.
    #[test]
    fn the_admin_named_is_the_one_signed_in() {
        let account = ann();

        let refused = SupportImpersonation::request(
            terms(UserId::new(), ImpersonationConsent::AdminDecides),
            &account,
            &signed_in_as::<ResolvedTenant>(UserId::new()),
            &control_over(&account),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// An admin asking to act as themselves is refused.
    #[test]
    fn nobody_acts_as_themselves() {
        let account = ann();
        let own = *account.id();

        let refused = SupportImpersonation::request(
            terms(own, ImpersonationConsent::AdminDecides),
            &account,
            &signed_in_as::<ResolvedTenant>(own),
            &control_over(&account),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Support cannot request impersonation of Ann's locked account.
    #[test]
    fn a_locked_account_is_acted_as_by_nobody() {
        let mut account = ann();
        account.lock(&control_over(&account)).unwrap();
        let admin = UserId::new();

        let refused = SupportImpersonation::request(
            terms(admin, ImpersonationConsent::AdminDecides),
            &account,
            &signed_in_as::<ResolvedTenant>(admin),
            &control_over(&account),
        );

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// A stored request naming the admin as the person acted as is refused
    /// as corrupt.
    #[test]
    fn a_stored_request_acting_as_its_admin_is_refused() {
        let same = UserId::new();
        let row = SupportImpersonationRow {
            id: SupportImpersonationId::new(),
            admin: same,
            user_id: same,
            reason: Text::new("reason", "checking").unwrap(),
            window: ImpersonationWindow::minutes(30).unwrap(),
            consent: ImpersonationConsent::AdminDecides,
            state: ImpersonationState::AwaitingConsent,
            requested_at: crate::shared::clock::now(),
        };

        assert!(refused_as_corrupt(
            &SupportImpersonation::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Ann approved support acting as her. Within the window the admin acts
    /// as Ann: what they hold is worked out for her account, so every check
    /// after it reads Ann's rights, not the admin's.
    #[test]
    fn an_open_window_lets_the_admin_act_as_the_person() {
        let account = ann();
        let admin = UserId::new();
        let request = asked(admin, &account, ImpersonationConsent::AdminDecides);
        let records = Records::default();

        let acting = acting_as(
            &request,
            &records.access(),
            &signed_in_as(admin),
            &account,
            crate::shared::clock::now(),
        )
        .unwrap();

        assert_eq!(acting.who().account(), HumanAccount::User(*account.id()));
    }

    /// Support receives no authority before Ann approves or after its window closes.
    #[test]
    fn no_authority_is_given_outside_an_open_window() {
        let account = ann();
        let admin = UserId::new();
        let waiting = asked(admin, &account, ImpersonationConsent::HolderApproves);
        let started = asked(admin, &account, ImpersonationConsent::AdminDecides);
        let records = Records::default();
        let later = crate::shared::clock::now() + Duration::hours(2);

        let early = acting_as(
            &waiting,
            &records.access(),
            &signed_in_as(admin),
            &account,
            crate::shared::clock::now(),
        );
        let late = acting_as(
            &started,
            &records.access(),
            &signed_in_as(admin),
            &account,
            later,
        );

        assert!(matches!(early, Err(DomainError::Forbidden(_))));
        assert!(matches!(late, Err(DomainError::Forbidden(_))));
    }
}
