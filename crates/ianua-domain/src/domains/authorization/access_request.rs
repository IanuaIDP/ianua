//! Just-in-time access: someone asks for a role or a group for a while, and
//! someone who could give it approves or denies.
//!
//! Ann is on call and needs the production group for two hours. She does not
//! hold it day to day, and nobody should hold it day to day. She asks, with
//! a reason, and Bob, who may give it, approves. She holds it for the two
//! hours she asked for and then not at all. Nobody approves their own
//! request, and nobody approves more than they could give by hand.

mod limits;

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

pub use crate::domains::authorization::access_request::limits::AccessRequestLimits;
use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::access_requests::{
    AccessRequestApproved, AccessRequestCancelled, AccessRequestDenied, AccessRequestExpired,
    AccessRequested,
};
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::group::{Group, GroupPlace};
use crate::domains::authorization::group_tree::Conferred;
use crate::domains::authorization::permission::{RoleAction, SystemPermission, UserAction};
use crate::domains::authorization::role::{Role, assignment_right};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::{
    AccessRequestId, ActorRef, EventLabel, Expiry, GroupId, Human, Lifetime, PrincipalRef, RoleId,
    Text,
};

/// The longest anyone may ask for access, whatever a tenant allows. Access
/// for longer than a month is a standing role, given the ordinary way.
pub(crate) const MAX_ACCESS_LENGTH: Duration = Duration::days(30);

/// How long a request waits for an answer before it runs out.
pub const ANSWER_WINDOW: Duration = Duration::days(7);

/// What someone asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskedAccess {
    /// A role, given straight to them.
    Role(RoleId),
    /// A place in a group, with every role it brings.
    Group(GroupId),
}

/// The role or group an approver gives, loaded so its grants can be
/// checked against what they hold.
#[derive(Debug)]
pub enum AskedGrant<'a, T: TenantScope> {
    /// The role asked for.
    Role(&'a Role<T>),
    /// The group asked for, with what sitting in it brings.
    Group(&'a Group<T>, &'a Conferred),
}

impl<T: TenantScope> AskedGrant<'_, T> {
    /// What it gives, as a request names it.
    fn asked(&self) -> AskedAccess {
        match self {
            Self::Role(role) => AskedAccess::Role(*role.id()),
            Self::Group(group, _) => AskedAccess::Group(*group.id()),
        }
    }

    /// Its name, for the audit trail.
    fn label(&self) -> EventLabel {
        match self {
            Self::Role(role) => role.label(),
            Self::Group(group, _) => group.label(),
        }
    }

    /// Refuses `held` when it could not give this to `principal` by hand.
    fn ensure_given_by(
        &self,
        principal: &PrincipalRef,
        held: &HeldByGranter<'_>,
    ) -> Result<(), DomainError> {
        match self {
            Self::Role(role) => {
                held.ensure_holds(assignment_right(principal))?;
                held.ensure_may_give(&role.grants())
            }
            Self::Group(group, conferred) => {
                held.ensure_holds(SystemPermission::Roles(RoleAction::Assign))?;
                conferred.ensure_for(GroupPlace::Under(*group.id()))?;
                held.ensure_may_give(&conferred.handout())
            }
        }
    }
}

/// Refuses `held` unless it holds a right that answers some request:
/// giving a person a role, or a place in a group.
///
/// Whether `held` may answer one request depends on what it asks for, so
/// that is checked once the request is read. This is checked before. Sam
/// may view users only. Without it, he answers made-up ids and real ones
/// differently, and learns which requests exist.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `held` may neither change people's
///   roles nor assign roles to groups.
pub fn ensure_answers_requests(held: &HeldByGranter<'_>) -> Result<(), DomainError> {
    let answering = [
        SystemPermission::Users(UserAction::Update),
        SystemPermission::Roles(RoleAction::Assign),
    ];
    if answering.iter().any(|right| held.holds(*right)) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "authorization-only-someone-who-may-give-roles",
        "only someone who may give roles or places in groups answers access requests"
    )))
}

/// Where a request is in its life.
///
/// Allowed moves, each from `Pending`, and none back:
/// - to `Approved`: someone who could give it said yes.
/// - to `Denied`: someone who could give it said no.
/// - to `Cancelled`: the person who asked withdrew it.
/// - to `Expired`: nobody answered within [`ANSWER_WINDOW`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessRequestStatus {
    /// Waiting for an answer.
    Pending,
    /// Approved; the access is given until its end.
    Approved,
    /// The approver refused the grant; no temporary access is issued.
    Denied,
    /// Withdrawn by the person who asked.
    Cancelled,
    /// Left unanswered until it ran out.
    Expired,
}

impl AccessRequestStatus {
    /// Moves to `to`, when [`AccessRequestStatus`] lists that move.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] when the move is not one listed.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            from == Self::Pending
                && matches!(
                    to,
                    Self::Approved | Self::Denied | Self::Cancelled | Self::Expired
                )
        })
    }

    /// The stable name storage and the API use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    /// Reads a stored status.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for a name no status has.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        [
            Self::Pending,
            Self::Approved,
            Self::Denied,
            Self::Cancelled,
            Self::Expired,
        ]
        .into_iter()
        .find(|status| status.as_str() == value)
        .ok_or_else(|| DomainError::corrupt_row("access request", "an unknown status"))
    }
}

/// Who answered a request and when, or that nobody has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestAnswer {
    /// Nobody has approved or denied it.
    Unanswered,
    /// This person, through this account, approved or denied it at `at`.
    By {
        /// Who answered.
        approver: Human,
        /// When.
        at: OffsetDateTime,
    },
}

/// What a person asks for when they ask for access.
#[derive(Debug, Clone)]
pub struct NewAccessRequest {
    /// The role or group.
    pub asked: AskedAccess,
    /// Its name, for the audit trail.
    pub asked_label: EventLabel,
    /// Why they need it.
    pub reason: Text,
    /// How long they need it.
    pub length: Lifetime,
}

/// What an approved request gives: to whom, by whom, until when.
#[derive(Debug, Clone)]
pub(crate) struct Granted {
    /// Who asked, and holds it now.
    pub(crate) principal: PrincipalRef,
    /// Who approved it, as the assignment records its granter.
    pub(crate) approver: ActorRef,
    /// When it ends.
    pub(crate) until: Expiry,
}

/// A request for a role or a group for a while.
///
/// A request keeps these rules:
/// - It is for the person who asks, never for someone else.
/// - It asks for no longer than the tenant allows, and never longer than
///   `MAX_ACCESS_LENGTH`.
/// - Nobody answers their own, through any of their accounts.
/// - Only someone who could give it by hand approves or denies it.
/// - Once answered, withdrawn or run out, it stays as it is.
#[derive(Debug)]
pub struct AccessRequest<T: TenantScope> {
    id: AccessRequestId,
    requester: Human,
    asked: AskedAccess,
    reason: Text,
    length: Lifetime,
    status: AccessRequestStatus,
    answer: RequestAnswer,
    requested_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// An [`AccessRequest`] as storage holds it, read back through
/// [`AccessRequest::reconstitute`].
pub struct AccessRequestRow {
    /// The request.
    pub id: AccessRequestId,
    /// Who asked, through which account.
    pub requester: Human,
    /// What they asked for.
    pub asked: AskedAccess,
    /// Why.
    pub reason: Text,
    /// For how long.
    pub length: Lifetime,
    /// Where it is in its life.
    pub status: AccessRequestStatus,
    /// Who answered it and when.
    pub answer: RequestAnswer,
    /// When it was asked.
    pub requested_at: OffsetDateTime,
}

impl<T: TenantScope> AccessRequest<T> {
    /// Asks for `new` for the person `requester` names, within `limits`.
    /// Raises `authorization.access_requested`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the length asked is longer than
    ///   `limits` allow.
    pub fn request(
        new: NewAccessRequest,
        requester: &TenantAuthority,
        limits: AccessRequestLimits,
    ) -> Result<Self, DomainError> {
        new.length
            .ensure_at_most(limits.longest().duration(), "access asked for")?;
        let mut request = Self {
            id: AccessRequestId::new(),
            requester: requester.who().clone(),
            asked: new.asked,
            reason: new.reason,
            length: new.length,
            status: AccessRequestStatus::Pending,
            answer: RequestAnswer::Unanswered,
            requested_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        request.raised.raise(AccessRequested {
            request_id: request.id,
            holder: request.requester.principal(),
            holder_label: request.holder_label(),
            asked: request.asked,
            asked_label: new.asked_label,
            reason: request.reason.clone(),
            length: request.length,
            occurred_at: request.requested_at,
        });
        Ok(request)
    }

    /// Rebuilds a request from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when its answer does not fit its
    ///   status, it was answered by the person who asked or before it was
    ///   asked, or it asks for longer than `MAX_ACCESS_LENGTH`.
    pub fn reconstitute(row: AccessRequestRow) -> Result<Self, DomainError> {
        let answered = matches!(
            row.status,
            AccessRequestStatus::Approved | AccessRequestStatus::Denied
        );
        let fits = match &row.answer {
            RequestAnswer::Unanswered => !answered,
            RequestAnswer::By { approver, at } => {
                answered && !approver.is_same_person_as(&row.requester) && *at >= row.requested_at
            }
        };
        RowCheck::of("access request")
            .holds(fits, "an answer that does not fit its status or its asker")
            .holds(
                row.length.duration() <= MAX_ACCESS_LENGTH,
                "asks for longer than anyone may",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            requester: row.requester,
            asked: row.asked,
            reason: row.reason,
            length: row.length,
            status: row.status,
            answer: row.answer,
            requested_at: row.requested_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The request.
    #[must_use]
    pub fn id(&self) -> &AccessRequestId {
        &self.id
    }

    /// Who asked, through which account.
    #[must_use]
    pub fn requester(&self) -> &Human {
        &self.requester
    }

    /// What they asked for.
    #[must_use]
    pub fn asked(&self) -> AskedAccess {
        self.asked
    }

    /// Why they asked.
    #[must_use]
    pub fn reason(&self) -> &Text {
        &self.reason
    }

    /// How long they asked for it.
    #[must_use]
    pub fn length(&self) -> Lifetime {
        self.length
    }

    /// Where the request is in its life.
    #[must_use]
    pub fn status(&self) -> AccessRequestStatus {
        self.status
    }

    /// Who answered it and when.
    #[must_use]
    pub fn answer(&self) -> &RequestAnswer {
        &self.answer
    }

    /// When it was asked.
    #[must_use]
    pub fn requested_at(&self) -> OffsetDateTime {
        self.requested_at
    }

    /// When it runs out if nobody answers.
    #[must_use]
    pub fn answer_by(&self) -> OffsetDateTime {
        self.requested_at.saturating_add(ANSWER_WINDOW)
    }

    /// Approves the request for `approver`, giving `grant`. Raises
    /// `authorization.access_request_approved` with when the access ends:
    /// the length asked, counted from now.
    ///
    /// The use case then records the holding with
    /// [`RoleAssignment::from_approved_request`](crate::domains::authorization::role::RoleAssignment::from_approved_request)
    /// or
    /// [`GroupMembership::from_approved_request`](crate::domains::authorization::group::GroupMembership::from_approved_request).
    ///
    /// # Errors
    ///
    /// - The cases [`deny`](Self::deny) lists.
    pub fn approve(
        &mut self,
        grant: &AskedGrant<'_, T>,
        approver: &TenantAuthority,
    ) -> Result<(), DomainError> {
        let now = crate::shared::clock::now();
        let status = self.answerable(grant, approver, now, AccessRequestStatus::Approved)?;
        self.status = status;
        self.answer = RequestAnswer::By {
            approver: approver.who().clone(),
            at: now,
        };
        self.raised.raise(AccessRequestApproved {
            request_id: self.id,
            holder: self.requester.principal(),
            holder_label: self.holder_label(),
            asked: self.asked,
            asked_label: grant.label(),
            until: self.length.ends_after(now),
            occurred_at: now,
        });
        Ok(())
    }

    /// Denies the request for `approver`. Raises
    /// `authorization.access_request_denied`.
    ///
    /// Only someone who could approve it denies it, so Sam, who could not
    /// give the role, cannot turn away every request for it either.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the request is no longer
    ///   pending.
    /// - [`DomainError::Conflict`] when it has run out, or `grant` is not
    ///   what it asked for.
    /// - [`DomainError::Forbidden`] when `approver` is the person who asked,
    ///   through any of their accounts.
    /// - [`DomainError::Forbidden`] when `approver` could not give `grant`
    ///   to the asker by hand.
    pub fn deny(
        &mut self,
        grant: &AskedGrant<'_, T>,
        approver: &TenantAuthority,
    ) -> Result<(), DomainError> {
        let now = crate::shared::clock::now();
        let status = self.answerable(grant, approver, now, AccessRequestStatus::Denied)?;
        self.status = status;
        self.answer = RequestAnswer::By {
            approver: approver.who().clone(),
            at: now,
        };
        self.raised.raise(AccessRequestDenied {
            request_id: self.id,
            holder: self.requester.principal(),
            holder_label: self.holder_label(),
            asked: self.asked,
            asked_label: grant.label(),
            occurred_at: now,
        });
        Ok(())
    }

    /// Withdraws the request, for the person who asked. Raises
    /// `authorization.access_request_cancelled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not the person who asked.
    /// - [`DomainError::InvalidTransition`] when it is no longer pending.
    pub fn cancel(&mut self, by: &TenantAuthority) -> Result<(), DomainError> {
        if !by.who().is_same_person_as(&self.requester) {
            return Err(DomainError::forbidden(message!(
                "authorization-only-the-person-who-asked-withdraws",
                "only the person who asked withdraws a request"
            )));
        }
        self.status = self.status.try_transition(AccessRequestStatus::Cancelled)?;
        self.raised.raise(AccessRequestCancelled {
            request_id: self.id,
            holder: self.requester.principal(),
            holder_label: self.holder_label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Ends a request nobody answered in time. Raises
    /// `authorization.access_request_expired`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when it may still be answered at `now`.
    /// - [`DomainError::InvalidTransition`] when it is no longer pending.
    pub fn expire(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        if now < self.answer_by() {
            return Err(DomainError::conflict(message!(
                "authorization-this-request-may-still-be-answered",
                "this request may still be answered"
            )));
        }
        self.status = self.status.try_transition(AccessRequestStatus::Expired)?;
        self.raised.raise(AccessRequestExpired {
            request_id: self.id,
            holder: self.requester.principal(),
            holder_label: self.holder_label(),
            occurred_at: now,
        });
        Ok(())
    }

    /// What this request gives, once approved, if it asked for `asked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when it is not approved, or asked for
    ///   something else.
    pub(crate) fn granted(&self, asked: AskedAccess) -> Result<Granted, DomainError> {
        let RequestAnswer::By { approver, at } = &self.answer else {
            return Err(DomainError::conflict(message!(
                "authorization-this-request-was-not-approved",
                "this request was not approved"
            )));
        };
        if self.status != AccessRequestStatus::Approved || self.asked != asked {
            return Err(DomainError::conflict(message!(
                "authorization-access-comes-only-from-an-approved",
                "access comes only from an approved request, for what it asked"
            )));
        }
        Ok(Granted {
            principal: self.requester.principal(),
            approver: ActorRef::from(approver.account()),
            until: Expiry::At(self.length.ends_after(*at)),
        })
    }

    /// The status `to` the request moves to when `approver` answers it with
    /// `grant` at `now`, once every rule is checked.
    fn answerable(
        &self,
        grant: &AskedGrant<'_, T>,
        approver: &TenantAuthority,
        now: OffsetDateTime,
        to: AccessRequestStatus,
    ) -> Result<AccessRequestStatus, DomainError> {
        let status = self.status.try_transition(to)?;
        if now >= self.answer_by() {
            return Err(DomainError::conflict(message!(
                "authorization-this-request-has-run-out",
                "this request has run out"
            )));
        }
        if grant.asked() != self.asked {
            return Err(DomainError::conflict(message!(
                "authorization-the-answer-names-another-role-or",
                "the answer names another role or group than the request"
            )));
        }
        if approver.who().is_same_person_as(&self.requester) {
            return Err(DomainError::forbidden(message!(
                "authorization-nobody-answers-their-own-request-for",
                "nobody answers their own request for access"
            )));
        }
        grant.ensure_given_by(&self.requester.principal(), &approver.standing())?;
        Ok(status)
    }

    /// How the audit trail names the person who asked.
    fn holder_label(&self) -> EventLabel {
        EventLabel::of(self.requester.person().as_str())
    }
}

impl<T: TenantScope> Raises for AccessRequest<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::{CreateGroupParams, GroupMembership, GroupOrigin};
    use crate::domains::authorization::group_tree::GroupTree;
    use crate::domains::authorization::permission::CustomPermission;
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, RoleAssignment};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::clock::freeze;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_names;
    use crate::types::{HumanAccount, OrgUserId, PersonKey, TenantId, UserId};

    fn person(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    fn acting(who: &Human, system: &[SystemPermission]) -> &'static TenantAuthority {
        assumed_authority(who, TenantId::new(), system, &[])
    }

    /// Ann, who asks.
    fn ann() -> Human {
        person("ann@acme.test")
    }

    /// Bob, who may update users and holds everything the on-call role
    /// gives.
    fn bob() -> &'static TenantAuthority {
        acting(
            &person("bob@acme.test"),
            &[SystemPermission::ManageUsers, SystemPermission::ManageRoles],
        )
    }

    fn on_call() -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("on-call"),
            system_permissions: vec![SystemPermission::Users(UserAction::Update)],
            custom_permissions: vec![CustomPermission::new("prod", "deploy").unwrap()],
            assignment: DefaultAssignment::Manual,
        })
    }

    fn hours(n: i64) -> Lifetime {
        Lifetime::new(Duration::hours(n)).unwrap()
    }

    fn eight_hours() -> AccessRequestLimits {
        AccessRequestLimits::new(hours(8)).unwrap()
    }

    /// Ann asking for `role` for two hours.
    fn asking_for(role: &Role<ResolvedTenant>) -> AccessRequest<ResolvedTenant> {
        AccessRequest::request(
            NewAccessRequest {
                asked: AskedAccess::Role(*role.id()),
                asked_label: role.label(),
                reason: Text::new("reason", "INC-42 production is down").unwrap(),
                length: hours(2),
            },
            acting(&ann(), &[]),
            eight_hours(),
        )
        .unwrap()
    }

    /// Ann asks for the on-call role for two hours. The request waits for
    /// an answer, and the asking is recorded.
    #[test]
    fn a_request_waits_for_an_answer() {
        let role = on_call();

        let mut request = asking_for(&role);

        assert_eq!(request.status(), AccessRequestStatus::Pending);
        assert!(request.requester().is_same_person_as(&ann()));
        assert_eq!(
            raised_names(&mut request),
            ["authorization.access_requested"]
        );
    }

    /// A two-day access request exceeds the tenant's eight-hour limit and is
    /// rejected; configuring a thirty-one-day limit is also rejected.
    #[test]
    fn a_request_asks_for_no_longer_than_allowed() {
        let role = on_call();

        let refused = AccessRequest::<ResolvedTenant>::request(
            NewAccessRequest {
                asked: AskedAccess::Role(*role.id()),
                asked_label: role.label(),
                reason: Text::new("reason", "migration").unwrap(),
                length: hours(48),
            },
            acting(&ann(), &[]),
            eight_hours(),
        );

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert!(AccessRequestLimits::new(hours(24 * 31)).is_err());
    }

    /// A tenant that set no limit lets its people ask for the longest
    /// anyone may, a month, and no longer.
    #[test]
    fn the_widest_limit_is_the_longest_anyone_may_ask() {
        let widest = AccessRequestLimits::WIDEST.longest().duration();

        assert_eq!(widest, MAX_ACCESS_LENGTH);
    }

    /// Bob approves Ann's request at noon. She is given the on-call role
    /// until two o'clock, recorded as given by Bob.
    #[test]
    fn an_approved_request_gives_the_role_until_its_end() {
        let role = on_call();
        let mut request = asking_for(&role);
        let bob = bob();
        let noon = crate::shared::clock::now();
        let _clock = freeze(noon);

        request.approve(&AskedGrant::Role(&role), bob).unwrap();
        let assignment =
            RoleAssignment::from_approved_request(&request, &role, EventLabel::of("ann")).unwrap();

        assert_eq!(request.status(), AccessRequestStatus::Approved);
        assert_eq!(*assignment.principal(), request.requester().principal());
        assert_eq!(assignment.expires(), Expiry::At(noon + Duration::hours(2)));
        assert_eq!(
            assignment.assigned_by().audit_label(),
            bob.actor().audit_label()
        );
    }

    /// Ann cannot approve her own request through either her tenant identity or
    /// an organization account with the same address. The request remains pending.
    #[test]
    fn nobody_approves_their_own_request() {
        let role = on_call();
        let mut request = asking_for(&role);
        let everything = SystemPermission::all();
        let anns_org_account = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            PersonKey::new("Ann@acme.test").unwrap(),
        );

        let own = request.approve(&AskedGrant::Role(&role), acting(&ann(), everything));
        let other_account = request.approve(
            &AskedGrant::Role(&role),
            acting(&anns_org_account, everything),
        );

        assert!(matches!(own, Err(DomainError::Forbidden(_))));
        assert!(matches!(other_account, Err(DomainError::Forbidden(_))));
        assert_eq!(request.status(), AccessRequestStatus::Pending);
    }

    /// Sam cannot approve or deny a role request when he lacks its deployment
    /// permission, and the request remains pending.
    #[test]
    fn only_someone_who_could_give_it_answers() {
        let role = on_call();
        let mut request = asking_for(&role);
        let sam = acting(
            &person("sam@acme.test"),
            &[SystemPermission::Users(UserAction::Update)],
        );

        let approved = request.approve(&AskedGrant::Role(&role), sam);
        let denied = request.deny(&AskedGrant::Role(&role), sam);

        assert!(matches!(approved, Err(DomainError::Forbidden(_))));
        assert!(matches!(denied, Err(DomainError::Forbidden(_))));
        assert_eq!(request.status(), AccessRequestStatus::Pending);
    }

    /// A request rejects approval for a different role and, once correctly
    /// approved, cannot produce an assignment for that different role.
    #[test]
    fn an_answer_gives_only_what_was_asked() {
        let role = on_call();
        let other = on_call();
        let mut request = asking_for(&role);

        let swapped = request.approve(&AskedGrant::Role(&other), bob());
        request.approve(&AskedGrant::Role(&role), bob()).unwrap();
        let other_role =
            RoleAssignment::from_approved_request(&request, &other, EventLabel::of("ann"));

        assert!(matches!(swapped, Err(DomainError::Conflict(_))));
        assert!(matches!(other_role, Err(DomainError::Conflict(_))));
    }

    /// A pending access request cannot produce a role assignment before approval.
    #[test]
    fn a_pending_request_gives_nothing() {
        let role = on_call();
        let request = asking_for(&role);

        let early = RoleAssignment::from_approved_request(&request, &role, EventLabel::of("ann"));

        assert!(matches!(early, Err(DomainError::Conflict(_))));
    }

    /// Bob denies Ann's request. It is recorded, and it gives nothing.
    #[test]
    fn a_denied_request_gives_nothing() {
        let role = on_call();
        let mut request = asking_for(&role);

        request.deny(&AskedGrant::Role(&role), bob()).unwrap();
        let after = RoleAssignment::from_approved_request(&request, &role, EventLabel::of("ann"));

        assert_eq!(request.status(), AccessRequestStatus::Denied);
        assert!(matches!(after, Err(DomainError::Conflict(_))));
    }

    /// Ann withdraws her request. Bob cannot withdraw it for her, and once
    /// it is withdrawn nobody approves it.
    #[test]
    fn only_the_asker_withdraws_a_request() {
        let role = on_call();
        let mut request = asking_for(&role);

        let by_bob = request.cancel(bob());
        request.cancel(acting(&ann(), &[])).unwrap();
        let approved_after = request.approve(&AskedGrant::Role(&role), bob());

        assert!(matches!(by_bob, Err(DomainError::Forbidden(_))));
        assert_eq!(request.status(), AccessRequestStatus::Cancelled);
        assert!(matches!(
            approved_after,
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// Nobody answers Ann's request for a week. It runs out, and Bob can
    /// no longer approve it. Before the week is over it does not run out.
    #[test]
    fn an_unanswered_request_runs_out() {
        let role = on_call();
        let mut request = asking_for(&role);
        let week_on = request.answer_by();

        let early = request.expire(week_on - Duration::minutes(1));
        let _clock = freeze(week_on);
        let late = request.approve(&AskedGrant::Role(&role), bob());
        request.expire(week_on).unwrap();

        assert!(matches!(early, Err(DomainError::Conflict(_))));
        assert!(matches!(late, Err(DomainError::Conflict(_))));
        assert_eq!(request.status(), AccessRequestStatus::Expired);
    }

    /// Ann asks for the Production group for two hours, and Bob approves
    /// it. She joins it until the two hours are over.
    #[test]
    fn an_approved_group_request_gives_a_membership_until_its_end() {
        let groups = [production_group()];
        let production = &groups[0];
        let conferred = GroupTree::new(&groups)
            .conferred(GroupPlace::Under(*production.id()), &[])
            .unwrap();
        let mut request = AccessRequest::<ResolvedTenant>::request(
            NewAccessRequest {
                asked: AskedAccess::Group(*production.id()),
                asked_label: production.label(),
                reason: Text::new("reason", "on call tonight").unwrap(),
                length: hours(2),
            },
            acting(&ann(), &[]),
            eight_hours(),
        )
        .unwrap();

        request
            .approve(&AskedGrant::Group(production, &conferred), bob())
            .unwrap();
        let membership =
            GroupMembership::from_approved_request(&request, production, EventLabel::of("ann"))
                .unwrap();

        assert!(matches!(membership.expires(), Expiry::At(_)));
        assert_eq!(membership.group_id(), production.id());
    }

    /// A top-level production group Bob may grant to an on-call requester.
    fn production_group() -> Group<ResolvedTenant> {
        Group::create(
            CreateGroupParams {
                name: label("Production"),
                origin: GroupOrigin::Dashboard,
                place: GroupPlace::TopLevel,
            },
            &Conferred::at_top(),
            &bob().standing(),
        )
        .unwrap()
    }

    fn stored(status: AccessRequestStatus, answer: RequestAnswer) -> AccessRequestRow {
        AccessRequestRow {
            id: AccessRequestId::new(),
            requester: ann(),
            asked: AskedAccess::Role(RoleId::new()),
            reason: Text::new("reason", "INC-42").unwrap(),
            length: hours(2),
            status,
            answer,
            requested_at: crate::shared::clock::now(),
        }
    }

    /// Stored approved requests with no answer or with the requester as approver
    /// are rejected as corrupt.
    #[test]
    fn a_stored_request_answered_by_nobody_or_its_asker_is_refused() {
        let later = crate::shared::clock::now() + Duration::minutes(5);
        let by_ann = RequestAnswer::By {
            approver: ann(),
            at: later,
        };

        let unanswered = AccessRequest::<ResolvedTenant>::reconstitute(stored(
            AccessRequestStatus::Approved,
            RequestAnswer::Unanswered,
        ));
        let own = AccessRequest::<ResolvedTenant>::reconstitute(stored(
            AccessRequestStatus::Approved,
            by_ann,
        ));

        assert!(matches!(unanswered, Err(DomainError::Infrastructure(_))));
        assert!(matches!(own, Err(DomainError::Infrastructure(_))));
    }

    /// Sam may view users only and answers no request. Ann may give people
    /// roles, and Dan may give groups roles: each answers some.
    #[test]
    fn only_someone_who_gives_roles_or_places_answers_requests() {
        let sam = crate::test_support::authority::anyone_holding(&[SystemPermission::Users(
            UserAction::View,
        )]);
        let ann = crate::test_support::authority::user_editor();
        let dan = crate::test_support::authority::anyone_holding(&[SystemPermission::Roles(
            RoleAction::Assign,
        )]);

        assert!(matches!(
            ensure_answers_requests(&sam.standing()),
            Err(DomainError::Forbidden(_))
        ));
        assert!(ensure_answers_requests(&ann.standing()).is_ok());
        assert!(ensure_answers_requests(&dan.standing()).is_ok());
    }

    /// Each status reads back from its stored name, and an unknown name is
    /// a corrupt row.
    #[test]
    fn statuses_round_trip_through_their_stored_names() {
        for status in [
            AccessRequestStatus::Pending,
            AccessRequestStatus::Approved,
            AccessRequestStatus::Denied,
            AccessRequestStatus::Cancelled,
            AccessRequestStatus::Expired,
        ] {
            assert_eq!(
                AccessRequestStatus::from_stored(status.as_str()).unwrap(),
                status
            );
        }
        assert!(AccessRequestStatus::from_stored("granted").is_err());
    }
}
