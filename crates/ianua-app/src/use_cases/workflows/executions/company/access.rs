//! The company steps about access: a group's members, adding and removing
//! people, taking them out of every group, access for a while, checking
//! what they may do, deciding requests and opening reviews.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_check::{
    AccessDecision, AccessQuestion, AllowedBy, CheckTarget,
};
use ianua_domain::domains::authorization::access_request::AccessRequestStatus;
use ianua_domain::domains::authorization::access_review::{ReviewScope, Unanswered};
use ianua_domain::domains::authorization::break_glass::BreakGlassAccess;
use ianua_domain::domains::authorization::permission::{
    CustomPermission, PermissionSegment, SystemPermission,
};
use ianua_domain::domains::authorization::relationship::{ObjectKey, ObjectRef};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::company::{
    ACTION_INPUT, DECISION_INPUT, EVERY_INPUT, GROUP_INPUT, HOURS_INPUT, MINUTES_INPUT,
    OBJECT_INPUT, PERMISSIONS_INPUT, PERSON_INPUT, REASON_INPUT, REQUEST_INPUT, RESOURCE_INPUT,
    REVIEWERS_INPUT,
};
use ianua_domain::shared::clock;
use ianua_domain::types::{AccessRequestId, Expiry, GroupId, Label, PrincipalRef, Text, UserId};
use time::Duration;

use crate::listing::{Limit, PageRequest};
use crate::ports::workflows::CompanyCall;
use crate::use_case::{Command as _, Query as _};
use crate::use_cases::authentication::sessions::break_glass::{
    BreakGlassGrantRequest, GrantUseCase,
};
use crate::use_cases::authorization::access_requests::{ApproveUseCase, DenyUseCase, GetUseCase};
use crate::use_cases::authorization::access_reviews::{StartRequest, StartUseCase, SuggestUseCase};
use crate::use_cases::authorization::checks::{AccessUseCase, CheckAccessRequest};
use crate::use_cases::authorization::groups::{
    AddMemberRequest, AddMemberUseCase, ListMembersRequest, ListMembersUseCase,
    RemoveMemberRequest, RemoveMemberUseCase,
};
use crate::use_cases::authorization::holdings::GetPrincipalAccessUseCase;
use crate::use_cases::notifications::notices::Offering;
use crate::use_cases::workflows::executions::answers::{data, failed, moment_text};
use crate::use_cases::workflows::executions::company::inputs::{
    id, optional_text, text, texts, whole_number,
};
use crate::use_cases::workflows::executions::company::people::{PeopleActions, count};
use crate::use_cases::workflows::executions::company::{succeeded, unmade};

/// The most members one step reads.
const MEMBERS_READ: u32 = 100;

/// The longest access a step gives, in hours: thirty days.
const LONGEST_HOURS: u32 = 720;

/// The longest emergency access a step gives, in minutes: a day, which no
/// grant may pass; the deployment's own limit may be shorter.
const LONGEST_MINUTES: u32 = 1_440;

/// How long a review a step opens runs before it is due.
const REVIEW_DAYS: i64 = 14;

/// The most hours apart reminders may go out: a week.
const LONGEST_REMINDER_HOURS: u32 = 168;

/// The dashboard's actions on access.
pub struct AccessActions {
    /// Lists a group's members.
    pub members: Arc<ListMembersUseCase>,
    /// Adds a person to a group, for good or until a moment.
    pub add: Arc<AddMemberUseCase>,
    /// Removes a person from a group.
    pub remove: Arc<RemoveMemberUseCase>,
    /// Approves an access request.
    pub approve: Arc<ApproveUseCase>,
    /// Denies an access request.
    pub deny: Arc<DenyUseCase>,
    /// Reads one access request.
    pub request: Arc<GetUseCase>,
    /// Opens an access review.
    pub start_review: Arc<StartUseCase>,
    /// Suggests keep or remove beside a review's holders.
    pub suggest_review: Arc<SuggestUseCase>,
    /// Reads what a person holds, their group memberships among it.
    pub principal_access: Arc<GetPrincipalAccessUseCase>,
    /// Answers whether a person may do an action.
    pub check: Arc<AccessUseCase>,
    /// Gives a person emergency access for a few minutes.
    pub break_glass: Arc<GrantUseCase>,
}

impl AccessActions {
    /// Reads the members of the group the step names.
    pub(super) async fn members(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let request = ListMembersRequest {
            group_id: id(step.call, GROUP_INPUT, GroupId::from_uuid)?,
            page: PageRequest::first(Limit::internal(MEMBERS_READ)),
        };
        let page = self
            .members
            .execute(step.caller, request)
            .await
            .map_err(unmade)?;
        let members = page
            .items
            .iter()
            .map(|member| {
                data(vec![
                    ("member", FlowData::text(member.principal.label())),
                    (
                        "name",
                        FlowData::text(member.display_name.clone().unwrap_or_default()),
                    ),
                    ("joined_at", moment_text(member.joined_at)),
                ])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let total = members.len();
        let list =
            FlowData::list(members).map_err(|_| failed("the members do not fit workflow data"))?;
        let output = data(vec![("members", Ok(list)), ("count", count(total))])?;
        Ok(succeeded(step, output, DataClassLevel::Confidential))
    }

    /// Adds the person the step names to its group, for good.
    pub(super) async fn add(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
    ) -> Result<ActionOutcome, ActionOutcome> {
        self.joined(step, people, Expiry::Never).await
    }

    /// Adds the person the step names to its group for its number of
    /// hours; the membership ends by itself.
    pub(super) async fn grant(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let hours = whole_number(step.call, HOURS_INPUT, 1, LONGEST_HOURS)?;
        let ends = clock::now() + time::Duration::hours(i64::from(hours));
        self.joined(step, people, Expiry::At(ends)).await
    }

    /// Adds the person the step names to its group until `until`.
    async fn joined(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
        until: Expiry,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let group_id = id(step.call, GROUP_INPUT, GroupId::from_uuid)?;
        let user_id = people.person(step, PERSON_INPUT).await?;
        let request = AddMemberRequest {
            group_id,
            member: PrincipalRef::User(user_id),
            until,
        };
        self.add
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let ends_at = match until {
            Expiry::Never => Ok(FlowData::null()),
            Expiry::At(at) => moment_text(at),
        };
        let output = data(vec![
            ("user_id", FlowData::text(user_id.to_string())),
            ("ends_at", ends_at),
        ])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Removes the person the step names from its group.
    pub(super) async fn remove(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let group_id = id(step.call, GROUP_INPUT, GroupId::from_uuid)?;
        let user_id = people.person(step, PERSON_INPUT).await?;
        let request = RemoveMemberRequest {
            group_id,
            member: PrincipalRef::User(user_id),
        };
        self.remove
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let output = data(vec![("user_id", FlowData::text(user_id.to_string()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Takes the person the step names out of every group they are in
    /// directly; a group they reach only through another stays reached
    /// through it.
    pub(super) async fn remove_everywhere(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let user_id = people.person(step, PERSON_INPUT).await?;
        let member = PrincipalRef::User(user_id);
        let held = self
            .principal_access
            .execute(step.caller, member)
            .await
            .map_err(unmade)?;
        for membership in &held.memberships {
            let request = RemoveMemberRequest {
                group_id: membership.group,
                member,
            };
            self.remove
                .execute(step.caller, step.auditor, request)
                .await
                .map_err(unmade)?;
        }
        let output = data(vec![("groups_left", count(held.memberships.len()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Answers whether the person the step names may do its action on its
    /// resource type, or on the one object it names, and why.
    pub(super) async fn check(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let question = question_of(step)?;
        let user_id = people.person(step, PERSON_INPUT).await?;
        let request = CheckAccessRequest {
            subject: PrincipalRef::User(user_id),
            questions: vec![question],
        };
        let decisions = self
            .check
            .execute(step.caller, request)
            .await
            .map_err(unmade)?;
        let Some(decision) = decisions.first() else {
            return Err(failed("the access check gave no answer"));
        };
        let output = data(vec![
            ("allowed", Ok(FlowData::bool(decision.is_allowed()))),
            ("why", FlowData::text(why(decision))),
        ])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Gives the person the step names its rights for its number of
    /// minutes, for its reason; the grant ends by itself.
    pub(super) async fn break_glass(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let access = emergency_access(step)?;
        let minutes = whole_number(step.call, MINUTES_INPUT, 1, LONGEST_MINUTES)?;
        let reason = Text::new(REASON_INPUT, text(step.call, REASON_INPUT)?)
            .map_err(|_| failed("the step's reason is not text a record keeps"))?;
        let user_id = people.person(step, PERSON_INPUT).await?;
        let request = BreakGlassGrantRequest {
            user_id,
            access,
            reason,
            duration_seconds: i64::from(minutes) * 60,
        };
        let grant = self
            .break_glass
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let ends = clock::now() + time::Duration::minutes(i64::from(minutes));
        let output = data(vec![
            ("grant_id", FlowData::text(grant.to_string())),
            ("ends_at", moment_text(ends)),
        ])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Approves or denies the access request the step names.
    pub(super) async fn decide(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let request_id = id(step.call, REQUEST_INPUT, AccessRequestId::from_uuid)?;
        let decision = text(step.call, DECISION_INPUT)?;
        let decided = match decision {
            "approve" => {
                self.approve
                    .execute(step.caller, step.auditor, request_id)
                    .await
            }
            "deny" => {
                self.deny
                    .execute(step.caller, step.auditor, request_id)
                    .await
            }
            _ => return Err(failed("the step's decision is not approve or deny")),
        };
        decided.map_err(unmade)?;
        let output = data(vec![("decision", FlowData::text(decision))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Reminds the person the step names, while the access request it names
    /// is still open: one notice now, and the next round after the hours it
    /// says. Once the request is decided, withdrawn or ran out, the step
    /// succeeds with how it ended and sends nothing.
    pub(super) async fn remind(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let request_id = id(step.call, REQUEST_INPUT, AccessRequestId::from_uuid)?;
        let every = whole_number(step.call, EVERY_INPUT, 1, LONGEST_REMINDER_HOURS)?;
        let request = self
            .request
            .execute(step.caller, request_id)
            .await
            .map_err(unmade)?;
        if request.status() != AccessRequestStatus::Pending {
            let output = data(vec![("ended", FlowData::text(request.status().as_str()))])?;
            return Ok(succeeded(step, output, DataClassLevel::Internal));
        }
        people.notify(step, Offering::Nothing).await?;
        let due = clock::now().saturating_add(Duration::hours(i64::from(every)));
        Ok(ActionOutcome::NotYet { due })
    }

    /// Opens a review of the group the step names, by its reviewers, due in
    /// two weeks; access nobody answers for is kept.
    pub(super) async fn open_review(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let group_id = id(step.call, GROUP_INPUT, GroupId::from_uuid)?;
        let reviewers = self.reviewers(step, people).await?;
        let request = StartRequest {
            name: Label::new("name", "Review a workflow opened")
                .map_err(|_| failed("the review's name does not read"))?,
            scope: ReviewScope::Group(group_id),
            reviewers,
            due: clock::now() + time::Duration::days(REVIEW_DAYS),
            unanswered: Unanswered::KeepAccess,
        };
        let review = self
            .start_review
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let output = data(vec![("review_id", FlowData::text(review.id().to_string()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// The people the step names as reviewers.
    async fn reviewers(
        &self,
        step: &CompanyCall<'_>,
        people: &PeopleActions,
    ) -> Result<Vec<UserId>, ActionOutcome> {
        let mut found = Vec::new();
        for named in texts(step.call, REVIEWERS_INPUT)? {
            found.push(people.named(step, named).await?);
        }
        Ok(found)
    }
}

/// The question the step asks: its action on its resource type, or on the
/// one object it names.
fn question_of(step: &CompanyCall<'_>) -> Result<AccessQuestion, ActionOutcome> {
    let segment = |input: &'static str| {
        let named = text(step.call, input)?;
        PermissionSegment::new(input, named)
            .map_err(|_| failed(&format!("the step's {input} is not a permission name")))
    };
    let action = segment(ACTION_INPUT)?;
    let resource = segment(RESOURCE_INPUT)?;
    let target = match optional_text(step.call, OBJECT_INPUT)? {
        None => CheckTarget::AnyOf(resource),
        Some(key) => CheckTarget::Object(ObjectRef::new(
            resource,
            ObjectKey::new(key).map_err(|_| failed("the step's object is not an object's key"))?,
        )),
    };
    Ok(AccessQuestion::new(action, target))
}

/// Why `decision` came out as it did: the reason a no was given, or what
/// gave the yes.
fn why(decision: &AccessDecision) -> &'static str {
    match decision {
        AccessDecision::Allowed(AllowedBy::Permission(_)) => "permission",
        AccessDecision::Allowed(AllowedBy::Relation { .. }) => "relation",
        AccessDecision::Denied(because) => because.as_str(),
    }
}

/// The rights the step gives: each permission it names, built in such as
/// `users:manage` or the tenant's own such as `invoices:approve`.
fn emergency_access(step: &CompanyCall<'_>) -> Result<BreakGlassAccess, ActionOutcome> {
    let mut system = Vec::new();
    let mut custom = Vec::new();
    for named in texts(step.call, PERMISSIONS_INPUT)? {
        if let Some(permission) = SystemPermission::parse(named) {
            system.push(permission);
            continue;
        }
        let permission = CustomPermission::parse(named)
            .ok_or_else(|| failed(&format!("{named} is not a permission")))?;
        custom.push(permission);
    }
    BreakGlassAccess::new(system, custom).map_err(|_| failed("the step names no permission"))
}
