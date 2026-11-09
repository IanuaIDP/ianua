//! The company's own steps: a built-in integration whose operations act on
//! the tenant itself, its people, groups, sign-ins, agents, apps, audit
//! trail and classification rules.
//!
//! Pat's workflow starts when Lee signs in from a risky place, signs Lee
//! out everywhere and pauses Lee's agents. Each step takes the same action
//! Pat could take from the dashboard, as Pat, with what Pat holds the
//! moment it acts. A step changing who can do what counts as an admin
//! action, so publishing asks for an approval right before it. Nothing is
//! called outside the platform, and no account is connected.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::FieldName;
use crate::domains::workflows::integration::{
    AccountNeed, InputNeed, InputSpec, IntegrationKey, OperationKey, OperationSpec,
    OperationSpecParams,
};
use crate::shared::errors::DomainError;
use crate::types::{ActionClass, DeclaredAction};

/// The built-in integration whose operations act on the company's own
/// platform; the platform runs them itself.
pub const COMPANY_INTEGRATION: &str = "ianua";

/// The input naming a person: their email address or their user id.
pub const PERSON_INPUT: &str = "person";
/// The input naming a group by its id.
pub const GROUP_INPUT: &str = "group";
/// The input saying for how many hours access is given.
pub const HOURS_INPUT: &str = "hours";
/// The input naming an access request by its id.
pub const REQUEST_INPUT: &str = "request";
/// The input deciding an access request: `approve` or `deny`.
pub const DECISION_INPUT: &str = "decision";
/// The input naming an agent by its id.
pub const AGENT_INPUT: &str = "agent";
/// The input naming an agent's run by its id.
pub const RUN_INPUT: &str = "run";
/// The input naming an app, one of the tenant's routes, by its id.
pub const APP_INPUT: &str = "app";
/// The input saying how far back to read: `hour`, `day`, `week` or
/// `month`.
pub const SINCE_INPUT: &str = "since";
/// The input naming the event type an audit search looks for.
pub const WHAT_INPUT: &str = "what";
/// The input naming a field of data, such as `orders.card_last4`.
pub const FIELD_INPUT: &str = "field";
/// The input naming a data classification level, such as `confidential`.
pub const LEVEL_INPUT: &str = "level";
/// The input naming a review's reviewers: a list of people.
pub const REVIEWERS_INPUT: &str = "reviewers";

/// The input naming an address to invite.
pub const EMAIL_INPUT: &str = "email";
/// The input naming the name an invited account gets.
pub const NAME_INPUT: &str = "name";
/// The input naming a role by its id.
pub const ROLE_INPUT: &str = "role";
/// The input naming the action an access check asks about, such as `read`.
pub const ACTION_INPUT: &str = "action";
/// The input naming the resource type an access check asks about, such as
/// `invoices`.
pub const RESOURCE_INPUT: &str = "resource";
/// The input naming one object of that resource type, by its key.
pub const OBJECT_INPUT: &str = "object";

/// The input naming the rights emergency access gives: permissions such as
/// `users:manage` or `invoices:approve`.
pub const PERMISSIONS_INPUT: &str = "permissions";
/// The input saying for how many minutes emergency access lasts.
pub const MINUTES_INPUT: &str = "minutes";
/// The input saying why, kept on the audit trail.
pub const REASON_INPUT: &str = "reason";
/// The input naming what an agent was given to reach, such as
/// `calendar:abc123`.
pub const SHARED_INPUT: &str = "shared";
/// The input saying how many hours apart reminders go out.
pub const EVERY_INPUT: &str = "every";
/// The input giving a notice's title.
pub const TITLE_INPUT: &str = "title";
/// The input giving what else a notice says.
pub const MESSAGE_INPUT: &str = "message";
/// The input naming an API key by its id.
pub const KEY_INPUT: &str = "key";
/// The input naming the signal reported: `risk_low`, `risk_medium`,
/// `risk_high`, `password_compromised` or `device_compromised`.
pub const SIGNAL_INPUT: &str = "signal";
/// The input giving the data a step works on, such as an earlier step's
/// answer.
pub const DATA_INPUT: &str = "data";
/// The input naming an access review by its id.
pub const REVIEW_INPUT: &str = "review";
/// The input giving what is suggested beside a review's holders: a list,
/// each naming a `person` (address or user id) or an `agent` (its id),
/// `keep` or `remove` as its `suggest`, and its `reason`.
pub const SUGGESTIONS_INPUT: &str = "suggestions";
/// The input naming the format an audit pack is written in: `csv`, the
/// default, or `json`.
pub const FORMAT_INPUT: &str = "format";

/// A person, required.
const NEEDS_PERSON: (&str, InputNeed) = (PERSON_INPUT, InputNeed::Required);
/// A group, required.
const NEEDS_GROUP: (&str, InputNeed) = (GROUP_INPUT, InputNeed::Required);
/// An agent, required.
const NEEDS_AGENT: (&str, InputNeed) = (AGENT_INPUT, InputNeed::Required);
/// An app, required.
const NEEDS_APP: (&str, InputNeed) = (APP_INPUT, InputNeed::Required);
/// How far back to look, a day when left out.
const MAY_SAY_SINCE: (&str, InputNeed) = (SINCE_INPUT, InputNeed::Optional);

/// What inviting a person takes: their address, their name and the role
/// accepting gives.
const INVITING: &[(&str, InputNeed)] = &[
    (EMAIL_INPUT, InputNeed::Required),
    (NAME_INPUT, InputNeed::Required),
    (ROLE_INPUT, InputNeed::Required),
];
/// What an access check takes: the person, the action and the resource
/// type, and one object of it when asked about one.
const CHECKING: &[(&str, InputNeed)] = &[
    NEEDS_PERSON,
    (ACTION_INPUT, InputNeed::Required),
    (RESOURCE_INPUT, InputNeed::Required),
    (OBJECT_INPUT, InputNeed::Optional),
];

/// What giving access for a while takes: the person, the group and for
/// how many hours.
const GRANTING: &[(&str, InputNeed)] = &[
    NEEDS_PERSON,
    NEEDS_GROUP,
    (HOURS_INPUT, InputNeed::Required),
];
/// What deciding an access request takes: the request and the decision.
const DECIDING: &[(&str, InputNeed)] = &[
    (REQUEST_INPUT, InputNeed::Required),
    (DECISION_INPUT, InputNeed::Required),
];
/// What classifying a field takes: the field and its level.
const CLASSIFYING: &[(&str, InputNeed)] = &[
    (FIELD_INPUT, InputNeed::Required),
    (LEVEL_INPUT, InputNeed::Required),
];

/// What breaking glass takes: the person, the rights, for how many minutes
/// and why.
const BREAKING_GLASS: &[(&str, InputNeed)] = &[
    NEEDS_PERSON,
    (PERMISSIONS_INPUT, InputNeed::Required),
    (MINUTES_INPUT, InputNeed::Required),
    (REASON_INPUT, InputNeed::Required),
];

/// What notifying a person takes: the person and a title, and a message
/// when there is more to say.
const NOTIFYING: &[(&str, InputNeed)] = &[
    NEEDS_PERSON,
    (TITLE_INPUT, InputNeed::Required),
    (MESSAGE_INPUT, InputNeed::Optional),
];

/// What offering to ask for access takes: the person, the group, a title,
/// and a message when there is more to say.
const OFFERING: &[(&str, InputNeed)] = &[
    NEEDS_PERSON,
    NEEDS_GROUP,
    (TITLE_INPUT, InputNeed::Required),
    (MESSAGE_INPUT, InputNeed::Optional),
];

/// What reminding until a request is decided takes: the person, the
/// request, a title, how many hours apart, and a message when there is
/// more to say.
const REMINDING: &[(&str, InputNeed)] = &[
    NEEDS_PERSON,
    (REQUEST_INPUT, InputNeed::Required),
    (TITLE_INPUT, InputNeed::Required),
    (EVERY_INPUT, InputNeed::Required),
    (MESSAGE_INPUT, InputNeed::Optional),
];

/// One of the company's own steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompanyOperation {
    /// Reads a person from the tenant's directory.
    FindPerson,
    /// Suspends a person: they cannot sign in until brought back.
    SuspendPerson,
    /// Clears a person's second factors, so they set up a new one.
    ResetTwoStep,
    /// Ends every session a person holds.
    SignOut,
    /// Ends every API key a person made.
    RevokeKeys,
    /// Forgets every device a person remembered, so the next sign-in from
    /// any of them asks for the second factor again.
    ForgetDevices,
    /// Invites a person to the tenant with a role.
    InvitePerson,
    /// Reads a group's members.
    ListMembers,
    /// Adds a person to a group.
    AddToGroup,
    /// Removes a person from a group.
    RemoveFromGroup,
    /// Removes a person from every group they are in directly.
    RemoveGroups,
    /// Adds a person to a group for a number of hours.
    GrantAccess,
    /// Approves or denies an access request.
    DecideRequest,
    /// Answers whether a person may do an action on a resource type, or on
    /// one object of it.
    CheckAccess,
    /// Gives a person named rights for a few minutes in an emergency; it
    /// ends by itself.
    BreakGlass,
    /// Opens an access review of a group's members.
    OpenReview,
    /// Suggests keep or remove, with a reason, beside holders of an open
    /// access review; its reviewers still decide.
    SuggestReview,
    /// Suspends the identity so further agent actions are refused.
    PauseAgent,
    /// Ends one of an agent's runs.
    EndAgentRun,
    /// Reads an agent's recent runs.
    AgentActions,
    /// Reads the recent requests to an app.
    ReadRequests,
    /// Closes an app to workflows.
    CloseApp,
    /// Checks every request to an app harder for a number of minutes, during
    /// an attack; it ends on its own.
    AttackMode,
    /// Searches the tenant's audit trail.
    SearchAudit,
    /// Asks for a sealed export of the tenant's audit trail, for an
    /// auditor to check against the tenant's published keys.
    MakeAuditPack,
    /// Adds a rule classifying a field of data.
    ClassifyField,
    /// Puts a notice in a person's inbox.
    Notify,
    /// Puts a notice in a person's inbox offering them to ask to join a
    /// group; asking still needs someone's approval.
    OfferAccess,
    /// Takes back every task an agent holds, and every one passed on from
    /// them.
    RevokeAgentTasks,
    /// Takes one thing an agent was given to reach out of every task it
    /// holds.
    NarrowAgent,
    /// Reminds a person every few hours, while the run lasts, until an
    /// access request is decided.
    RemindUntilDecided,
    /// Pauses an API key: it signs in nothing until resumed.
    PauseKey,
    /// Resumes a paused API key, giving its access back.
    ResumeKey,
    /// Tells every signal stream that takes it something of a person: a
    /// risk level, a compromised password or device.
    SendSignal,
    /// Hides the fields of some data the tenant classifies as sensitive,
    /// as the gateway hides them in an app's answer.
    HideFields,
    /// Lets the change a "before" workflow guards happen.
    Allow,
    /// Stops the change a "before" workflow guards.
    Refuse,
}

impl CompanyOperation {
    /// Every company step, in the order the catalog lists them.
    pub const ALL: [Self; 37] = [
        Self::FindPerson,
        Self::SuspendPerson,
        Self::ResetTwoStep,
        Self::SignOut,
        Self::RevokeKeys,
        Self::ForgetDevices,
        Self::InvitePerson,
        Self::ListMembers,
        Self::AddToGroup,
        Self::RemoveFromGroup,
        Self::RemoveGroups,
        Self::GrantAccess,
        Self::DecideRequest,
        Self::CheckAccess,
        Self::BreakGlass,
        Self::OpenReview,
        Self::SuggestReview,
        Self::PauseAgent,
        Self::EndAgentRun,
        Self::AgentActions,
        Self::ReadRequests,
        Self::CloseApp,
        Self::AttackMode,
        Self::SearchAudit,
        Self::MakeAuditPack,
        Self::ClassifyField,
        Self::Notify,
        Self::OfferAccess,
        Self::RevokeAgentTasks,
        Self::NarrowAgent,
        Self::RemindUntilDecided,
        Self::PauseKey,
        Self::ResumeKey,
        Self::SendSignal,
        Self::HideFields,
        Self::Allow,
        Self::Refuse,
    ];

    /// The name the step is called by.
    // One arm per company step, so a step added without its name fails to
    // compile here; splitting the match would lose that.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::FindPerson => "find-person",
            Self::SuspendPerson => "suspend-person",
            Self::ResetTwoStep => "reset-two-step",
            Self::SignOut => "sign-out",
            Self::RevokeKeys => "revoke-keys",
            Self::ForgetDevices => "forget-devices",
            Self::InvitePerson => "invite-person",
            Self::ListMembers => "list-members",
            Self::AddToGroup => "add-to-group",
            Self::RemoveFromGroup => "remove-from-group",
            Self::RemoveGroups => "remove-groups",
            Self::GrantAccess => "grant-access",
            Self::DecideRequest => "decide-request",
            Self::CheckAccess => "check-access",
            Self::BreakGlass => "break-glass",
            Self::OpenReview => "open-review",
            Self::SuggestReview => "suggest-review",
            Self::PauseAgent => "pause-agent",
            Self::EndAgentRun => "end-agent-run",
            Self::AgentActions => "agent-actions",
            Self::ReadRequests => "read-requests",
            Self::CloseApp => "close-app",
            Self::AttackMode => "attack-mode",
            Self::SearchAudit => "search-audit",
            Self::MakeAuditPack => "make-audit-pack",
            Self::ClassifyField => "classify-field",
            Self::Notify => "notify",
            Self::OfferAccess => "offer-access",
            Self::RevokeAgentTasks => "revoke-agent-tasks",
            Self::NarrowAgent => "narrow-agent",
            Self::RemindUntilDecided => "remind-until-decided",
            Self::PauseKey => "pause-key",
            Self::ResumeKey => "resume-key",
            Self::SendSignal => "send-signal",
            Self::HideFields => "hide-fields",
            Self::Allow => "allow",
            Self::Refuse => "refuse",
        }
    }

    /// The step called `key`, if it is one.
    #[must_use]
    pub fn named(key: &OperationKey) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.key() == key.as_str())
    }

    /// What kind of action it is. Steps that only narrow what someone may
    /// do, such as signing out or pausing an agent, change something; steps
    /// that give or take away access change who can do what.
    // Every step is named, with no catch-all, so a step added without its
    // kind of action fails to compile here; a catch-all could file a new
    // admin step as a harmless one.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn effect(self) -> ActionClass {
        match self {
            Self::FindPerson
            | Self::ListMembers
            | Self::CheckAccess
            | Self::AgentActions
            | Self::ReadRequests
            | Self::SearchAudit
            | Self::MakeAuditPack
            | Self::HideFields
            | Self::Allow
            | Self::Refuse => ActionClass::Read,
            Self::Notify | Self::OfferAccess | Self::RemindUntilDecided => ActionClass::Communicate,
            Self::SignOut
            | Self::RevokeKeys
            | Self::ForgetDevices
            | Self::OpenReview
            | Self::SuggestReview
            | Self::PauseAgent
            | Self::EndAgentRun
            | Self::RevokeAgentTasks
            | Self::NarrowAgent
            | Self::PauseKey
            | Self::SendSignal
            | Self::AttackMode => ActionClass::Write,
            Self::SuspendPerson
            | Self::ResetTwoStep
            | Self::AddToGroup
            | Self::RemoveFromGroup
            | Self::RemoveGroups
            | Self::InvitePerson
            | Self::GrantAccess
            | Self::DecideRequest
            | Self::BreakGlass
            | Self::CloseApp
            | Self::ClassifyField
            | Self::ResumeKey => ActionClass::Admin,
        }
    }

    /// The inputs it takes, each with whether it must be given.
    // One arm per company step, so a step added without its inputs fails to
    // compile here; splitting the match would lose that.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn inputs(self) -> &'static [(&'static str, InputNeed)] {
        match self {
            Self::FindPerson
            | Self::SuspendPerson
            | Self::ResetTwoStep
            | Self::SignOut
            | Self::RevokeKeys
            | Self::ForgetDevices
            | Self::RemoveGroups => &[NEEDS_PERSON],
            Self::InvitePerson => INVITING,
            Self::CheckAccess => CHECKING,
            Self::BreakGlass => BREAKING_GLASS,
            Self::ListMembers => &[NEEDS_GROUP],
            Self::AddToGroup | Self::RemoveFromGroup => &[NEEDS_PERSON, NEEDS_GROUP],
            Self::GrantAccess => GRANTING,
            Self::DecideRequest => DECIDING,
            Self::OpenReview => &[NEEDS_GROUP, (REVIEWERS_INPUT, InputNeed::Required)],
            Self::SuggestReview => &[
                (REVIEW_INPUT, InputNeed::Required),
                (SUGGESTIONS_INPUT, InputNeed::Required),
            ],
            Self::PauseAgent | Self::RevokeAgentTasks => &[NEEDS_AGENT],
            Self::NarrowAgent => &[NEEDS_AGENT, (SHARED_INPUT, InputNeed::Required)],
            Self::EndAgentRun => &[NEEDS_AGENT, (RUN_INPUT, InputNeed::Required)],
            Self::AgentActions => &[NEEDS_AGENT, MAY_SAY_SINCE],
            Self::ReadRequests => &[NEEDS_APP, MAY_SAY_SINCE],
            Self::CloseApp => &[NEEDS_APP],
            Self::AttackMode => &[NEEDS_APP, (MINUTES_INPUT, InputNeed::Required)],
            Self::SearchAudit => &[(WHAT_INPUT, InputNeed::Optional), MAY_SAY_SINCE],
            Self::MakeAuditPack => &[
                (WHAT_INPUT, InputNeed::Optional),
                MAY_SAY_SINCE,
                (FORMAT_INPUT, InputNeed::Optional),
            ],
            Self::ClassifyField => CLASSIFYING,
            Self::Notify => NOTIFYING,
            Self::OfferAccess => OFFERING,
            Self::RemindUntilDecided => REMINDING,
            Self::PauseKey | Self::ResumeKey => &[(KEY_INPUT, InputNeed::Required)],
            Self::SendSignal => &[NEEDS_PERSON, (SIGNAL_INPUT, InputNeed::Required)],
            Self::HideFields => &[
                (DATA_INPUT, InputNeed::Required),
                (LEVEL_INPUT, InputNeed::Optional),
            ],
            Self::Allow | Self::Refuse => &[],
        }
    }

    /// How the integration describes the step, taking data up to
    /// `ceiling`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when a name or input here breaks
    /// a rule of the workflow domain, which a change here would cause.
    pub fn spec(self, ceiling: DataClassLevel) -> Result<OperationSpec, DomainError> {
        let inputs = self
            .inputs()
            .iter()
            .map(|(name, need)| Ok(InputSpec::new(FieldName::new(*name)?, *need)))
            .collect::<Result<Vec<_>, DomainError>>()?;
        OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new(COMPANY_INTEGRATION)?,
            operation: OperationKey::new(self.key())?,
            inputs,
            effect: DeclaredAction::Declared(self.effect()),
            account: AccountNeed::Company,
            ceiling,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every company step describes itself within the workflow domain's
    /// rules, and is found again by its name.
    #[test]
    fn every_step_describes_itself_and_is_found_by_name() {
        for operation in CompanyOperation::ALL {
            let spec = operation.spec(DataClassLevel::Confidential).unwrap();

            assert_eq!(CompanyOperation::named(spec.operation()), Some(operation));
            assert_eq!(spec.account(), AccountNeed::Company);
        }
    }

    /// Adding a group member, granting access, breaking glass and suspending
    /// a person all declare effects that may be high risk.
    #[test]
    fn steps_changing_access_are_high_risk() {
        for operation in [
            CompanyOperation::AddToGroup,
            CompanyOperation::GrantAccess,
            CompanyOperation::BreakGlass,
            CompanyOperation::SuspendPerson,
        ] {
            let spec = operation.spec(DataClassLevel::Confidential).unwrap();

            assert!(spec.effect().may_be_high_risk());
        }
    }

    /// Signing someone out only narrows what they may do; it runs at once,
    /// with no yes needed.
    #[test]
    fn steps_that_only_narrow_are_not_high_risk() {
        for operation in [
            CompanyOperation::SignOut,
            CompanyOperation::PauseAgent,
            CompanyOperation::RevokeKeys,
            CompanyOperation::RevokeAgentTasks,
            CompanyOperation::NarrowAgent,
            CompanyOperation::SuggestReview,
        ] {
            let spec = operation.spec(DataClassLevel::Confidential).unwrap();

            assert!(!spec.effect().may_be_high_risk());
        }
    }

    /// A name no company step goes by is none of them.
    #[test]
    fn an_unknown_name_is_no_step() {
        let key = OperationKey::new("delete-company").unwrap();

        assert_eq!(CompanyOperation::named(&key), None);
    }
}
