//! The built-in company integration: steps acting on the tenant itself,
//! its people, groups, access, agents, apps, audit trail and
//! classification rules.
//!
//! It declares the steps and explains them to a workflow's builder, so the
//! catalog lists them beside every other step. The platform makes them
//! itself, each through the dashboard's own action, as the person the run
//! acts for; nothing is ever called through this integration.

mod inputs;

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::domains::workflows::integration::company::{
    COMPANY_INTEGRATION, CompanyOperation,
};
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationSpec};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::answer::failed;
use ianua_integration::describe::{BuiltInText, GuideText, built_in_profile, guide};
use ianua_integration::{Called, Integration};

use self::inputs::input_text;

/// How the integration presents itself.
const PROFILE: BuiltInText<'static> = BuiltInText {
    title: "Company",
    description: "Acts on the company itself, as the person the run is for: finds people, signs them out, changes their groups, pauses agents, closes apps to workflows and reads the audit trail.",
    icon: "shield",
    brand: "0f766e",
};

/// The company integration, installed under `ianua`.
pub struct CompanyIntegration {
    profile: IntegrationProfile,
    operations: Vec<OperationSpec>,
    guides: Vec<OperationGuide>,
}

impl CompanyIntegration {
    /// The integration, its steps taking data up to `ceiling`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when a step or a guide breaks a rule of the
    /// workflow domain, which a change here would cause.
    pub fn new(ceiling: DataClassLevel) -> Result<Self, DomainError> {
        let key = IntegrationKey::new(COMPANY_INTEGRATION)?;
        let operations = CompanyOperation::ALL
            .into_iter()
            .map(|operation| operation.spec(ceiling))
            .collect::<Result<Vec<_>, _>>()?;
        let guides = CompanyOperation::ALL
            .into_iter()
            .map(guide_of)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            profile: built_in_profile(&key, &PROFILE)?,
            operations,
            guides,
        })
    }
}

#[async_trait]
impl Integration for CompanyIntegration {
    fn profile(&self) -> &IntegrationProfile {
        &self.profile
    }

    fn operations(&self) -> &[OperationSpec] {
        &self.operations
    }

    fn guides(&self) -> &[OperationGuide] {
        &self.guides
    }

    /// The company keeps no account.
    async fn check_account(&self, _credential: &Secret) -> AccountCheck {
        AccountCheck::NotCheckable
    }

    async fn call(&self, _call: &ActionCall, _credential: Option<&Secret>) -> Called {
        failed("a company step is run by the platform itself").into()
    }
}

/// How `operation` is explained to a workflow's builder.
fn guide_of(operation: CompanyOperation) -> Result<OperationGuide, DomainError> {
    let words = WORDS
        .iter()
        .find(|words| words.operation == operation)
        .ok_or_else(|| DomainError::infra_msg("a company step has no words"))?;
    let inputs = operation
        .inputs()
        .iter()
        .map(|(name, _)| input_text(name))
        .collect::<Result<Vec<_>, _>>()?;
    guide(&GuideText {
        operation: operation.key(),
        title: words.title,
        description: words.description,
        inputs: &inputs,
        outputs: words.outputs,
        preview: None,
    })
}

/// How one step is explained: its title, what it does, and what it gives
/// back at which path.
struct Words {
    operation: CompanyOperation,
    title: &'static str,
    description: &'static str,
    outputs: &'static [(&'static str, &'static str)],
}

/// The words every company step is explained with.
const WORDS: &[Words] = &[
    Words {
        operation: CompanyOperation::FindPerson,
        title: "Look up a person",
        description: "Reads a person from the company's own directory, by their address or user id.",
        outputs: &[
            ("user_id", "Their user id."),
            ("name", "Their name."),
            ("email", "Their address."),
            (
                "status",
                "Whether they may sign in, such as active or locked.",
            ),
        ],
    },
    Words {
        operation: CompanyOperation::SuspendPerson,
        title: "Suspend a person",
        description: "Locks a person's account: they cannot sign in and their sessions end until someone unlocks it. Their data stays.",
        outputs: &[("user_id", "The person suspended.")],
    },
    Words {
        operation: CompanyOperation::ResetTwoStep,
        title: "Reset their two-step sign-in",
        description: "Removes a person's authenticator apps and passkeys, so they set up a new one at their next sign-in.",
        outputs: &[("factors_removed", "How many factors were removed.")],
    },
    Words {
        operation: CompanyOperation::SignOut,
        title: "Sign someone out everywhere",
        description: "Ends every session a person holds at once.",
        outputs: &[("sessions_ended", "How many sessions were ended.")],
    },
    Words {
        operation: CompanyOperation::RevokeKeys,
        title: "Revoke their API keys",
        description: "Ends every API key the person made; each stops working at once.",
        outputs: &[("keys_revoked", "How many keys were ended.")],
    },
    Words {
        operation: CompanyOperation::ForgetDevices,
        title: "Forget their devices",
        description: "Stops trusting every device a person remembered, so the next sign-in from any of them asks for their second factor again.",
        outputs: &[("devices_forgotten", "How many devices were forgotten.")],
    },
    Words {
        operation: CompanyOperation::InvitePerson,
        title: "Invite a person",
        description: "Invites a person to the company with a role, mailing them a link to accept. It gives them the role's access, so it needs a yes before it.",
        outputs: &[("user_id", "The account the invitation made.")],
    },
    Words {
        operation: CompanyOperation::RemoveGroups,
        title: "Take out of all groups",
        description: "Takes a person out of every group they are in directly, and with it what those groups gave.",
        outputs: &[("groups_left", "How many groups they were taken out of.")],
    },
    Words {
        operation: CompanyOperation::CheckAccess,
        title: "Check access",
        description: "Answers whether a person may do an action on a kind of thing, such as reading invoices, or on one of them, by the company's own permissions and relations.",
        outputs: &[
            ("allowed", "Whether they may."),
            (
                "why",
                "What gave the yes, permission or relation, or why not, such as not_held.",
            ),
        ],
    },
    Words {
        operation: CompanyOperation::BreakGlass,
        title: "Break glass",
        description: "Gives a person named rights for a few minutes in an emergency, with a reason kept on the audit trail. It ends by itself, and like every change to who can do what, two people say yes before it.",
        outputs: &[
            ("grant_id", "The emergency grant."),
            ("ends_at", "When it ends by itself."),
        ],
    },
    Words {
        operation: CompanyOperation::ListMembers,
        title: "List a group's members",
        description: "Reads up to 100 members of a group, the longest-standing first.",
        outputs: &[
            (
                "members",
                "Each member, with member as who they are, name, and joined_at.",
            ),
            ("count", "How many members were read."),
        ],
    },
    Words {
        operation: CompanyOperation::AddToGroup,
        title: "Add to a group",
        description: "Adds a person to a group, with everything the group gives.",
        outputs: &[
            ("user_id", "The person added."),
            ("ends_at", "Empty: the membership does not end by itself."),
        ],
    },
    Words {
        operation: CompanyOperation::RemoveFromGroup,
        title: "Remove from a group",
        description: "Takes a person out of a group, and with it what the group gave.",
        outputs: &[("user_id", "The person removed.")],
    },
    Words {
        operation: CompanyOperation::GrantAccess,
        title: "Give access for a while",
        description: "Adds a person to a group for a number of hours, up to 30 days. The membership ends by itself; nobody keeps it by accident.",
        outputs: &[
            ("user_id", "The person given access."),
            ("ends_at", "When the membership ends."),
        ],
    },
    Words {
        operation: CompanyOperation::DecideRequest,
        title: "Approve or deny an access request",
        description: "Decides a request someone made for access. The workflow may approve only what its person could approve by hand.",
        outputs: &[("decision", "approve or deny, as decided.")],
    },
    Words {
        operation: CompanyOperation::OpenReview,
        title: "Open an access review",
        description: "Opens a review of who is in a group, due in two weeks. Access nobody answers for is kept.",
        outputs: &[("review_id", "The review opened.")],
    },
    Words {
        operation: CompanyOperation::SuggestReview,
        title: "Suggest keep or remove",
        description: "Puts keep or remove, with a reason, beside people in an open access review. The reviewers still decide every one.",
        outputs: &[("suggested", "How many people were given a suggestion.")],
    },
    Words {
        operation: CompanyOperation::PauseAgent,
        title: "Pause an agent",
        description: "Suspends an agent: it stops at its next step and takes no new work until someone resumes it.",
        outputs: &[("agent_id", "The agent paused.")],
    },
    Words {
        operation: CompanyOperation::EndAgentRun,
        title: "End an agent's run",
        description: "Ends one run of an agent where it stands.",
        outputs: &[("status", "The run's status once ended.")],
    },
    Words {
        operation: CompanyOperation::AgentActions,
        title: "List an agent's recent runs",
        description: "Reads an agent's runs started in the time asked for, newest first, with what each spent.",
        outputs: &[
            (
                "runs",
                "Each run, with run_id, status, spent and started_at.",
            ),
            ("count", "How many runs were read."),
            (
                "spent",
                "What they spent together, in the provider's currency.",
            ),
        ],
    },
    Words {
        operation: CompanyOperation::ReadRequests,
        title: "Read recent requests to an app",
        description: "Counts the requests that reached an app through the gateway in the time asked for, and how many were refused.",
        outputs: &[
            ("requests", "How many requests reached it."),
            ("denied", "How many were refused."),
            ("server_errors", "How many the app itself failed."),
        ],
    },
    Words {
        operation: CompanyOperation::CloseApp,
        title: "Close an app to workflows",
        description: "Stops every workflow step from reaching an app until someone opens it again.",
        outputs: &[("app", "The app closed.")],
    },
    Words {
        operation: CompanyOperation::AttackMode,
        title: "Turn on attack mode",
        description: "Checks every request to an app harder for a while: addresses caught by decoys or recon scoring are refused, and each address may send 60 requests a minute. It ends on its own.",
        outputs: &[("until", "When attack mode ends.")],
    },
    Words {
        operation: CompanyOperation::SearchAudit,
        title: "Search the audit trail",
        description: "Reads up to 50 of the newest audit records of a kind, in the time asked for.",
        outputs: &[
            (
                "records",
                "Each record, with record_id, event_type, actor and occurred_at.",
            ),
            ("count", "How many records were read."),
        ],
    },
    Words {
        operation: CompanyOperation::MakeAuditPack,
        title: "Make an audit pack",
        description: "Asks for an export of the audit trail, of a kind and since when asked. The platform writes the file and seals it with the company's published key, for an auditor to check.",
        outputs: &[
            (
                "export_id",
                "The export, to fetch its file and seal by once it is ready.",
            ),
            ("status", "pending: the file is written next."),
        ],
    },
    Words {
        operation: CompanyOperation::ClassifyField,
        title: "Classify a field",
        description: "Adds a rule classifying a field of data, such as orders.card_last4. The gateway masks it from then on.",
        outputs: &[("rule_id", "The rule added.")],
    },
    Words {
        operation: CompanyOperation::Notify,
        title: "Notify someone",
        description: "Puts a notice in a person's inbox in ianua, whatever they may see.",
        outputs: &[("sent", "Whether the notice was sent.")],
    },
    Words {
        operation: CompanyOperation::OfferAccess,
        title: "Offer to ask for access",
        description: "Puts a notice in a person's inbox offering them to ask to join a group. Someone still approves the request.",
        outputs: &[("sent", "Whether the offer was sent.")],
    },
    Words {
        operation: CompanyOperation::RevokeAgentTasks,
        title: "Take back an agent's tasks",
        description: "Takes back every task an agent still holds, and every task passed on from them.",
        outputs: &[("tasks_revoked", "How many tasks were taken back.")],
    },
    Words {
        operation: CompanyOperation::NarrowAgent,
        title: "Narrow what an agent may reach",
        description: "Takes one thing an agent was given, such as calendar:abc123, out of every task it holds.",
        outputs: &[("relations_taken", "How many relations were taken out.")],
    },
    Words {
        operation: CompanyOperation::RemindUntilDecided,
        title: "Remind until decided",
        description: "Reminds a person every few hours, while the run lasts, until an access request is approved, denied, withdrawn or runs out.",
        outputs: &[(
            "ended",
            "How the request ended: approved, denied, cancelled or expired.",
        )],
    },
    Words {
        operation: CompanyOperation::PauseKey,
        title: "Pause an API key",
        description: "Stops an API key signing in, at once, until someone resumes it. Nothing about the key is lost.",
        outputs: &[("key_id", "The key paused.")],
    },
    Words {
        operation: CompanyOperation::ResumeKey,
        title: "Resume an API key",
        description: "Lets a paused API key sign in again, giving its access back.",
        outputs: &[("key_id", "The key resumed.")],
    },
    Words {
        operation: CompanyOperation::SendSignal,
        title: "Send a security signal",
        description: "Tells every connected security tool that takes it something of a person: their risk level, or that their password or a device is compromised.",
        outputs: &[("reported", "The signal sent.")],
    },
    Words {
        operation: CompanyOperation::HideFields,
        title: "Hide sensitive fields",
        description: "Hides the fields of some data the company classifies as sensitive, as the gateway hides them in an app's answer: removed, masked or replaced by a fingerprint, as each rule says.",
        outputs: &[
            ("data", "The data, its sensitive fields hidden."),
            ("hidden", "How many fields were hidden."),
        ],
    },
    Words {
        operation: CompanyOperation::Allow,
        title: "Allow it",
        description: "Lets the change a \"before\" workflow decides go ahead. Every way through such a workflow ends in Allow or Refuse.",
        outputs: &[("verdict", "allow")],
    },
    Words {
        operation: CompanyOperation::Refuse,
        title: "Refuse it",
        description: "Stops the change a \"before\" workflow decides; the person making it is told a company rule refused it.",
        outputs: &[("verdict", "refuse")],
    },
];

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::integration::AccountNeed;

    use super::*;

    /// Every company step is offered, run by the platform as the run's
    /// person, and explained by a guide naming each of its inputs.
    #[test]
    fn every_step_is_offered_and_explained() {
        let company = CompanyIntegration::new(DataClassLevel::Confidential).unwrap();

        assert_eq!(company.operations().len(), CompanyOperation::ALL.len());
        assert_eq!(company.guides().len(), CompanyOperation::ALL.len());
        assert!(
            company
                .operations()
                .iter()
                .all(|spec| spec.account() == AccountNeed::Company)
        );
    }
}
