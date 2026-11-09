//! The people a fan-out may tell about one event: where each one's
//! notifications go, and how they chose to be reached.

use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::reach::ToldAs;
use ianua_domain::types::{Email, OperatorId, OrgUserId, OrganizationId, UserId};
use uuid::Uuid;

use crate::tenancy::ScopedTenant;

/// One person who may be told, where their notifications go, and how they
/// chose to be reached.
pub(in crate::use_cases::notifications) struct Member {
    /// Who they are, as the event names its actor.
    pub(in crate::use_cases::notifications) id: Uuid,
    /// The name a notification credits them by.
    pub(in crate::use_cases::notifications) name: String,
    /// Where their mail goes.
    pub(in crate::use_cases::notifications) email: Email,
    /// Where their notifications are kept and pushed.
    pub(in crate::use_cases::notifications) inbox: Inbox,
    /// How they hear of the event: as they chose for its category, or, for
    /// what happened to their own account, in the app and by mail to a
    /// proved address whatever they chose.
    pub(in crate::use_cases::notifications) channel: NotificationChannel,
    /// Why they are told: they run what it happened to, or it happened to
    /// their own account.
    pub(in crate::use_cases::notifications) told_as: ToldAs,
}

impl Member {
    /// Whether this member is told: not the one who acted, and not having
    /// switched the category off.
    pub(in crate::use_cases::notifications) fn hears(&self, actor: Option<Uuid>) -> bool {
        self.channel.includes_in_app() && actor != Some(self.id)
    }
}

/// Where one person's notifications are kept and pushed.
pub(in crate::use_cases::notifications) enum Inbox {
    /// An operator's.
    Operator(OperatorId),
    /// An organization member's.
    OrgUser(OrganizationId, OrgUserId),
    /// A tenant user's, in their tenant.
    TenantUser(ScopedTenant, UserId),
}

impl Inbox {
    /// The tenant whose mail provider this inbox's owner is mailed through,
    /// or `None` for an operator or organization member, who belong to no
    /// tenant.
    pub(in crate::use_cases::notifications) fn tenant(&self) -> Option<&ScopedTenant> {
        match self {
            Self::TenantUser(tenant, _) => Some(tenant),
            Self::Operator(_) | Self::OrgUser(..) => None,
        }
    }

    /// Whose inbox this is, by their bare id.
    pub(in crate::use_cases::notifications) fn owner(&self) -> &Uuid {
        match self {
            Self::Operator(id) => id.as_uuid(),
            Self::OrgUser(_, id) => id.as_uuid(),
            Self::TenantUser(_, id) => id.as_uuid(),
        }
    }
}

/// The channel `who` chose, out of `chosen`, or in-app when they chose
/// none.
pub(in crate::use_cases::notifications) fn channel_of<K: PartialEq>(
    chosen: &[(K, NotificationChannel)],
    who: &K,
) -> NotificationChannel {
    chosen
        .iter()
        .find(|(owner, _)| owner == who)
        .map(|(_, channel)| *channel)
        .unwrap_or_default()
}

/// The name of the member who acted, if they are among `members`.
pub(in crate::use_cases::notifications) fn name_of(
    members: &[Member],
    actor: Option<Uuid>,
) -> Option<&str> {
    let actor = actor?;
    members
        .iter()
        .find(|member| member.id == actor)
        .map(|member| member.name.as_str())
}
