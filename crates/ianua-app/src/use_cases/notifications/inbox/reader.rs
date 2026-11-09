//! Whose inbox a notification operation acts on, worked out from who calls.
//!
//! A request never names the inbox it reads. The caller's session or key is
//! checked by `acting`, and the inbox is theirs. A tenant user's inbox also
//! carries what they may see now, so a notification about keys reaches only
//! someone who may still view keys.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::notifications::reading::InboxOwner;
use ianua_domain::message;
use ianua_domain::types::{ActorRef, HumanAccount, OperatorId, OrgUserId, OrganizationId, UserId};

use crate::acting::{OperatorAuthorities, OrgActors, TenantAuthorities};
use crate::context::{CallerContext, OperatorCaller, OrgCaller};
use crate::error::AppError;
use crate::tenancy::ScopedTenant;

/// Who reads their notifications, on one of the three tiers.
pub enum NotificationReader {
    /// A platform operator.
    Operator(OperatorCaller),
    /// A member of an organization.
    Member(OrgCaller),
    /// A user acting in a tenant.
    Tenant(CallerContext),
}

/// The inbox a reader reads, once who they are was checked.
pub(crate) enum Inbox {
    /// A platform operator's.
    Operator(OperatorId),
    /// A member's, in their organization.
    Member {
        /// The organization the member belongs to.
        organization_id: OrganizationId,
        /// The member.
        org_user_id: OrgUserId,
    },
    /// A tenant user's.
    TenantUser {
        /// The tenant the user belongs to.
        tenant: ScopedTenant,
        /// The account whose notices are being read.
        user_id: UserId,
        /// Every permission they hold now, each wider one with all it
        /// covers, so a notification shows only to someone who may see it.
        visible: Vec<SystemPermission>,
    },
}

impl Inbox {
    /// The reader, as the actor of what they do to their own inbox.
    pub(crate) fn actor(&self) -> ActorRef {
        match self {
            Self::Operator(id) => ActorRef::Operator(*id),
            Self::Member { org_user_id, .. } => ActorRef::OrgUser(*org_user_id),
            Self::TenantUser { user_id, .. } => ActorRef::User(*user_id),
        }
    }

    /// Whose inbox it is, which decides whose trail records what is done
    /// to it.
    pub(crate) fn owner(&self) -> InboxOwner {
        match self {
            Self::Operator(_) => InboxOwner::Operator,
            Self::Member {
                organization_id, ..
            } => InboxOwner::OrgMember(*organization_id),
            Self::TenantUser { tenant, .. } => InboxOwner::TenantUser(**tenant),
        }
    }
}

/// Who may be asked which inbox a reader reads.
#[derive(Clone, ianua_macros::Fakes)]
pub struct ReaderPorts {
    /// What a tenant caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

impl ReaderPorts {
    /// The inbox `reader` reads, once their session or key still counts.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session or key no longer
    ///   counts.
    /// - `AppError::Forbidden` when the caller may not act where they ask,
    ///   or is an organization member acting in a tenant, whose
    ///   notifications are in the organization.
    /// - `AppError::Internal` when a store fails.
    pub(crate) async fn inbox(&self, reader: &NotificationReader) -> Result<Inbox, AppError> {
        match reader {
            NotificationReader::Operator(caller) => {
                let authority = self.operator_authorities.authority(caller).await?;
                Ok(Inbox::Operator(*authority.operator()))
            }
            NotificationReader::Member(caller) => {
                let (organization, actor) = self.org_actors.actor(caller).await?;
                actor.control()?;
                Ok(Inbox::Member {
                    organization_id: *organization.id(),
                    org_user_id: *actor.member().id(),
                })
            }
            NotificationReader::Tenant(caller) => {
                let authority = self.tenant_authorities.authority(caller).await?;
                tenant_inbox(caller, &authority)
            }
        }
    }
}

/// The tenant user's inbox `authority` reads, with what it may see now.
fn tenant_inbox(caller: &CallerContext, authority: &TenantAuthority) -> Result<Inbox, AppError> {
    let HumanAccount::User(user_id) = authority.who().account() else {
        return Err(AppError::Forbidden(message!(
            "notifications-an-organization-member-reads-their-notifications",
            "an organization member reads their notifications in the organization"
        )));
    };
    let visible = SystemPermission::ALL_VARIANTS
        .iter()
        .copied()
        .filter(|permission| authority.holds(*permission))
        .collect();
    Ok(Inbox::TenantUser {
        tenant: caller.tenant(),
        user_id,
        visible,
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::UserAction;
    use ianua_domain::types::KeyPrefix;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, FakeTenantAuthorities, Refusal};
    use crate::test_support::{block_on, test_ctx};

    /// Ann may manage users. Her inbox shows what every user permission
    /// covers, viewing users among them, and nothing about keys.
    #[test]
    fn a_tenant_inbox_shows_what_the_reader_holds_now() {
        let ports = ReaderPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::ManageUsers,
            ])),
            ..ReaderPorts::fakes()
        };

        let inbox = block_on(ports.inbox(&NotificationReader::Tenant(test_ctx()))).unwrap();

        assert!(matches!(
            &inbox,
            Inbox::TenantUser { visible, .. }
                if visible.contains(&SystemPermission::Users(UserAction::View))
                    && !visible.contains(&SystemPermission::ManageApiKeys)
        ));
    }

    /// Resolving an operator's inbox after authentication fails returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_operator_reads_no_inbox() {
        let ports = ReaderPorts {
            operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(Refusal::SignedOut)),
            ..ReaderPorts::fakes()
        };
        let caller = OperatorCaller::new(OperatorId::new(), KeyPrefix::new("op_live_abc").unwrap());

        let result = block_on(ports.inbox(&NotificationReader::Operator(caller)));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
