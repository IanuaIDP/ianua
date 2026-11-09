//! Unread count: how many notifications in the caller's inbox wait unread.

use std::sync::Arc;

use crate::error::{AppError, OrInternal};
use crate::ports::notifications::{
    OrgNotificationStore, PlatformNotificationStore, TenantNotificationStore,
};
use crate::use_case::Query;
use crate::use_cases::notifications::inbox::reader::{Inbox, NotificationReader, ReaderPorts};

/// Ports needed by the unread count use case.
#[derive(ianua_macros::Fakes)]
pub struct UnreadCountPorts {
    /// Platform-tier store.
    pub platform_store: Arc<dyn PlatformNotificationStore>,
    /// Org-tier store.
    pub org_store: Arc<dyn OrgNotificationStore>,
    /// Tenant-tier store.
    pub tenant_store: Arc<dyn TenantNotificationStore>,
    /// Whose inbox the caller reads.
    pub readers: ReaderPorts,
}

/// Counts unread inbox items the caller is allowed to see.
pub struct UnreadCountUseCase {
    ports: UnreadCountPorts,
}

impl UnreadCountUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: UnreadCountPorts) -> Self {
        Self { ports }
    }

    async fn counted(&self, inbox: &Inbox) -> Result<u64, AppError> {
        match inbox {
            Inbox::Operator(operator_id) => {
                self.ports.platform_store.unread_count(operator_id).await
            }
            Inbox::Member {
                organization_id,
                org_user_id,
            } => {
                self.ports
                    .org_store
                    .unread_count(organization_id, org_user_id)
                    .await
            }
            Inbox::TenantUser {
                tenant,
                user_id,
                visible,
            } => {
                self.ports
                    .tenant_store
                    .unread_count(tenant, user_id, visible)
                    .await
            }
        }
        .or_internal()
    }
}

impl Query for UnreadCountUseCase {
    type Caller = NotificationReader;
    type Input = ();
    type Output = Result<u64, AppError>;

    /// How many of the caller's own notifications are unread. A tenant user
    /// counts only those what they hold now lets them see.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not act where they ask.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, reader: &NotificationReader, (): ()) -> Result<u64, AppError> {
        let inbox = self.ports.readers.inbox(reader).await?;
        self.counted(&inbox).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::types::{OperatorId, OrgUserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::notifications::{
        FakeOrgNotificationStore, FakePlatformNotificationStore, FakeTenantNotificationStore,
        key_rotated, operator_caller, test_ctx_user, user_registered,
    };
    use crate::test_support::{block_on, test_ctx, test_org_caller};

    /// An operator with an empty inbox has nothing unread.
    #[test]
    fn an_empty_inbox_counts_zero() {
        let use_case = UnreadCountUseCase::new(UnreadCountPorts::fakes());

        let count = block_on(use_case.execute(
            &NotificationReader::Operator(operator_caller(OperatorId::new())),
            (),
        ))
        .unwrap();

        assert_eq!(count, 0);
    }

    /// An operator has two notifications and read one. One counts.
    #[test]
    fn only_unread_notifications_count() {
        let platform = Arc::new(FakePlatformNotificationStore::empty());
        let operator = OperatorId::new();
        let read = user_registered(NotificationSeverity::Info);
        block_on(platform.save(&operator, &read)).unwrap();
        block_on(platform.save(&operator, &user_registered(NotificationSeverity::Info))).unwrap();
        block_on(platform.mark_read(&operator, &read.id())).unwrap();
        let use_case = UnreadCountUseCase::new(UnreadCountPorts {
            platform_store: platform,
            ..UnreadCountPorts::fakes()
        });

        let count = block_on(
            use_case.execute(&NotificationReader::Operator(operator_caller(operator)), ()),
        )
        .unwrap();

        assert_eq!(count, 1);
    }

    /// When two organization members each have one unread notification,
    /// the caller's count includes only their own.
    #[test]
    fn a_member_counts_only_their_own_notifications() {
        let org = Arc::new(FakeOrgNotificationStore::empty());
        let caller = test_org_caller();
        let notification = user_registered(NotificationSeverity::Info);
        block_on(org.save(&caller.organization_id(), caller.member(), &notification)).unwrap();
        block_on(org.save(&caller.organization_id(), &OrgUserId::new(), &notification)).unwrap();
        let use_case = UnreadCountUseCase::new(UnreadCountPorts {
            org_store: org,
            ..UnreadCountPorts::fakes()
        });

        let count = block_on(use_case.execute(&NotificationReader::Member(caller), ())).unwrap();

        assert_eq!(count, 1);
    }

    /// Ann may view users but not keys. A new user and a rotated key wait
    /// unread. Only the new user counts.
    #[test]
    fn a_tenant_user_counts_only_what_they_may_see_now() {
        let store = Arc::new(FakeTenantNotificationStore::empty());
        let ann = test_ctx_user();
        for notification in [user_registered(NotificationSeverity::Info), key_rotated()] {
            block_on(store.save(&test_ctx().tenant(), &ann, &notification)).unwrap();
        }
        let use_case = UnreadCountUseCase::new(UnreadCountPorts {
            tenant_store: store,
            readers: ReaderPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                    SystemPermission::Users(UserAction::View),
                ])),
                ..ReaderPorts::fakes()
            },
            ..UnreadCountPorts::fakes()
        });

        let count =
            block_on(use_case.execute(&NotificationReader::Tenant(test_ctx()), ())).unwrap();

        assert_eq!(count, 1);
    }

    /// Counting unread notifications with a signed-out tenant session returns
    /// an unauthenticated error.
    #[test]
    fn a_signed_out_tenant_user_is_refused() {
        let use_case = UnreadCountUseCase::new(UnreadCountPorts {
            readers: ReaderPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
                ..ReaderPorts::fakes()
            },
            ..UnreadCountPorts::fakes()
        });

        let result = block_on(use_case.execute(&NotificationReader::Tenant(test_ctx()), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
