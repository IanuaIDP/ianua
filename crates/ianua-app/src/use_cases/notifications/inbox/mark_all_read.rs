//! Mark all read: marks every notification in the caller's inbox read and
//! publishes an event.

use std::sync::Arc;

use ianua_domain::domains::notifications::reading::InboxRead;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::notifications::{
    OrgNotificationStore, PlatformNotificationStore, TenantNotificationStore,
};
use crate::use_case::Command;
use crate::use_cases::notifications::inbox::reader::{Inbox, NotificationReader, ReaderPorts};

/// Ports needed by the mark all read use case.
#[derive(ianua_macros::Fakes)]
pub struct MarkAllReadPorts {
    /// Platform-tier store.
    pub platform_store: Arc<dyn PlatformNotificationStore>,
    /// Org-tier store.
    pub org_store: Arc<dyn OrgNotificationStore>,
    /// Tenant-tier store.
    pub tenant_store: Arc<dyn TenantNotificationStore>,
    /// Whose inbox the caller reads.
    pub readers: ReaderPorts,
}

/// Clears unread state across the caller's inbox and reports how many changed.
pub struct MarkAllReadUseCase {
    ports: MarkAllReadPorts,
}

impl MarkAllReadUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: MarkAllReadPorts) -> Self {
        Self { ports }
    }

    /// Marks every notification in `inbox` read and returns how many
    /// changed.
    async fn marked_all_read(&self, inbox: &Inbox) -> Result<u64, AppError> {
        match inbox {
            Inbox::Operator(operator_id) => {
                self.ports.platform_store.mark_all_read(operator_id).await
            }
            Inbox::Member {
                organization_id,
                org_user_id,
            } => {
                self.ports
                    .org_store
                    .mark_all_read(organization_id, org_user_id)
                    .await
            }
            Inbox::TenantUser {
                tenant, user_id, ..
            } => self.ports.tenant_store.mark_all_read(tenant, user_id).await,
        }
        .or_internal()
    }
}

impl Command for MarkAllReadUseCase {
    type Caller = NotificationReader;
    type Input = ();
    type Output = Result<u64, AppError>;

    /// Marks all of the caller's own notifications as read, dispatches
    /// `notifications.all_notifications_read`, and returns how many changed.
    ///
    /// The event is published, so read state syncs across the reader's
    /// devices, but kept out of the audit trail: a read receipt is not a
    /// governance action.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not act where they ask.
    /// - `AppError::Internal` on persistence failure, or if the event cannot
    ///   be dispatched.
    async fn execute(
        &self,
        reader: &NotificationReader,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<u64, AppError> {
        let inbox = self.ports.readers.inbox(reader).await?;
        let count = self.marked_all_read(&inbox).await?;

        auditor
            .dispatch_by(&inbox.actor(), InboxRead::all(count).events(inbox.owner()))
            .await
            .or_internal()?;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::types::{OperatorId, OrgUserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::notifications::{
        FakeOrgNotificationStore, FakePlatformNotificationStore, FakeTenantNotificationStore,
        operator_caller, test_ctx_user, user_registered,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
        test_org_caller,
    };

    const ALL_READ: &str = "notifications.all_notifications_read";

    fn clear(
        use_case: &MarkAllReadUseCase,
        reader: &NotificationReader,
    ) -> (Result<u64, AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(reader, &test_auditor(audit.clone()), ()));
        (result, audit)
    }

    fn operator_inbox(operator: OperatorId, unread: usize) -> MarkAllReadUseCase {
        let platform = Arc::new(FakePlatformNotificationStore::empty());
        for _ in 0..unread {
            block_on(platform.save(&operator, &user_registered(NotificationSeverity::Info)))
                .unwrap();
        }
        MarkAllReadUseCase::new(MarkAllReadPorts {
            platform_store: platform,
            ..MarkAllReadPorts::fakes()
        })
    }

    /// An operator has two unread notifications and clears them. Two are
    /// marked.
    #[test]
    fn marking_all_read_returns_how_many_changed() {
        let operator = OperatorId::new();

        let (result, _) = clear(
            &operator_inbox(operator, 2),
            &NotificationReader::Operator(operator_caller(operator)),
        );

        assert_eq!(result.unwrap(), 2);
    }

    /// An operator with an empty inbox clears nothing.
    #[test]
    fn an_empty_inbox_marks_none() {
        let operator = OperatorId::new();

        let (result, _) = clear(
            &operator_inbox(operator, 0),
            &NotificationReader::Operator(operator_caller(operator)),
        );

        assert_eq!(result.unwrap(), 0);
    }

    /// A member clears their two notifications. A colleague's stays unread,
    /// and the clearing is recorded.
    #[test]
    fn a_member_clears_only_their_own_notifications_and_it_is_recorded() {
        let org = Arc::new(FakeOrgNotificationStore::empty());
        let caller = test_org_caller();
        let colleague = OrgUserId::new();
        let organization = caller.organization_id();
        for _ in 0..2 {
            block_on(org.save(
                &organization,
                caller.member(),
                &user_registered(NotificationSeverity::Info),
            ))
            .unwrap();
        }
        block_on(org.save(
            &organization,
            &colleague,
            &user_registered(NotificationSeverity::Info),
        ))
        .unwrap();
        let use_case = MarkAllReadUseCase::new(MarkAllReadPorts {
            org_store: org.clone(),
            ..MarkAllReadPorts::fakes()
        });

        let (result, audit) = clear(&use_case, &NotificationReader::Member(caller));

        assert_eq!(result.unwrap(), 2);
        assert_eq!(
            block_on(org.unread_count(&organization, &colleague)).unwrap(),
            1
        );
        assert_eq!(audit.records.lock().unwrap().as_slice(), [ALL_READ]);
    }

    /// Ann clears her three notifications and is told how many.
    #[test]
    fn a_tenant_user_clears_their_notifications_and_gets_the_count() {
        let store = Arc::new(FakeTenantNotificationStore::empty());
        for _ in 0..3 {
            block_on(store.save(
                &test_ctx().tenant(),
                &test_ctx_user(),
                &user_registered(NotificationSeverity::Info),
            ))
            .unwrap();
        }
        let use_case = MarkAllReadUseCase::new(MarkAllReadPorts {
            tenant_store: store,
            ..MarkAllReadPorts::fakes()
        });

        let (result, audit) = clear(&use_case, &NotificationReader::Tenant(test_ctx()));

        assert_eq!(result.unwrap(), 3);
        assert_eq!(audit.records.lock().unwrap().as_slice(), [ALL_READ]);
    }

    /// Marking all notifications read with a signed-out tenant session
    /// returns an unauthenticated error.
    #[test]
    fn a_signed_out_tenant_user_is_refused() {
        let use_case = MarkAllReadUseCase::new(MarkAllReadPorts {
            readers: ReaderPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
                ..ReaderPorts::fakes()
            },
            ..MarkAllReadPorts::fakes()
        });

        let (result, _) = clear(&use_case, &NotificationReader::Tenant(test_ctx()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Audit failure is operation failure, here as everywhere else.
    #[test]
    fn marking_all_read_fails_when_its_audit_record_cannot_be_written() {
        let operator = OperatorId::new();
        let use_case = operator_inbox(operator, 1);

        let result = block_on(use_case.execute(
            &NotificationReader::Operator(operator_caller(operator)),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            (),
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
