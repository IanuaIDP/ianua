//! Mark read: marks one notification in the caller's inbox read and
//! publishes an event.

use std::sync::Arc;

use ianua_domain::domains::notifications::reading::InboxRead;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EventLabel, NotificationId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::notifications::{
    OrgNotificationStore, PlatformNotificationStore, TenantNotificationStore,
};
use crate::ports::shared::{AuditLabelResolver, ControlPlaneLabelResolver};
use crate::use_case::Command;
use crate::use_cases::notifications::inbox::reader::{Inbox, NotificationReader, ReaderPorts};

/// Ports needed by the mark read use case.
#[derive(ianua_macros::Fakes)]
pub struct MarkReadPorts {
    /// Platform-tier store.
    pub platform_store: Arc<dyn PlatformNotificationStore>,
    /// Org-tier store.
    pub org_store: Arc<dyn OrgNotificationStore>,
    /// Tenant-tier store.
    pub tenant_store: Arc<dyn TenantNotificationStore>,
    /// Resolves a tenant notification's label captured into the audit payload.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Resolves an operator's or member's notification label captured into
    /// the audit payload.
    pub control_plane_label_resolver: Arc<dyn ControlPlaneLabelResolver>,
    /// Whose inbox the caller reads.
    pub readers: ReaderPorts,
}

/// Clears unread state for one item in the caller's inbox.
pub struct MarkReadUseCase {
    ports: MarkReadPorts,
}

impl MarkReadUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: MarkReadPorts) -> Self {
        Self { ports }
    }

    /// Marks the notification read if it is in `inbox`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the inbox has no such notification; one in
    ///   somebody else's inbox is not admitted to exist.
    /// - `AppError::Internal` on persistence failure.
    async fn ensure_marked_read(
        &self,
        inbox: &Inbox,
        notification_id: &NotificationId,
    ) -> Result<(), AppError> {
        if !self.marked(inbox, notification_id).await? {
            return Err(AppError::NotFound(message!(
                "notifications-notification-not-found",
                "notification not found"
            )));
        }
        Ok(())
    }

    /// Whether `inbox` held the notification, which is now read.
    async fn marked(
        &self,
        inbox: &Inbox,
        notification_id: &NotificationId,
    ) -> Result<bool, AppError> {
        match inbox {
            Inbox::Operator(operator_id) => {
                self.ports
                    .platform_store
                    .mark_read(operator_id, notification_id)
                    .await
            }
            Inbox::Member {
                organization_id,
                org_user_id,
            } => {
                self.ports
                    .org_store
                    .mark_read(organization_id, org_user_id, notification_id)
                    .await
            }
            Inbox::TenantUser {
                tenant, user_id, ..
            } => {
                self.ports
                    .tenant_store
                    .mark_read(tenant, user_id, notification_id)
                    .await
            }
        }
        .or_internal()
    }

    /// The notification's title, falling back to its id when the title
    /// cannot be resolved: a label lookup never fails a mark-read.
    async fn notification_label(
        &self,
        inbox: &Inbox,
        notification_id: &NotificationId,
    ) -> EventLabel {
        let control_plane = &self.ports.control_plane_label_resolver;
        let resolved = match inbox {
            Inbox::Operator(operator_id) => {
                control_plane
                    .platform_notification(operator_id, notification_id)
                    .await
            }
            Inbox::Member {
                organization_id,
                org_user_id,
            } => {
                control_plane
                    .org_notification(organization_id, org_user_id, notification_id)
                    .await
            }
            Inbox::TenantUser { tenant, .. } => {
                self.ports
                    .audit_label_resolver
                    .notification(tenant, notification_id)
                    .await
            }
        };
        label_or_id(resolved, notification_id)
    }
}

impl Command for MarkReadUseCase {
    type Caller = NotificationReader;
    type Input = NotificationId;
    type Output = Result<(), AppError>;

    /// Marks a notification in the caller's own inbox as read and dispatches
    /// `notifications.notification_read`.
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
    /// - `AppError::NotFound` if the notification is not in their inbox.
    /// - `AppError::Internal` on persistence failure, or if the event cannot
    ///   be dispatched.
    async fn execute(
        &self,
        reader: &NotificationReader,
        auditor: &RequestAuditor,
        notification_id: NotificationId,
    ) -> Result<(), AppError> {
        let inbox = self.ports.readers.inbox(reader).await?;
        self.ensure_marked_read(&inbox, &notification_id).await?;
        let label = self.notification_label(&inbox, &notification_id).await;

        auditor
            .dispatch_by(
                &inbox.actor(),
                InboxRead::one(notification_id, label).events(inbox.owner()),
            )
            .await
            .or_internal()
    }
}

/// A resolved title, or the notification's id when it could not be read.
///
/// A label lookup is never allowed to fail a mark-read, so a resolver error and
/// a missing row collapse to the same id fallback, visible in the event.
fn label_or_id(
    resolved: Result<Option<EventLabel>, DomainError>,
    notification_id: &NotificationId,
) -> EventLabel {
    resolved
        .ok()
        .flatten()
        .unwrap_or_else(|| EventLabel::of(&notification_id.to_string()))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::notification::Notification;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::types::{OperatorId, OrgUserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::notifications::{
        FakeOrgNotificationStore, FakePlatformNotificationStore, FakeTenantNotificationStore,
        operator_caller, test_ctx_user, user_registered,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeAuditLabelResolver, FakeEventDispatcher, block_on,
        test_auditor, test_ctx, test_org_caller,
    };

    const READ: &str = "notifications.notification_read";

    fn notification() -> Notification {
        user_registered(NotificationSeverity::Info)
    }

    fn mark(
        use_case: &MarkReadUseCase,
        reader: &NotificationReader,
        id: NotificationId,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(reader, &test_auditor(audit.clone()), id));
        (result, audit)
    }

    fn tenant_inbox_with(
        notification: &Notification,
        resolver: FakeAuditLabelResolver,
    ) -> MarkReadUseCase {
        let store = Arc::new(FakeTenantNotificationStore::empty());
        block_on(store.save(&test_ctx().tenant(), &test_ctx_user(), notification)).unwrap();
        MarkReadUseCase::new(MarkReadPorts {
            tenant_store: store,
            audit_label_resolver: Arc::new(resolver),
            ..MarkReadPorts::fakes()
        })
    }

    fn operator_inbox_with(operator: OperatorId, notification: &Notification) -> MarkReadUseCase {
        let platform = Arc::new(FakePlatformNotificationStore::empty());
        block_on(platform.save(&operator, notification)).unwrap();
        MarkReadUseCase::new(MarkReadPorts {
            platform_store: platform,
            ..MarkReadPorts::fakes()
        })
    }

    /// An operator marks a notification in their inbox read. The record
    /// names it by its title.
    #[test]
    fn an_operator_marking_a_notification_read_records_it_by_title() {
        let operator = OperatorId::new();
        let n = notification();
        let use_case = operator_inbox_with(operator, &n);

        let (result, audit) = mark(
            &use_case,
            &NotificationReader::Operator(operator_caller(operator)),
            n.id(),
        );

        result.unwrap();
        assert_eq!(
            audit.label_of(READ, "notification").as_deref(),
            Some("test platform notification")
        );
    }

    /// An operator marks a notification that is not in their inbox. It is
    /// not found.
    #[test]
    fn a_notification_not_in_the_inbox_is_not_found() {
        let use_case = MarkReadUseCase::new(MarkReadPorts::fakes());

        let (result, _) = mark(
            &use_case,
            &NotificationReader::Operator(operator_caller(OperatorId::new())),
            NotificationId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann marks a notification in her inbox read. The record names it by
    /// its title.
    #[test]
    fn a_tenant_user_marking_a_notification_read_records_it_by_title() {
        let n = notification();
        let use_case = tenant_inbox_with(&n, FakeAuditLabelResolver::new());

        let (result, audit) = mark(&use_case, &NotificationReader::Tenant(test_ctx()), n.id());

        result.unwrap();
        assert_eq!(
            audit.label_of(READ, "notification").as_deref(),
            Some("test notification")
        );
    }

    /// The title cannot be looked up. The notification is still marked
    /// read, and the record names it by its id.
    #[test]
    fn a_tenant_user_marks_read_when_the_title_is_unresolvable() {
        let n = notification();
        let use_case = tenant_inbox_with(&n, FakeAuditLabelResolver::missing());

        let (result, audit) = mark(&use_case, &NotificationReader::Tenant(test_ctx()), n.id());

        result.unwrap();
        assert_eq!(
            audit.label_of(READ, "notification"),
            Some(n.id().to_string())
        );
    }

    /// A member marks a notification in their own inbox read. It no longer
    /// counts as unread, and the record names it by its title.
    #[test]
    fn a_member_marks_their_own_notification_read_and_it_is_recorded() {
        let org = Arc::new(FakeOrgNotificationStore::empty());
        let caller = test_org_caller();
        let n = notification();
        block_on(org.save(&caller.organization_id(), caller.member(), &n)).unwrap();
        let use_case = MarkReadUseCase::new(MarkReadPorts {
            org_store: org.clone(),
            ..MarkReadPorts::fakes()
        });

        let (result, audit) = mark(
            &use_case,
            &NotificationReader::Member(caller.clone()),
            n.id(),
        );

        result.unwrap();
        let unread =
            block_on(org.unread_count(&caller.organization_id(), caller.member())).unwrap();
        assert_eq!(unread, 0);
        assert_eq!(
            audit.label_of(READ, "notification").as_deref(),
            Some("test org notification")
        );
    }

    /// Marking another member's notification read returns not found,
    /// leaves it unread and records no event.
    #[test]
    fn a_member_cannot_mark_someone_elses_notification_read() {
        let org = Arc::new(FakeOrgNotificationStore::empty());
        let caller = test_org_caller();
        let ann = OrgUserId::new();
        let n = notification();
        block_on(org.save(&caller.organization_id(), &ann, &n)).unwrap();
        let use_case = MarkReadUseCase::new(MarkReadPorts {
            org_store: org.clone(),
            ..MarkReadPorts::fakes()
        });

        let (result, audit) = mark(
            &use_case,
            &NotificationReader::Member(caller.clone()),
            n.id(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            block_on(org.unread_count(&caller.organization_id(), &ann)).unwrap(),
            1
        );
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Marking a notification read with a signed-out tenant session returns
    /// an unauthenticated error.
    #[test]
    fn a_signed_out_tenant_user_is_refused() {
        let n = notification();
        let use_case = MarkReadUseCase::new(MarkReadPorts {
            readers: ReaderPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
                ..ReaderPorts::fakes()
            },
            ..MarkReadPorts::fakes()
        });

        let (result, _) = mark(&use_case, &NotificationReader::Tenant(test_ctx()), n.id());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Audit failure is operation failure, here as everywhere else.
    #[test]
    fn marking_read_fails_when_its_audit_record_cannot_be_written() {
        let operator = OperatorId::new();
        let n = notification();
        let use_case = operator_inbox_with(operator, &n);

        let result = block_on(use_case.execute(
            &NotificationReader::Operator(operator_caller(operator)),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            n.id(),
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
