//! List notifications: the notifications in the caller's own inbox.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::notifications::notification::Notification;
use ianua_domain::types::UserId;

use crate::error::AppError;
use crate::listing::{Listing, Page, PageRequest, SortOrder};
use crate::ports::notifications::{
    NotificationSortField, OrgNotificationStore, PlatformNotificationStore, ReadFilter,
    TenantNotificationFilter, TenantNotificationStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::notifications::inbox::reader::{Inbox, NotificationReader, ReaderPorts};

/// Ports needed by the list notifications use case.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Platform-tier store.
    pub platform_store: Arc<dyn PlatformNotificationStore>,
    /// Org-tier store.
    pub org_store: Arc<dyn OrgNotificationStore>,
    /// Tenant-tier store.
    pub tenant_store: Arc<dyn TenantNotificationStore>,
    /// Whose inbox the caller reads.
    pub readers: ReaderPorts,
}

/// Reads the caller's inbox at the platform, organization or tenant level.
pub struct ListUseCase {
    ports: ListPorts,
}

/// Which notifications to list, in what order, and which page.
pub struct ListRequest {
    /// Read and unread, or unread only.
    pub reads: ReadFilter,
    /// The order to return them in.
    pub sort: SortOrder<NotificationSortField>,
    /// Which page of the ordered notifications to return.
    pub page: PageRequest,
}

/// The slice of an inbox one listing reads.
type InboxListing<'a> = Listing<'a, ReadFilter, NotificationSortField>;

/// One page of notifications.
type Listed = Page<Notification>;

impl ListUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }

    async fn listed_for(
        &self,
        inbox: &Inbox,
        listing: &InboxListing<'_>,
    ) -> Result<Listed, AppError> {
        match inbox {
            Inbox::Operator(operator_id) => self
                .ports
                .platform_store
                .list_for_operator(operator_id, listing.filter, listing.sort, listing.page)
                .await
                .map_err(AppError::from_domain),
            Inbox::Member {
                organization_id,
                org_user_id,
            } => self
                .ports
                .org_store
                .list_for_user(organization_id, org_user_id, *listing)
                .await
                .map_err(AppError::from_domain),
            Inbox::TenantUser {
                tenant,
                user_id,
                visible,
            } => {
                self.listed_for_tenant_user(tenant, user_id, visible, listing)
                    .await
            }
        }
    }

    /// A tenant user's notifications, narrowed to the ones `visible` lets
    /// them see now.
    async fn listed_for_tenant_user(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
        visible: &[SystemPermission],
        listing: &InboxListing<'_>,
    ) -> Result<Listed, AppError> {
        let filter = TenantNotificationFilter {
            permissions: visible,
            reads: listing.filter,
        };
        let shown = Listing {
            filter: &filter,
            sort: listing.sort,
            page: listing.page,
        };
        self.ports
            .tenant_store
            .list_for_user(tenant, user_id, shown)
            .await
            .map_err(AppError::from_domain)
    }
}

impl Query for ListUseCase {
    type Caller = NotificationReader;
    type Input = ListRequest;
    type Output = Result<Page<Notification>, AppError>;

    /// Lists the caller's own notifications with ordering and pagination.
    ///
    /// A tenant user sees only the notifications what they hold now lets
    /// them see.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not act where they ask.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        reader: &NotificationReader,
        request: ListRequest,
    ) -> Result<Page<Notification>, AppError> {
        let inbox = self.ports.readers.inbox(reader).await?;
        let listing = InboxListing {
            filter: request.reads,
            sort: &request.sort,
            page: &request.page,
        };
        self.listed_for(&inbox, &listing).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::UserAction;
    use ianua_domain::domains::notifications::reach::NotificationReach;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::types::OperatorId;

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeOrgActors, FakeTenantAuthorities, Refusal};
    use crate::test_support::notifications::{
        FakeOrgNotificationStore, FakePlatformNotificationStore, FakeTenantNotificationStore,
        key_rotated, operator_caller, own_account_locked, someone_elses_account_locked,
        test_ctx_user, user_registered,
    };
    use crate::test_support::{block_on, test_ctx, test_org_caller};

    fn request(sort: SortOrder<NotificationSortField>) -> ListRequest {
        ListRequest {
            reads: ReadFilter::All,
            sort,
            page: PageRequest::default(),
        }
    }

    fn list(
        use_case: &ListUseCase,
        reader: &NotificationReader,
    ) -> Result<Page<Notification>, AppError> {
        block_on(use_case.execute(reader, request(SortOrder::default())))
    }

    fn tenant_inbox_holding(
        held: &[SystemPermission],
    ) -> (ListUseCase, Arc<FakeTenantNotificationStore>) {
        let store = Arc::new(FakeTenantNotificationStore::empty());
        let use_case = ListUseCase::new(ListPorts {
            tenant_store: store.clone(),
            readers: ReaderPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
                ..ReaderPorts::fakes()
            },
            ..ListPorts::fakes()
        });
        (use_case, store)
    }

    /// An operator with nothing in their inbox lists nothing.
    #[test]
    fn an_empty_inbox_lists_nothing() {
        let use_case = ListUseCase::new(ListPorts::fakes());

        let page = list(
            &use_case,
            &NotificationReader::Operator(operator_caller(OperatorId::new())),
        )
        .unwrap();

        assert!(page.is_empty());
    }

    /// Two notifications wait for an operator. They list both.
    #[test]
    fn an_operator_lists_their_notifications() {
        let platform = Arc::new(FakePlatformNotificationStore::empty());
        let operator = OperatorId::new();
        for _ in 0..2 {
            block_on(platform.save(&operator, &user_registered(NotificationSeverity::Info)))
                .unwrap();
        }
        let use_case = ListUseCase::new(ListPorts {
            platform_store: platform,
            ..ListPorts::fakes()
        });

        let page = list(
            &use_case,
            &NotificationReader::Operator(operator_caller(operator)),
        )
        .unwrap();

        assert_eq!(page.items.len(), 2);
    }

    /// An operator lists their notifications by severity, by urgency: info,
    /// then warning, then critical, never by the alphabet.
    #[test]
    fn an_operator_orders_by_severity() {
        let platform = Arc::new(FakePlatformNotificationStore::empty());
        let operator = OperatorId::new();
        for severity in [
            NotificationSeverity::Warning,
            NotificationSeverity::Critical,
            NotificationSeverity::Info,
        ] {
            block_on(platform.save(&operator, &user_registered(severity))).unwrap();
        }
        let use_case = ListUseCase::new(ListPorts {
            platform_store: platform,
            ..ListPorts::fakes()
        });
        let sort = SortOrder::single(Sort::ascending(NotificationSortField::Severity));

        let page = block_on(use_case.execute(
            &NotificationReader::Operator(operator_caller(operator)),
            request(sort),
        ))
        .unwrap();

        let severities: Vec<&str> = page.items.iter().map(|n| n.severity().as_str()).collect();
        assert_eq!(severities, ["info", "warning", "critical"]);
    }

    /// Ann may view users but not keys. Her inbox holds a new user and a
    /// rotated key. She sees only the new user.
    #[test]
    fn a_tenant_user_sees_only_what_they_may_see_now() {
        let (use_case, store) = tenant_inbox_holding(&[SystemPermission::Users(UserAction::View)]);
        let ann = test_ctx_user();
        for notification in [user_registered(NotificationSeverity::Info), key_rotated()] {
            block_on(store.save(&test_ctx().tenant(), &ann, &notification)).unwrap();
        }

        let page = list(&use_case, &NotificationReader::Tenant(test_ctx())).unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(
            page.items[0].event_type(),
            user_registered(NotificationSeverity::Info).event_type()
        );
    }

    /// Carol holds no right at all. An admin locked her out, and once she
    /// is let back in, her feed shows that her own account was locked. A
    /// notice of another account's lock, kept from when she ran users, and
    /// a new user stay hidden: she sees nothing else in that category.
    #[test]
    fn a_plain_user_sees_what_happened_to_their_own_account_and_nothing_else() {
        let (use_case, store) = tenant_inbox_holding(&[]);
        let carol = test_ctx_user();
        for notification in [
            own_account_locked(),
            someone_elses_account_locked(),
            user_registered(NotificationSeverity::Info),
        ] {
            block_on(store.save(&test_ctx().tenant(), &carol, &notification)).unwrap();
        }

        let page = list(&use_case, &NotificationReader::Tenant(test_ctx())).unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].reach(), NotificationReach::OwnAccount);
    }

    /// A member of Acme lists the notifications in their own inbox.
    #[test]
    fn a_member_lists_their_own_notifications() {
        let org = Arc::new(FakeOrgNotificationStore::empty());
        let caller = test_org_caller();
        block_on(org.save(
            &caller.organization_id(),
            caller.member(),
            &user_registered(NotificationSeverity::Info),
        ))
        .unwrap();
        let use_case = ListUseCase::new(ListPorts {
            org_store: org,
            ..ListPorts::fakes()
        });

        let page = list(&use_case, &NotificationReader::Member(caller)).unwrap();

        assert_eq!(page.items.len(), 1);
    }

    /// Listing notifications with a signed-out tenant session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_tenant_user_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            readers: ReaderPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
                ..ReaderPorts::fakes()
            },
            ..ListPorts::fakes()
        });

        let result = list(&use_case, &NotificationReader::Tenant(test_ctx()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Listing a member's notifications returns forbidden when organization
    /// authority refuses the caller.
    #[test]
    fn a_member_the_organization_turns_away_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            readers: ReaderPorts {
                org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
                ..ReaderPorts::fakes()
            },
            ..ListPorts::fakes()
        });

        let result = list(&use_case, &NotificationReader::Member(test_org_caller()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
