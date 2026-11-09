//! Send a notice: one person puts a message in another's inbox, by name.
//!
//! Pat's workflow signs Lee out and tells Lee why. The notice is kept in
//! Lee's inbox, shown to Lee whatever Lee may see, and pushed to Lee's
//! open dashboard. The audit trail records that Pat sent it, to Lee, under
//! its title; its message stays in Lee's inbox.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::notifications::notice::{Notice, NoticeMessage, SendNoticeParams};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{EventLabel, Label, NotificationId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::GroupStore;
use crate::ports::identity::UserStore;
use crate::ports::notifications::{Kept, TenantNotificationStore};
use crate::ports::realtime::{NotificationPublisher, NotificationUpdate, RealtimeMessage};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::services::lookup::existing_user;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::notifications::notices::lookup::{Offering, existing_offer};

/// What a notice says, and to whom.
pub struct SendRequest {
    /// Its id: the same each time the same step's call sends it, so a call
    /// made again sends nothing twice.
    pub id: NotificationId,
    /// The person it is for.
    pub recipient: UserId,
    /// What it says in short.
    pub title: Label,
    /// What else it says.
    pub message: NoticeMessage,
    /// What it offers them to ask for.
    pub offering: Offering,
}

/// The ports [`SendUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SendPorts {
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The tenant's people, to find the recipient.
    pub users: Arc<dyn UserStore>,
    /// The tenant's groups, to find one offered.
    pub groups: Arc<dyn GroupStore>,
    /// Tenant users' inboxes.
    pub inboxes: Arc<dyn TenantNotificationStore>,
    /// Pushes the notice to the recipient's open dashboard.
    pub publisher: Arc<dyn NotificationPublisher>,
    /// Keeps the notice and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Puts a notice in a tenant person's inbox.
pub struct SendUseCase {
    ports: SendPorts,
}

impl SendUseCase {
    /// A use case sending through `ports`.
    #[must_use]
    pub fn new(ports: SendPorts) -> Self {
        Self { ports }
    }

    /// Keeps `notice` in its recipient's inbox together with its record:
    /// both or neither, and nothing again for a notice already kept.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        notice: &mut Notice<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let kept = async {
            let saved = self
                .ports
                .inboxes
                .save(tenant, notice.recipient(), notice.notification())
                .await
                .or_internal()?;
            if saved == Kept::AlreadyKept {
                return Ok(());
            }
            auditor
                .dispatch(&notice.take_events(tenant))
                .await
                .or_internal()
        };
        kept_together(self.ports.unit_of_work.as_ref(), kept).await
    }

    /// Pushes `notice` to its recipient's open dashboard. A push that does
    /// not reach is only logged: the notice is kept, and shows when they
    /// next look.
    async fn push(&self, ctx: &CallerContext, notice: &Notice<ResolvedTenant>) {
        let message =
            RealtimeMessage::Notification(NotificationUpdate::from(notice.notification()));
        let pushed = self
            .ports
            .publisher
            .publish_to_tenant_user(&ctx.tenant_id(), notice.recipient(), &message)
            .await;
        if let Err(error) = pushed {
            tracing::warn!(%error, "a notice was kept but not pushed");
        }
    }
}

impl Command for SendUseCase {
    type Caller = CallerContext;
    type Input = SendRequest;
    type Output = Result<(), AppError>;

    /// Sends `request`'s notice to a person of the caller's tenant, for a
    /// caller who may view people, and records
    /// `notifications.notice_sent`, or `notifications.access_offered` for a
    /// notice offering to ask to join a group.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view people.
    /// - `AppError::NotFound` when the tenant has no such person, or no
    ///   such group to offer.
    /// - `AppError::Internal` on persistence or audit failure; nothing is
    ///   kept then.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SendRequest,
    ) -> Result<(), AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Users(UserAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let recipient =
            existing_user(self.ports.users.as_ref(), &tenant, &request.recipient).await?;
        let offer = existing_offer(self.ports.groups.as_ref(), &tenant, request.offering).await?;
        let mut notice = Notice::<ResolvedTenant>::send(SendNoticeParams {
            id: request.id,
            recipient: request.recipient,
            recipient_label: EventLabel::of(recipient.email().as_str()),
            title: request.title,
            message: request.message,
            offer,
        });
        self.keep(&tenant, auditor, &mut notice).await?;
        self.push(ctx, &notice).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupOrigin;
    use ianua_domain::domains::notifications::notification::AboutResource;
    use ianua_domain::types::{GroupId, Text};

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authorization::FakeGroupStore;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::notifications::FakeTenantNotificationStore;
    use crate::test_support::scim::kept_group;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Lee, and the inbox the notice lands in.
    struct World {
        lee: UserId,
        support: GroupId,
        groups: Arc<FakeGroupStore>,
        inboxes: Arc<FakeTenantNotificationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn world() -> World {
        let support = kept_group("Support", GroupOrigin::Dashboard);
        World {
            lee: UserId::new(),
            support: *support.id(),
            groups: Arc::new(FakeGroupStore::holding(test_ctx().tenant_id(), [support])),
            inboxes: Arc::new(FakeTenantNotificationStore::empty()),
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn sending(w: &World, authorities: FakeTenantAuthorities) -> Result<(), AppError> {
        offering(w, authorities, Offering::Nothing)
    }

    fn may_view_people() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Users(UserAction::View)])
    }

    fn offering(
        w: &World,
        authorities: FakeTenantAuthorities,
        offer: Offering,
    ) -> Result<(), AppError> {
        let use_case = SendUseCase::new(SendPorts {
            tenant_authorities: Arc::new(authorities),
            users: Arc::new(FakeUserStore::with_user(w.lee, "lee@acme.com")),
            groups: w.groups.clone(),
            inboxes: w.inboxes.clone(),
            ..SendPorts::fakes()
        });
        block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(w.audit.clone()),
            SendRequest {
                id: NotificationId::new(),
                recipient: w.lee,
                title: Label::new("title", "You were signed out").unwrap(),
                message: NoticeMessage::Says(Text::new("message", "Check your devices.").unwrap()),
                offering: offer,
            },
        ))
    }

    /// Pat tells Lee they were signed out. The notice is in Lee's inbox,
    /// and the trail records it was sent.
    #[test]
    fn a_notice_lands_in_the_recipients_inbox_and_is_recorded() {
        let w = world();

        sending(&w, may_view_people()).unwrap();

        let kept = w.inboxes.notifications.lock().unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0.1, w.lee);
        assert_eq!(
            *w.audit.records.lock().unwrap(),
            ["notifications.notice_sent"]
        );
    }

    /// Pat's workflow offers Lee to ask to join Support. The notice names
    /// the group and is recorded as an offer of access.
    #[test]
    fn an_offer_names_the_group_and_is_recorded_as_one() {
        let w = world();

        offering(&w, may_view_people(), Offering::JoinGroup(w.support)).unwrap();

        let kept = w.inboxes.notifications.lock().unwrap();
        assert_eq!(
            kept[0].1.resource_id(),
            AboutResource::Resource(*w.support.as_uuid())
        );
        assert_eq!(
            *w.audit.records.lock().unwrap(),
            ["notifications.access_offered"]
        );
    }

    /// Offering an unknown group returns not found and saves no notice.
    #[test]
    fn an_offer_of_a_group_the_tenant_lacks_sends_nothing() {
        let w = world();

        let result = offering(&w, may_view_people(), Offering::JoinGroup(GroupId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(w.inboxes.notifications.lock().unwrap().is_empty());
    }

    /// Sending a notice without user viewing rights is forbidden and saves
    /// neither a notice nor an audit event.
    #[test]
    fn a_caller_who_may_not_view_people_sends_nothing() {
        let w = world();

        let result = sending(&w, FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(w.inboxes.notifications.lock().unwrap().is_empty());
        assert!(w.audit.records.lock().unwrap().is_empty());
    }
}
