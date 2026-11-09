//! Fan out notifications: tell the people who run a plane what happened on
//! it, once the event is recorded.
//!
//! The event pipeline runs this after the audit record is written. Each
//! person is reached through the channel they chose for the notification's
//! category: in the app, in the app and by mail, or not at all. Who is told
//! on each plane is worked out beside this, in `people`.
//!
//! Mail goes through the mailer, like every other templated mail, as an
//! activity notice: queued, sent through the tenant's own mail provider for
//! a tenant user once a test send through it worked, and through the
//! platform's otherwise. The organization's own destinations, a Slack or
//! Teams channel or a webhook, each get a queued post when their filter
//! covers it, so a slow one holds up neither this nor the others.
//!
//! Notifications are an activity feed, not a delivery promise: a recipient
//! or destination that cannot be reached is skipped and logged, and the
//! others still get theirs.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::notifications::destination::NotificationDestination;
use ianua_domain::domains::notifications::notification::Notification;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{AuditRecordId, OrganizationId, TenantId, Text};
use uuid::Uuid;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::ports::notifications::{
    AlertThrottle, Kept, MemberPreferenceStore, NotificationDestinationStore,
    NotificationPreferenceStore, OperatorPreferenceStore, OrgNotificationStore,
    PlatformNotificationStore, TenantNotificationStore,
};
use crate::ports::operator::OperatorStore;
use crate::ports::organization::{OrgUserStore, OrganizationStore, TenantMemberRoster};
use crate::ports::realtime::{
    NotificationPublisher, NotificationUpdate, PLATFORM_DASHBOARD_SUBJECT, RealtimeMessage,
    org_dashboard_subject,
};
use crate::ports::scheduling::JobQueue;
use crate::ports::shared::Mailer;
use crate::ports::tenant::TenantStore;
use crate::ports::workflows::WorkflowExecutionStore;
use crate::use_case::Command;
use crate::use_cases::notifications::delivery::audience::Audience;
use crate::use_cases::notifications::delivery::job::{DestinationPost, PostedNotification};
use crate::use_cases::notifications::delivery::notice::{Notice, Occurrences};
use crate::use_cases::notifications::delivery::recipients::{Inbox, Member, name_of};
use crate::use_cases::notifications::delivery::render::{Credit, NotificationText};

/// The ports [`FanOutUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct FanOutPorts {
    /// Where notices are kept and pushed live.
    pub inboxes: InboxPorts,
    /// How notices reach people outside the dashboard.
    pub outward: DeliveryPorts,
    /// What each kind of person chose to be told.
    pub preferences: PreferencePorts,
    /// Who could be told, and what they hold.
    pub audience: AudiencePorts,
    /// The tenants, named in what the management plane is told and whose
    /// organization's destinations hear of them.
    pub tenants: Arc<dyn TenantStore>,
}

/// Where notices are kept and pushed live.
#[derive(ianua_macros::Fakes)]
pub struct InboxPorts {
    /// Operators' notifications.
    pub platform_store: Arc<dyn PlatformNotificationStore>,
    /// Org users' notifications.
    pub org_store: Arc<dyn OrgNotificationStore>,
    /// Tenant users' notifications.
    pub tenant_store: Arc<dyn TenantNotificationStore>,
    /// Pushes each notification to its recipient's open dashboard.
    pub publisher: Arc<dyn NotificationPublisher>,
}

/// How notices reach people outside the dashboard.
#[derive(ianua_macros::Fakes)]
pub struct DeliveryPorts {
    /// Mails a notification, as an activity notice, to whoever chose to
    /// have it by mail.
    pub mailer: Arc<dyn Mailer>,
    /// The organization's destinations outside the app.
    pub destinations: Arc<dyn NotificationDestinationStore>,
    /// Where each destination's post is queued.
    pub jobs: Arc<dyn JobQueue>,
    /// Holds back repeats of a security alert to one a window.
    pub alert_throttle: Arc<dyn AlertThrottle>,
}

/// What each kind of person chose to be told.
#[derive(ianua_macros::Fakes)]
pub struct PreferencePorts {
    /// The channels tenant users chose.
    pub preference_store: Arc<dyn NotificationPreferenceStore>,
    /// The channels organization members chose.
    pub member_preferences: Arc<dyn MemberPreferenceStore>,
    /// The channels operators chose.
    pub operator_preferences: Arc<dyn OperatorPreferenceStore>,
}

/// Who could be told, and what they hold.
#[derive(ianua_macros::Fakes)]
pub struct AudiencePorts {
    /// The operators, told about platform events.
    pub operator_store: Arc<dyn OperatorStore>,
    /// An organization's users, told about its events.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// A tenant's users, read for the administrators and the person an
    /// event is about.
    pub user_store: Arc<dyn UserStore>,
    /// Who administers a tenant, and what each person told may see.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Organizations, for which of their members reach a tenant.
    pub organizations: Arc<dyn OrganizationStore>,
    /// The organization's members who might reach a tenant.
    pub member_roster: Arc<dyn TenantMemberRoster>,
    /// Workflow runs, read for the authors a failed run's version asked to
    /// tell.
    pub executions: Arc<dyn WorkflowExecutionStore>,
}

/// An event once recorded, with the context it was recorded in.
pub struct RecordedEvent {
    /// The audit record it was kept as. Events reach the fan-out at least
    /// once, so every notification about it is named after this record and
    /// its recipient, and a second run tells no one twice.
    pub record_id: AuditRecordId,
    /// The audited change from which recipient notices are derived.
    pub event: DomainEvent,
    /// Who made it, and where.
    pub context: AuditContext,
}

/// Tells the people who run a plane about an event on it.
///
/// No one calls it: the event pipeline runs it, so its caller is `()`.
pub struct FanOutUseCase {
    pub(in crate::use_cases::notifications::delivery) ports: FanOutPorts,
    pub(in crate::use_cases::notifications::delivery) max_recipients: PageRequest,
}

impl FanOutUseCase {
    /// A fan-out over `ports` telling at most `max_recipients` people of
    /// each kind about one event. Past the cap the rest are not told:
    /// notifications must never hold up the event pipeline.
    #[must_use]
    pub fn new(ports: FanOutPorts, max_recipients: u32) -> Self {
        Self {
            ports,
            max_recipients: PageRequest::first(Limit::internal(max_recipients)),
        }
    }

    /// The name of the tenant an organization's users are told about, or
    /// `None` when there is none. A lookup that fails drops the name, never
    /// the notification.
    async fn tenant_name(&self, audience: &Audience) -> Option<String> {
        let Audience::Organization {
            about_tenant: Some(tenant_id),
            ..
        } = audience
        else {
            return None;
        };
        match self.ports.tenants.find_by_id(tenant_id).await {
            Ok(tenant) => tenant.map(|tenant| tenant.display_name().as_str().to_owned()),
            Err(error) => {
                tracing::warn!(%error, %tenant_id, "notification fan-out: tenant name not read");
                None
            }
        }
    }

    /// Keeps, pushes and, where chosen, mails `text` for every member who
    /// hears it and was not told already, and counts both.
    ///
    /// A member whose notification an earlier run kept is not pushed or
    /// mailed again. A run that stopped between keeping and mailing leaves
    /// that mail unsent: notifications are a feed, and telling once matters
    /// more than the mail.
    async fn deliver(
        &self,
        members: &[Member],
        actor: Option<Uuid>,
        text: &NotificationText,
    ) -> Told {
        let mut told = Told::default();
        for member in members.iter().filter(|member| member.hears(actor)) {
            let notification = text.notification(member.inbox.owner(), member.told_as);
            match self.keep(&member.inbox, &notification).await {
                Ok(Kept::New) => {}
                Ok(Kept::AlreadyKept) => {
                    told.before = told.before.saturating_add(1);
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "notification fan-out: notification not kept");
                    continue;
                }
            }
            self.push(&member.inbox, &notification).await;
            self.mail(member, &notification).await;
            told.now = told.now.saturating_add(1);
        }
        told
    }

    /// Keeps `notification` in `inbox`.
    async fn keep(&self, inbox: &Inbox, notification: &Notification) -> Result<Kept, DomainError> {
        match inbox {
            Inbox::Operator(id) => {
                self.ports
                    .inboxes
                    .platform_store
                    .save(id, notification)
                    .await
            }
            Inbox::OrgUser(organization_id, id) => {
                self.ports
                    .inboxes
                    .org_store
                    .save(organization_id, id, notification)
                    .await
            }
            Inbox::TenantUser(tenant, id) => {
                self.ports
                    .inboxes
                    .tenant_store
                    .save(tenant, id, notification)
                    .await
            }
        }
    }

    /// Pushes `notification` to the dashboards `inbox`'s owner has open. A
    /// failed push is logged: the notification is kept and shows on the
    /// next load.
    async fn push(&self, inbox: &Inbox, notification: &Notification) {
        let message = live(notification);
        let pushed = match inbox {
            Inbox::Operator(id) => {
                self.ports
                    .inboxes
                    .publisher
                    .publish_to_operator(id, &message)
                    .await
            }
            Inbox::OrgUser(organization_id, id) => {
                self.ports
                    .inboxes
                    .publisher
                    .publish_to_org_user(organization_id, id, &message)
                    .await
            }
            Inbox::TenantUser(tenant, id) => {
                self.ports
                    .inboxes
                    .publisher
                    .publish_to_tenant_user(tenant, id, &message)
                    .await
            }
        };
        if let Err(error) = pushed {
            tracing::warn!(%error, "notification fan-out: live push failed");
        }
    }

    /// Hands `notification` to the mailer for `member` when they chose to
    /// have its category by mail: in their tenant's mail for a tenant user,
    /// the platform's for anyone else. A mail the mailer refuses is logged:
    /// the notification is kept in the app.
    async fn mail(&self, member: &Member, notification: &Notification) {
        if !member.channel.includes_email() {
            return;
        }
        if let Err(error) = self
            .ports
            .outward
            .mailer
            .send(
                &member.email,
                member.inbox.tenant().copied(),
                EmailTemplateType::ActivityNotice,
                &notice_of(notification),
            )
            .await
        {
            tracing::warn!(%error, "notification fan-out: mail not handed over");
        }
    }

    /// Shows `text` once on the shared dashboard feed of `audience`, when
    /// it has one and anyone was told just now.
    async fn show_on_dashboard(&self, audience: &Audience, text: &NotificationText, told: Told) {
        let Some(subject) = dashboard_subject(audience) else {
            return;
        };
        if told.now == 0 {
            return;
        }
        let message = live(&text.shared());
        if let Err(error) = self
            .ports
            .inboxes
            .publisher
            .publish_dashboard(&subject, &message)
            .await
        {
            tracing::warn!(%error, "notification fan-out: dashboard push failed");
        }
    }

    /// Queues a post of `text` to every destination of the organization
    /// `audience` belongs to that is active and whose filter covers it, one
    /// job per destination. A run that found its members told already is a
    /// repeat, and posts nothing again.
    async fn post_to_destinations(&self, audience: &Audience, text: &NotificationText, told: Told) {
        if told.before > 0 {
            return;
        }
        let Some(organization_id) = self.owning_organization(audience).await else {
            return;
        };
        let destinations = match self.ports.outward.destinations.list(&organization_id).await {
            Ok(destinations) => destinations,
            Err(error) => {
                tracing::warn!(%error, "notification fan-out: destinations not read");
                return;
            }
        };
        let notification = text.shared();
        let (category, severity) = (notification.category(), notification.severity());
        let posted = PostedNotification::of(&notification);
        for destination in destinations
            .iter()
            .filter(|destination| destination.receives(category, severity))
        {
            self.queue_post(destination, &posted).await;
        }
    }

    /// Queues the post of `notification` to `destination`. A post that
    /// cannot be queued is logged by the destination's id, never its
    /// address.
    async fn queue_post(
        &self,
        destination: &NotificationDestination,
        notification: &PostedNotification,
    ) {
        let post = DestinationPost {
            organization_id: *destination.organization_id(),
            destination_id: *destination.id(),
            notification: notification.clone(),
        };
        let queued = match post.scheduled() {
            Ok(job) => self.ports.outward.jobs.enqueue(&job).await.or_internal(),
            Err(error) => Err(error),
        };
        let Err(error) = queued else {
            return;
        };
        tracing::warn!(
            destination_id = %destination.id(),
            %error,
            "notification fan-out: destination post not queued"
        );
    }

    /// The organization whose destinations hear of an event `audience`
    /// hears: its own, or the one owning its tenant. The platform has none.
    async fn owning_organization(&self, audience: &Audience) -> Option<OrganizationId> {
        match *audience {
            Audience::Organization {
                organization_id, ..
            } => Some(organization_id),
            Audience::Tenant { tenant_id, .. } => self.organization_of(&tenant_id).await,
            Audience::Platform { .. } => None,
        }
    }

    /// The text `recorded` is told in to `members` of `audience`, naming its
    /// actor and tenant, and how often it happened since the last alert.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the event's name makes no valid title.
    async fn text_for(
        &self,
        recorded: &RecordedEvent,
        members: &[Member],
        audience: &Audience,
        occurrences: Occurrences,
    ) -> Result<NotificationText, AppError> {
        let tenant = self.tenant_name(audience).await;
        let credit = Credit {
            actor: name_of(members, audience.actor()),
            tenant: tenant.as_deref(),
        };
        NotificationText::of(
            recorded.record_id,
            recorded.event.event_type(),
            &recorded.event.payload(),
            credit,
        )
        .and_then(|text| text.counting(occurrences))
        .or_internal()
    }

    /// Whether this occurrence is told to `audience` as `notice` says, and
    /// how often it happened since the last alert of its kind: a feed
    /// notice always is, an alert only when the throttle lets it out.
    async fn admitted(&self, notice: Notice, audience: &Audience) -> Option<Occurrences> {
        let Some((key, window)) = notice.alert_key(audience) else {
            return Some(Occurrences::NotCounted);
        };
        let turn = self.ports.outward.alert_throttle.admit(&key, window).await;
        Occurrences::admitted(turn)
    }

    /// The organization owning `tenant_id`, or `None` when it cannot be
    /// read. A lookup that fails drops the posts, never the notification.
    async fn organization_of(&self, tenant_id: &TenantId) -> Option<OrganizationId> {
        match self.ports.tenants.find_by_id(tenant_id).await {
            Ok(tenant) => tenant.map(|tenant| *tenant.organization_id()),
            Err(error) => {
                tracing::warn!(%error, %tenant_id, "notification fan-out: tenant not read");
                None
            }
        }
    }
}

impl Command for FanOutUseCase {
    type Caller = ();
    type Input = RecordedEvent;
    type Output = Result<u64, AppError>;

    /// Tells the people who run the plane `recorded` happened on about it,
    /// each through the channel they chose, queues a post to each of the
    /// organization's destinations whose filter covers it, and returns how
    /// many people were told.
    ///
    /// An event not worth a notification tells no one; so do notification
    /// events themselves, so the fan-out cannot feed itself. A security
    /// alert is told on its first occurrence on a plane and then at most
    /// once a window, saying how many came since the last; the others are
    /// only in the trail. Records nothing: telling people is not a change
    /// anyone made.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the people to tell cannot be listed, or
    ///   the event's name makes no valid title.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        recorded: RecordedEvent,
    ) -> Result<u64, AppError> {
        let event_type = recorded.event.event_type();
        let Some(notice) = Notice::of(&event_type) else {
            return Ok(0);
        };
        let Some(audience) = Audience::of(&recorded.event, &recorded.context) else {
            return Ok(0);
        };
        let Some(occurrences) = self.admitted(notice, &audience).await else {
            return Ok(0);
        };
        let mut members = self
            .members(&audience, event_type, notice)
            .await
            .or_internal()?;
        let authors = self
            .authors_told(&recorded.event, &members)
            .await
            .or_internal()?;
        members.extend(authors);
        let text = self
            .text_for(&recorded, &members, &audience, occurrences)
            .await?;
        let told = self.deliver(&members, audience.actor(), &text).await;
        self.show_on_dashboard(&audience, &text, told).await;
        self.post_to_destinations(&audience, &text, told).await;
        Ok(told.now)
    }
}

/// How many members one run told, and how many an earlier run for the same
/// event had told already.
#[derive(Debug, Clone, Copy, Default)]
struct Told {
    now: u64,
    before: u64,
}

/// What the activity notice about `notification` is filled with: its title,
/// and its body, or the title again when it has none.
fn notice_of(notification: &Notification) -> HashMap<TemplateVariable, String> {
    let title = notification.title().as_str();
    let body = notification.body().map_or(title, Text::as_str);
    HashMap::from([
        (TemplateVariable::NoticeTitle, title.to_owned()),
        (TemplateVariable::NoticeBody, body.to_owned()),
    ])
}

/// The shared dashboard feed `audience` has, if any. A tenant's people have
/// none.
fn dashboard_subject(audience: &Audience) -> Option<String> {
    match audience {
        Audience::Platform { .. } => Some(PLATFORM_DASHBOARD_SUBJECT.to_owned()),
        Audience::Organization {
            organization_id, ..
        } => Some(org_dashboard_subject(organization_id)),
        Audience::Tenant { .. } => None,
    }
}

/// The live update telling a dashboard about `notification`.
fn live(notification: &Notification) -> RealtimeMessage {
    RealtimeMessage::Notification(NotificationUpdate::from(notification))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::delegation::HeldResources;
    use ianua_domain::domains::authorization::permission::{
        BrandingAction, SystemPermission, UserAction, WorkflowAction,
    };
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::notifications::category::NotificationCategory;
    use ianua_domain::domains::notifications::channel::NotificationChannel;
    use ianua_domain::domains::notifications::destination::DestinationState;
    use ianua_domain::domains::notifications::events::{
        MailSentFor, MailUndelivered, UndeliveredMail,
    };
    use ianua_domain::domains::notifications::personal::{
        MemberNotificationPreferences, MemberNotificationPreferencesRow,
        OperatorNotificationPreferences, OperatorNotificationPreferencesRow,
    };
    use ianua_domain::domains::notifications::preference::{
        NotificationPreference, NotificationPreferenceRow,
    };
    use ianua_domain::domains::notifications::reach::NotificationReach;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::domains::operator::status::OperatorStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::proxy::events::CanaryTokenTriggered;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::workflows::data::FlowData;
    use ianua_domain::domains::workflows::design::workflow::FailureAlert;
    use ianua_domain::domains::workflows::events::execution_events;
    use ianua_domain::domains::workflows::execution::{ManualStartParams, WorkflowExecution};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock::freeze;
    use ianua_domain::test_support::events::{
        sample_account_under_attack, sample_event_about, sample_platform_event,
        sample_refresh_token_reused, sample_tenant_event, sample_unnotifiable_event,
    };
    use ianua_domain::types::{
        ActorRef, CorrelationId, Email, Human, HumanAccount, IpAddress, OperatorId, OrgUserId,
        PersonKey, PrincipalRef, UntrustedText, UserId,
    };

    use super::*;
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::authorization::{
        FakeAccessRecordStore, stored_assignment, stored_role,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::notification_delivery::{
        FakeAlertThrottle, FakeDestinationStore, FakeMemberPreferenceStore,
        FakeOperatorPreferenceStore, destination_in_state, webhook_destination,
    };
    use crate::test_support::notifications::{
        FakeNotificationPreferenceStore, FakeOrgNotificationStore, FakePlatformNotificationStore,
        FakeTenantNotificationStore,
    };
    use crate::test_support::operator::{FakeOperatorStore, stored_operator};
    use crate::test_support::organization::{
        FakeTenantMemberRoster, OrgShape, org_shaped, org_store_with, org_user_store_with,
        test_org_user,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx, test_tenant_in};
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, draft_by, managing, published_by, wait_step,
    };
    use crate::test_support::{FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_ctx};
    use crate::use_cases::notifications::delivery::job::DESTINATION_POST_JOB;

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);

    const VIEW_WORKFLOWS: SystemPermission = SystemPermission::Workflows(WorkflowAction::View);

    /// Where a test's notifications land.
    #[derive(Default)]
    struct Inboxes {
        platform: Arc<FakePlatformNotificationStore>,
        org: Arc<FakeOrgNotificationStore>,
        tenant: Arc<FakeTenantNotificationStore>,
    }

    impl Inboxes {
        fn tenant_recipients(&self) -> Vec<UserId> {
            let held = self.tenant.notifications.lock().unwrap();
            held.iter().map(|((_, user), _)| *user).collect()
        }

        fn operator_recipients(&self) -> Vec<OperatorId> {
            let held = self.platform.notifications.lock().unwrap();
            held.iter().map(|(operator, _)| *operator).collect()
        }

        fn org_recipients(&self) -> Vec<OrgUserId> {
            let held = self.org.notifications.lock().unwrap();
            held.iter().map(|((_, user), _)| *user).collect()
        }

        fn org_bodies(&self) -> Vec<(OrgUserId, String)> {
            let held = self.org.notifications.lock().unwrap();
            held.iter()
                .map(|((_, user), notification)| {
                    let body = notification.body().map(|body| body.as_str().to_owned());
                    (*user, body.unwrap_or_default())
                })
                .collect()
        }
    }

    fn fan_out(inboxes: &Inboxes, ports: FanOutPorts) -> FanOutUseCase {
        FanOutUseCase::new(
            FanOutPorts {
                inboxes: InboxPorts {
                    platform_store: inboxes.platform.clone(),
                    org_store: inboxes.org.clone(),
                    tenant_store: inboxes.tenant.clone(),
                    ..ports.inboxes
                },
                ..ports
            },
            100,
        )
    }

    fn run(use_case: &FanOutUseCase, event: DomainEvent, context: AuditContext) -> u64 {
        run_as(use_case, AuditRecordId::new(), event, context)
    }

    fn run_as(
        use_case: &FanOutUseCase,
        record_id: AuditRecordId,
        event: DomainEvent,
        context: AuditContext,
    ) -> u64 {
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let recorded = RecordedEvent {
            record_id,
            event,
            context,
        };
        block_on(use_case.execute(&(), &auditor, recorded)).unwrap()
    }

    /// Acme's people: Ann and Bob administer it, and twenty customers hold
    /// nothing.
    struct Acme {
        ann: UserId,
        bob: UserId,
        customers: Vec<UserId>,
        users: FakeUserStore,
        records: AccessRecords,
    }

    impl Acme {
        fn new() -> Self {
            let (ann, bob) = (UserId::new(), UserId::new());
            let users = FakeUserStore::with_user(ann, "ann@acme.com");
            users.add_active_user(bob, "bob@acme.com");
            let customers: Vec<UserId> = (0..20).map(|_| UserId::new()).collect();
            for (n, customer) in customers.iter().enumerate() {
                users.add_active_user(*customer, &format!("customer{n}@example.com"));
            }
            let admin = stored_role("admin", SystemPermission::all().to_vec(), Vec::new());
            let records = AccessRecords {
                assignments: vec![
                    stored_assignment(PrincipalRef::User(ann), *admin.id()),
                    stored_assignment(PrincipalRef::User(bob), *admin.id()),
                ],
                roles: vec![admin],
                ..AccessRecords::default()
            };
            Self {
                ann,
                bob,
                customers,
                users,
                records,
            }
        }

        /// `person`, an active user, holding a role that gives `held`.
        fn holding(mut self, person: UserId, address: &str, held: &[SystemPermission]) -> Self {
            self.users.add_active_user(person, address);
            let role = stored_role("held", held.to_vec(), Vec::new());
            self.records
                .assignments
                .push(stored_assignment(PrincipalRef::User(person), *role.id()));
            self.records.roles.push(role);
            self
        }

        /// The fan-out's ports reading Acme's users and records.
        fn ports(self) -> FanOutPorts {
            FanOutPorts {
                audience: AudiencePorts {
                    user_store: Arc::new(self.users),
                    access_records: Arc::new(FakeAccessRecordStore::holding(
                        test_ctx().tenant_id(),
                        self.records,
                    )),
                    ..AudiencePorts::fakes()
                },
                ..FanOutPorts::fakes()
            }
        }
    }

    /// Ann pausing a topic in the test tenant.
    fn ann_pauses_a_topic(ann: UserId) -> (DomainEvent, AuditContext) {
        let tenant_id = test_ctx().tenant_id();
        (
            sample_tenant_event(tenant_id).with_actor(ActorRef::User(ann)),
            AuditContext::system().with_tenant(tenant_id),
        )
    }

    /// `channel` for messaging, as `user` of the test tenant chose it.
    fn chose(user: UserId, channel: NotificationChannel) -> Arc<FakeNotificationPreferenceStore> {
        Arc::new(FakeNotificationPreferenceStore::with_prefs(
            test_ctx().tenant_id(),
            user,
            vec![NotificationPreference::new(
                NotificationCategory::Messaging,
                channel,
            )],
        ))
    }

    /// Acme has two admins and twenty customers. Ann, an admin, pauses a
    /// topic: Bob, the other admin, is told. Ann is not told of her own
    /// action, and none of the customers hears of it.
    #[test]
    fn an_admin_action_in_a_tenant_tells_only_its_administrators() {
        let acme = Acme::new();
        let (ann, bob, customers) = (acme.ann, acme.bob, acme.customers.clone());
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, acme.ports());
        let (event, context) = ann_pauses_a_topic(ann);

        let told = run(&use_case, event, context);

        let recipients = inboxes.tenant_recipients();
        assert_eq!(told, 1);
        assert_eq!(recipients, [bob]);
        assert!(
            customers
                .iter()
                .all(|customer| !recipients.contains(customer))
        );
    }

    /// Ann, an admin, locks Carol's account. Carol, who may view users,
    /// hears of what was done to her, and so does Bob; the customers do
    /// not.
    #[test]
    fn the_person_an_event_is_about_is_told() {
        let carol = UserId::new();
        let acme = Acme::new().holding(carol, "carol@acme.com", &[VIEW_USERS]);
        let (ann, bob) = (acme.ann, acme.bob);
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, acme.ports());
        let tenant_id = test_ctx().tenant_id();

        let told = run(
            &use_case,
            sample_event_about(tenant_id, carol).with_actor(ActorRef::User(ann)),
            AuditContext::system().with_tenant(tenant_id),
        );

        let recipients = inboxes.tenant_recipients();
        assert_eq!(told, 2);
        assert!(recipients.contains(&carol) && recipients.contains(&bob));
    }

    /// A run of a workflow Carol wrote, waiting, whose version tells its
    /// authors of failures when `tells` says so; and the event of it running
    /// out of time.
    fn carols_run_timed_out(
        carol: UserId,
        tells: FailureAlert,
    ) -> (WorkflowExecution<ResolvedTenant>, DomainEvent) {
        let author = Human::new(
            HumanAccount::User(carol),
            PersonKey::new("carol@acme.com").unwrap(),
        );
        let mut draft = draft_by(&author, vec![wait_step("later")], Vec::new());
        draft
            .change_failure_alert(&managing(&author), tells)
            .unwrap();
        let workflow = published_by(&author, draft);
        let (mut execution, _) = WorkflowExecution::start_by_hand(
            &workflow,
            managing(&author),
            ManualStartParams {
                resources: HeldResources::answered(author.principal(), Vec::new()),
                input: FlowData::null(),
                exposure: DataClassLevel::Internal,
            },
        )
        .unwrap();
        let _late = freeze(execution.deadline() + time::Duration::SECOND);
        let records = execution.expire().unwrap();
        let ended = execution_events(test_ctx().tenant_id(), &execution, records)
            .into_iter()
            .last()
            .unwrap();
        (execution, ended)
    }

    /// Carol may view workflows but administers nothing. A run of a
    /// workflow she wrote, whose version tells its authors, runs out of
    /// time: Carol is told, as are the administrators.
    #[test]
    fn the_authors_of_a_failed_run_are_told_when_their_version_asks() {
        let carol = UserId::new();
        let acme = Acme::new().holding(carol, "carol@acme.com", &[VIEW_WORKFLOWS]);
        let (execution, ended) = carols_run_timed_out(carol, FailureAlert::AlsoAuthors);
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, {
            let base = acme.ports();
            FanOutPorts {
                audience: AudiencePorts {
                    executions: Arc::new(FakeWorkflowExecutionStore::holding(&execution)),
                    ..base.audience
                },
                ..base
            }
        });

        run(
            &use_case,
            ended,
            AuditContext::system().with_tenant(test_ctx().tenant_id()),
        );

        assert!(inboxes.tenant_recipients().contains(&carol));
    }

    /// A timed-out run whose version alerts only administrators does not
    /// notify its author, who holds only workflow viewing rights.
    #[test]
    fn an_author_is_not_told_when_the_version_tells_only_administrators() {
        let carol = UserId::new();
        let acme = Acme::new().holding(carol, "carol@acme.com", &[VIEW_WORKFLOWS]);
        let (execution, ended) = carols_run_timed_out(carol, FailureAlert::Administrators);
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, {
            let base = acme.ports();
            FanOutPorts {
                audience: AudiencePorts {
                    executions: Arc::new(FakeWorkflowExecutionStore::holding(&execution)),
                    ..base.audience
                },
                ..base
            }
        });

        run(
            &use_case,
            ended,
            AuditContext::system().with_tenant(test_ctx().tenant_id()),
        );

        assert!(!inboxes.tenant_recipients().contains(&carol));
    }

    /// What the tenant inbox of `user` holds.
    fn kept_for(inboxes: &Inboxes, user: UserId) -> Vec<Notification> {
        let held = inboxes.tenant.notifications.lock().unwrap();
        held.iter()
            .filter(|((_, owner), _)| *owner == user)
            .map(|(_, notification)| notification.clone())
            .collect()
    }

    /// Ann, an admin, locks out Carol, who holds no right at all and can no
    /// longer sign in. Carol is told all the same: the notice is kept in
    /// her inbox on her own account, and mailed to her proved address
    /// though she never chose mail.
    #[test]
    fn a_locked_out_plain_user_is_told_and_mailed() {
        let carol = UserId::new();
        let acme = Acme::new();
        acme.users
            .add(stored_user(carol, "carol@acme.com", UserStatus::Locked));
        let ann = acme.ann;
        let mailer = Arc::new(FakeMailer::new());
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, {
            let base = acme.ports();
            FanOutPorts {
                outward: DeliveryPorts {
                    mailer: mailer.clone(),
                    ..base.outward
                },
                ..base
            }
        });
        let tenant_id = test_ctx().tenant_id();

        run(
            &use_case,
            sample_event_about(tenant_id, carol).with_actor(ActorRef::User(ann)),
            AuditContext::system().with_tenant(tenant_id),
        );

        let kept = kept_for(&inboxes, carol);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].reach(), NotificationReach::OwnAccount);
        assert!(mailer.recipients().contains(&"carol@acme.com".to_owned()));
    }

    /// Locking a user's account still saves a notice in their inbox when
    /// they disabled identity notifications.
    #[test]
    fn a_holder_who_switched_account_notices_off_is_still_told() {
        let carol = UserId::new();
        let acme = Acme::new();
        acme.users.add_active_user(carol, "carol@acme.com");
        let ann = acme.ann;
        let muted = Arc::new(FakeNotificationPreferenceStore::with_prefs(
            test_ctx().tenant_id(),
            carol,
            vec![NotificationPreference::new(
                NotificationCategory::Identity,
                NotificationChannel::Disabled,
            )],
        ));
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, {
            let base = acme.ports();
            FanOutPorts {
                preferences: PreferencePorts {
                    preference_store: muted,
                    ..base.preferences
                },
                ..base
            }
        });
        let tenant_id = test_ctx().tenant_id();

        run(
            &use_case,
            sample_event_about(tenant_id, carol).with_actor(ActorRef::User(ann)),
            AuditContext::system().with_tenant(tenant_id),
        );

        assert_eq!(kept_for(&inboxes, carol).len(), 1);
    }

    /// Locking one ordinary user's account notifies that user and saves no
    /// notice for another user without permissions.
    #[test]
    fn a_plain_user_is_not_told_of_someone_elses_lock() {
        let (carol, dave) = (UserId::new(), UserId::new());
        let acme = Acme::new();
        acme.users.add_active_user(carol, "carol@acme.com");
        acme.users.add_active_user(dave, "dave@acme.com");
        let ann = acme.ann;
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, acme.ports());
        let tenant_id = test_ctx().tenant_id();

        run(
            &use_case,
            sample_event_about(tenant_id, dave).with_actor(ActorRef::User(ann)),
            AuditContext::system().with_tenant(tenant_id),
        );

        assert!(kept_for(&inboxes, carol).is_empty());
        assert_eq!(kept_for(&inboxes, dave).len(), 1);
    }

    /// Olivia, a member of the organization, locks Carol's account from
    /// the management plane. Carol, a plain user of the tenant, is told in
    /// her own tenant's inbox.
    #[test]
    fn a_lock_made_from_the_management_plane_tells_its_holder() {
        let organization_id = test_ctx().organization_id();
        let olivia = test_org_user(organization_id, "olivia@acme.com", OrgRole::Owner);
        let olivia_id = *olivia.id();
        let carol = UserId::new();
        let users = FakeUserStore::with_user(carol, "carol@acme.com");
        let inboxes = Inboxes::default();
        let use_case = fan_out(
            &inboxes,
            FanOutPorts {
                tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                audience: AudiencePorts {
                    user_store: Arc::new(users),
                    org_user_store: Arc::new(org_user_store_with([olivia])),
                    ..AudiencePorts::fakes()
                },
                ..FanOutPorts::fakes()
            },
        );
        let caller = ActorRef::OrgUser(olivia_id);
        let tenant_id = test_ctx().tenant_id();

        run(
            &use_case,
            sample_event_about(tenant_id, carol).with_actor(caller.clone()),
            AuditContext::for_caller(organization_id, caller),
        );

        assert_eq!(inboxes.tenant_recipients(), [carol]);
    }

    /// A user and role administrator without messaging access receives no
    /// topic-pause notice in their inbox or mail despite choosing mailed alerts.
    #[test]
    fn someone_who_may_not_see_the_category_is_neither_told_nor_mailed() {
        let erin = UserId::new();
        let acme = Acme::new().holding(
            erin,
            "erin@acme.com",
            &[SystemPermission::ManageUsers, SystemPermission::ManageRoles],
        );
        let ann = acme.ann;
        let mailer = Arc::new(FakeMailer::new());
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, {
            let base = acme.ports();
            FanOutPorts {
                outward: DeliveryPorts {
                    mailer: mailer.clone(),
                    ..base.outward
                },
                preferences: PreferencePorts {
                    preference_store: chose(erin, NotificationChannel::InAppAndEmail),
                    ..base.preferences
                },
                ..base
            }
        });
        let (event, context) = ann_pauses_a_topic(ann);

        run(&use_case, event, context);

        assert!(!inboxes.tenant_recipients().contains(&erin));
        assert!(mailer.recipients().is_empty());
    }

    /// Bob switched messaging notifications off. Ann pauses a topic and
    /// nobody is told.
    #[test]
    fn an_admin_who_switched_the_category_off_is_not_told() {
        let acme = Acme::new();
        let (ann, bob) = (acme.ann, acme.bob);
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, {
            let base = acme.ports();
            FanOutPorts {
                preferences: PreferencePorts {
                    preference_store: chose(bob, NotificationChannel::Disabled),
                    ..base.preferences
                },
                ..base
            }
        });
        let (event, context) = ann_pauses_a_topic(ann);

        let told = run(&use_case, event, context);

        assert_eq!(told, 0);
        assert!(inboxes.tenant_recipients().is_empty());
    }

    /// Bob wants messaging notifications by mail too. Ann pauses a topic:
    /// Bob finds it in the app, and the mailer is handed an activity notice
    /// for him carrying the notification's title.
    #[test]
    fn an_admin_who_chose_mail_is_mailed_through_the_mailer() {
        let acme = Acme::new();
        let (ann, bob) = (acme.ann, acme.bob);
        let mailer = Arc::new(FakeMailer::new());
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, {
            let base = acme.ports();
            FanOutPorts {
                outward: DeliveryPorts {
                    mailer: mailer.clone(),
                    ..base.outward
                },
                preferences: PreferencePorts {
                    preference_store: chose(bob, NotificationChannel::InAppAndEmail),
                    ..base.preferences
                },
                ..base
            }
        });
        let (event, context) = ann_pauses_a_topic(ann);

        run(&use_case, event, context);

        let sent = mailer.sent.lock().unwrap();
        assert_eq!(inboxes.tenant_recipients(), [bob]);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "bob@acme.com");
        assert_eq!(sent[0].template, EmailTemplateType::ActivityNotice);
        assert!(
            sent[0]
                .variables
                .contains_key(&TemplateVariable::NoticeTitle)
        );
    }

    /// Processing the same audit record twice saves and mails one notification;
    /// the second run reports no newly notified recipients.
    #[test]
    fn the_same_event_run_twice_tells_and_mails_once() {
        let acme = Acme::new();
        let (ann, bob) = (acme.ann, acme.bob);
        let mailer = Arc::new(FakeMailer::new());
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, {
            let base = acme.ports();
            FanOutPorts {
                outward: DeliveryPorts {
                    mailer: mailer.clone(),
                    ..base.outward
                },
                preferences: PreferencePorts {
                    preference_store: chose(bob, NotificationChannel::InAppAndEmail),
                    ..base.preferences
                },
                ..base
            }
        });
        let record = AuditRecordId::new();
        let (event, context) = ann_pauses_a_topic(ann);
        let (again, again_context) = ann_pauses_a_topic(ann);

        let first = run_as(&use_case, record, event, context);
        let second = run_as(&use_case, record, again, again_context);

        assert_eq!((first, second), (1, 0));
        assert_eq!(inboxes.tenant_recipients(), [bob]);
        assert_eq!(mailer.count(), 1);
    }

    /// Two events alike, recorded apart, are two notifications: only the
    /// same record is told once.
    #[test]
    fn two_records_of_the_same_change_are_both_told() {
        let acme = Acme::new();
        let (ann, bob) = (acme.ann, acme.bob);
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, acme.ports());
        let (event, context) = ann_pauses_a_topic(ann);
        let (again, again_context) = ann_pauses_a_topic(ann);

        run(&use_case, event, context);
        run(&use_case, again, again_context);

        assert_eq!(inboxes.tenant_recipients(), [bob, bob]);
    }

    /// Nobody chose mail. Bob is told in the app and nothing is mailed.
    #[test]
    fn nobody_is_mailed_who_did_not_choose_it() {
        let acme = Acme::new();
        let ann = acme.ann;
        let mailer = Arc::new(FakeMailer::new());
        let use_case = fan_out(&Inboxes::default(), {
            let base = acme.ports();
            FanOutPorts {
                outward: DeliveryPorts {
                    mailer: mailer.clone(),
                    ..base.outward
                },
                ..base
            }
        });
        let (event, context) = ann_pauses_a_topic(ann);

        run(&use_case, event, context);

        assert_eq!(mailer.count(), 0);
    }

    /// Acme's organization has Olivia, an owner, and Bill, its billing
    /// contact. Ann pauses a topic inside the tenant. Olivia, who reaches
    /// every tenant, is told in her organization inbox; Bill, who reaches
    /// none, is not.
    #[test]
    fn members_with_access_to_the_tenant_are_told() {
        let tenant = test_tenant_for_ctx();
        let organization_id = *tenant.organization_id();
        let olivia = test_org_user(organization_id, "olivia@acme.com", OrgRole::Owner);
        let bill = test_org_user(organization_id, "bill@acme.com", OrgRole::Billing);
        let olivia_id = *olivia.id();
        let acme = Acme::new();
        let ann = acme.ann;
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, {
            let base = acme.ports();
            FanOutPorts {
                tenants: Arc::new(FakeTenantStore::holding(tenant)),
                audience: AudiencePorts {
                    organizations: org_store_with([org_shaped(
                        organization_id,
                        OrgShape::owning(&[test_ctx().tenant_id()]),
                    )]),
                    member_roster: Arc::new(FakeTenantMemberRoster::holding(
                        [olivia, bill],
                        Vec::new(),
                    )),
                    ..base.audience
                },
                ..base
            }
        });
        let (event, context) = ann_pauses_a_topic(ann);

        run(&use_case, event, context);

        assert_eq!(inboxes.org_recipients(), [olivia_id]);
    }

    /// Ann turns a category off. That is not worth telling anyone, and a
    /// notification about notifications would feed the fan-out itself.
    #[test]
    fn an_event_not_worth_a_notification_tells_no_one() {
        let tenant_id = test_ctx().tenant_id();
        let inboxes = Inboxes::default();
        let use_case = fan_out(&inboxes, Acme::new().ports());

        let told = run(
            &use_case,
            sample_unnotifiable_event(tenant_id),
            AuditContext::system().with_tenant(tenant_id),
        );

        assert_eq!(told, 0);
        assert!(inboxes.tenant_recipients().is_empty());
    }

    /// Olga creates an operator. Pat, the other operator, is told; Olga is
    /// not.
    #[test]
    fn the_other_operators_hear_of_a_platform_change() {
        let (olga, pat) = (OperatorId::new(), OperatorId::new());
        let operators = FakeOperatorStore::holding([
            stored_operator(olga, "olga@ianua.dev", OperatorStatus::Active),
            stored_operator(pat, "pat@ianua.dev", OperatorStatus::Active),
        ]);
        let inboxes = Inboxes::default();
        let use_case = fan_out(
            &inboxes,
            FanOutPorts {
                audience: AudiencePorts {
                    operator_store: Arc::new(operators),
                    ..AudiencePorts::fakes()
                },
                ..FanOutPorts::fakes()
            },
        );
        let caller = ActorRef::Operator(olga);

        let told = run(
            &use_case,
            sample_platform_event().with_actor(caller.clone()),
            AuditContext::for_platform_caller(caller),
        );

        assert_eq!(told, 1);
        assert_eq!(inboxes.operator_recipients(), [pat]);
    }

    /// Keeps an operator's choice to suppress a single notification category.
    fn muted_operator(
        operator_id: OperatorId,
        category: NotificationCategory,
    ) -> OperatorNotificationPreferences {
        OperatorNotificationPreferences::reconstitute(OperatorNotificationPreferencesRow {
            operator_id,
            preferences: vec![NotificationPreferenceRow {
                category,
                channel: NotificationChannel::Disabled,
            }],
        })
        .unwrap()
    }

    /// Pat switched the category of operator changes off. Olga creates an
    /// operator and Pat is not told.
    #[test]
    fn an_operator_who_switched_the_category_off_is_not_told() {
        let (olga, pat) = (OperatorId::new(), OperatorId::new());
        let operators = FakeOperatorStore::holding([
            stored_operator(olga, "olga@ianua.dev", OperatorStatus::Active),
            stored_operator(pat, "pat@ianua.dev", OperatorStatus::Active),
        ]);
        let event = sample_platform_event().with_actor(ActorRef::Operator(olga));
        let category = NotificationCategory::from_event_type(&event.event_type());
        let muted = muted_operator(pat, category);
        let inboxes = Inboxes::default();
        let use_case = fan_out(
            &inboxes,
            FanOutPorts {
                preferences: PreferencePorts {
                    operator_preferences: Arc::new(FakeOperatorPreferenceStore::holding(muted)),
                    ..PreferencePorts::fakes()
                },
                audience: AudiencePorts {
                    operator_store: Arc::new(operators),
                    ..AudiencePorts::fakes()
                },
                ..FanOutPorts::fakes()
            },
        );

        let told = run(
            &use_case,
            event,
            AuditContext::for_platform_caller(ActorRef::Operator(olga)),
        );

        assert_eq!(told, 0);
        assert!(inboxes.operator_recipients().is_empty());
    }

    /// Ann, an org member, pauses a topic in the Acme tenant from the
    /// management plane. Her colleague Bob is told, and the notification
    /// says it happened in Acme, since Bob reads it outside the tenant.
    #[test]
    fn the_management_plane_hears_what_an_org_user_did_in_a_tenant_and_where() {
        let organization_id = OrganizationId::new();
        let tenant = test_tenant_in(organization_id, "acme", "acme.example.com");
        let tenant_id = *tenant.id();
        let ann = test_org_user(organization_id, "ann@acme.com", OrgRole::Member);
        let bob = test_org_user(organization_id, "bob@acme.com", OrgRole::Member);
        let (ann_id, bob_id) = (*ann.id(), *bob.id());
        let tenant_name = tenant.display_name().as_str().to_owned();
        let inboxes = Inboxes::default();
        let use_case = fan_out(
            &inboxes,
            FanOutPorts {
                tenants: Arc::new(FakeTenantStore::holding(tenant)),
                audience: AudiencePorts {
                    org_user_store: Arc::new(org_user_store_with([ann, bob])),
                    ..AudiencePorts::fakes()
                },
                ..FanOutPorts::fakes()
            },
        );
        let caller = ActorRef::OrgUser(ann_id);

        let told = run(
            &use_case,
            sample_tenant_event(tenant_id).with_actor(caller.clone()),
            AuditContext::for_caller(organization_id, caller),
        );

        let bodies = inboxes.org_bodies();
        assert_eq!(told, 1);
        assert_eq!(bodies[0].0, bob_id);
        assert!(bodies[0].1.contains(&tenant_name), "{}", bodies[0].1);
    }

    /// Keeps a member's choice to suppress messaging notifications in their organization.
    fn muted_member(
        organization_id: OrganizationId,
        org_user_id: OrgUserId,
    ) -> MemberNotificationPreferences {
        MemberNotificationPreferences::reconstitute(MemberNotificationPreferencesRow {
            organization_id,
            org_user_id,
            preferences: vec![NotificationPreferenceRow {
                category: NotificationCategory::Messaging,
                channel: NotificationChannel::Disabled,
            }],
        })
        .unwrap()
    }

    /// Bob, an org member, switched the category off. Ann pauses a topic
    /// from the management plane and Bob is not told.
    #[test]
    fn a_member_who_switched_the_category_off_is_not_told() {
        let organization_id = OrganizationId::new();
        let tenant = test_tenant_in(organization_id, "acme", "acme.example.com");
        let tenant_id = *tenant.id();
        let ann = test_org_user(organization_id, "ann@acme.com", OrgRole::Member);
        let bob = test_org_user(organization_id, "bob@acme.com", OrgRole::Member);
        let ann_id = *ann.id();
        let muted = muted_member(organization_id, *bob.id());
        let inboxes = Inboxes::default();
        let base = organization_ports(tenant, [ann, bob]);
        let use_case = fan_out(
            &inboxes,
            FanOutPorts {
                preferences: PreferencePorts {
                    member_preferences: Arc::new(FakeMemberPreferenceStore::holding(muted)),
                    ..PreferencePorts::fakes()
                },
                ..base
            },
        );
        let caller = ActorRef::OrgUser(ann_id);

        let told = run(
            &use_case,
            sample_tenant_event(tenant_id).with_actor(caller.clone()),
            AuditContext::for_caller(organization_id, caller),
        );

        assert_eq!(told, 0);
        assert!(inboxes.org_recipients().is_empty());
    }

    /// The fan-out in Acme's tenant, whose organization keeps
    /// `destinations`, queueing posts on `jobs`.
    fn with_destinations(
        destinations: FakeDestinationStore,
        jobs: Arc<FakeJobQueue>,
    ) -> (FanOutUseCase, UserId) {
        let acme = Acme::new();
        let ann = acme.ann;
        let use_case = fan_out(&Inboxes::default(), {
            let base = acme.ports();
            FanOutPorts {
                tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                outward: DeliveryPorts {
                    destinations: Arc::new(destinations),
                    jobs,
                    ..base.outward
                },
                ..base
            }
        });
        (use_case, ann)
    }

    /// Acme posts everything to an on-call webhook and a second channel.
    /// Ann pauses a topic: one post is queued for each, naming its own
    /// destination, and nothing is posted inline.
    #[test]
    fn each_destination_whose_filter_covers_it_gets_its_own_queued_post() {
        let organization_id = test_ctx().organization_id();
        let jobs = Arc::new(FakeJobQueue::new());
        let hooks = [
            webhook_destination(organization_id, NotificationSeverity::Info),
            webhook_destination(organization_id, NotificationSeverity::Info),
        ];
        let ids = [*hooks[0].id(), *hooks[1].id()];
        let (use_case, ann) = with_destinations(FakeDestinationStore::holding(hooks), jobs.clone());
        let (event, context) = ann_pauses_a_topic(ann);

        run(&use_case, event, context);

        let queued: Vec<_> = jobs
            .jobs_of(DESTINATION_POST_JOB)
            .iter()
            .map(|job| DestinationPost::read(job).unwrap().destination_id)
            .collect();
        assert_eq!(queued.len(), 2);
        assert!(ids.iter().all(|id| queued.contains(id)));
    }

    /// Processing the same audit record twice queues only one destination post.
    #[test]
    fn the_same_event_run_twice_posts_once() {
        let organization_id = test_ctx().organization_id();
        let jobs = Arc::new(FakeJobQueue::new());
        let hooks = [webhook_destination(
            organization_id,
            NotificationSeverity::Info,
        )];
        let (use_case, ann) = with_destinations(FakeDestinationStore::holding(hooks), jobs.clone());
        let record = AuditRecordId::new();
        let (event, context) = ann_pauses_a_topic(ann);
        let (again, again_context) = ann_pauses_a_topic(ann);

        run_as(&use_case, record, event, context);
        run_as(&use_case, record, again, again_context);

        assert_eq!(jobs.jobs_of(DESTINATION_POST_JOB).len(), 1);
    }

    /// Acme's webhook takes critical alerts only, and another is paused.
    /// Pausing a topic queues a post for neither.
    #[test]
    fn a_paused_destination_or_one_filtering_it_out_gets_no_post() {
        let organization_id = test_ctx().organization_id();
        let jobs = Arc::new(FakeJobQueue::new());
        let destinations = FakeDestinationStore::holding([
            webhook_destination(organization_id, NotificationSeverity::Critical),
            destination_in_state(
                organization_id,
                NotificationSeverity::Info,
                DestinationState::Paused,
            ),
        ]);
        let (use_case, ann) = with_destinations(destinations, jobs.clone());
        let (event, context) = ann_pauses_a_topic(ann);

        run(&use_case, event, context);

        assert!(!jobs.holds(DESTINATION_POST_JOB));
    }

    /// A tenant event queues no post to another organization's destination.
    #[test]
    fn another_organizations_destination_gets_no_post() {
        let jobs = Arc::new(FakeJobQueue::new());
        let theirs = webhook_destination(OrganizationId::new(), NotificationSeverity::Info);
        let (use_case, ann) =
            with_destinations(FakeDestinationStore::holding([theirs]), jobs.clone());
        let (event, context) = ann_pauses_a_topic(ann);

        run(&use_case, event, context);

        assert!(!jobs.holds(DESTINATION_POST_JOB));
    }

    /// A fan-out over Acme's people whose alerts go through `throttle`.
    fn alerting(acme: Acme, inboxes: &Inboxes, throttle: &Arc<FakeAlertThrottle>) -> FanOutUseCase {
        fan_out(inboxes, {
            let base = acme.ports();
            FanOutPorts {
                outward: DeliveryPorts {
                    alert_throttle: throttle.clone(),
                    ..base.outward
                },
                ..base
            }
        })
    }

    /// Mallory presents one of the test tenant's canary credentials.
    fn canary_hit() -> (DomainEvent, AuditContext) {
        let tenant_id = test_ctx().tenant_id();
        let ip = IpAddress::new("203.0.113.9").unwrap();
        (
            CanaryTokenTriggered::observed(tenant_id, ip, CorrelationId::new()),
            AuditContext::system().with_tenant(tenant_id),
        )
    }

    /// Records `event` in the trail, as the pipeline does before any
    /// fan-out, then tells whom it tells.
    fn record_and_tell(
        use_case: &FanOutUseCase,
        trail: &Arc<FakeEventDispatcher>,
        (event, context): (DomainEvent, AuditContext),
    ) -> u64 {
        block_on(test_auditor(trail.clone()).dispatch(std::slice::from_ref(&event))).unwrap();
        run(use_case, event, context)
    }

    /// The first canary credential alert notifies both tenant administrators.
    #[test]
    fn the_first_canary_hit_tells_the_admins() {
        let acme = Acme::new();
        let (ann, bob) = (acme.ann, acme.bob);
        let inboxes = Inboxes::default();
        let use_case = alerting(acme, &inboxes, &Arc::new(FakeAlertThrottle::default()));
        let (event, context) = canary_hit();

        let told = run(&use_case, event, context);

        let recipients = inboxes.tenant_recipients();
        assert_eq!(told, 2);
        assert!(recipients.contains(&ann) && recipients.contains(&bob));
    }

    /// Two canary alerts within the throttle window notify administrators
    /// only on the first occurrence while both remain in the audit trail.
    #[test]
    fn a_second_hit_within_the_hour_is_only_recorded() {
        let inboxes = Inboxes::default();
        let use_case = alerting(
            Acme::new(),
            &inboxes,
            &Arc::new(FakeAlertThrottle::default()),
        );
        let trail = Arc::new(FakeEventDispatcher::new());

        let first = record_and_tell(&use_case, &trail, canary_hit());
        let second = record_and_tell(&use_case, &trail, canary_hit());

        assert_eq!(first, 2);
        assert_eq!(second, 0);
        assert_eq!(
            *trail.records.lock().unwrap(),
            [
                "proxy.canary_token_triggered",
                "proxy.canary_token_triggered"
            ]
        );
    }

    /// Mallory keeps replaying the canary credential. Once the hour passed,
    /// the next hit tells the admins again, saying how many hits came since
    /// the last alert.
    #[test]
    fn after_the_window_the_next_hit_tells_again_with_the_count() {
        let acme = Acme::new();
        let bob = acme.bob;
        let inboxes = Inboxes::default();
        let throttle = Arc::new(FakeAlertThrottle::default());
        let use_case = alerting(acme, &inboxes, &throttle);
        let (first, first_context) = canary_hit();
        let (held, held_context) = canary_hit();
        let (later, later_context) = canary_hit();
        run(&use_case, first, first_context);
        run(&use_case, held, held_context);
        throttle.pass_window();

        let told = run(&use_case, later, later_context);

        let kept = kept_for(&inboxes, bob);
        let body = kept[1].body().map(|body| body.as_str().to_owned());
        assert_eq!(told, 2);
        assert_eq!(kept.len(), 2);
        assert!(
            body.unwrap_or_default()
                .contains("It happened 2 times since the last alert."),
        );
    }

    /// A refresh-token reuse alert notifies both tenant administrators.
    #[test]
    fn a_reused_refresh_token_tells_the_admins() {
        let acme = Acme::new();
        let (ann, bob) = (acme.ann, acme.bob);
        let inboxes = Inboxes::default();
        let use_case = alerting(acme, &inboxes, &Arc::new(FakeAlertThrottle::default()));
        let tenant_id = test_ctx().tenant_id();

        let told = run(
            &use_case,
            sample_refresh_token_reused(tenant_id),
            AuditContext::system().with_tenant(tenant_id),
        );

        let recipients = inboxes.tenant_recipients();
        assert_eq!(told, 2);
        assert!(recipients.contains(&ann) && recipients.contains(&bob));
    }

    /// Two account-attack alerts within the throttle window notify
    /// administrators only on the first occurrence while both are audited.
    #[test]
    fn an_account_under_attack_tells_the_admins_at_most_hourly() {
        let inboxes = Inboxes::default();
        let use_case = alerting(
            Acme::new(),
            &inboxes,
            &Arc::new(FakeAlertThrottle::default()),
        );
        let trail = Arc::new(FakeEventDispatcher::new());
        let tenant_id = test_ctx().tenant_id();
        let attacked = || {
            (
                sample_account_under_attack(tenant_id),
                AuditContext::system().with_tenant(tenant_id),
            )
        };

        let first = record_and_tell(&use_case, &trail, attacked());
        let second = record_and_tell(&use_case, &trail, attacked());

        assert_eq!(first, 2);
        assert_eq!(second, 0);
        assert_eq!(
            *trail.records.lock().unwrap(),
            [
                "authentication.account_under_attack",
                "authentication.account_under_attack"
            ]
        );
    }

    /// A user with only user viewing rights receives no canary alert.
    #[test]
    fn someone_who_is_no_admin_is_not_told_of_an_alert() {
        let carol = UserId::new();
        let acme = Acme::new().holding(carol, "carol@acme.com", &[VIEW_USERS]);
        let inboxes = Inboxes::default();
        let use_case = alerting(acme, &inboxes, &Arc::new(FakeAlertThrottle::default()));
        let (event, context) = canary_hit();

        run(&use_case, event, context);

        assert!(!inboxes.tenant_recipients().contains(&carol));
    }

    /// Acme's reset link to Ann is given up on after its last try.
    fn reset_link_lost() -> (DomainEvent, AuditContext) {
        let tenant_id = test_ctx().tenant_id();
        let mail = UndeliveredMail {
            template: EmailTemplateType::PasswordReset,
            recipient: Email::new("ann@acme.com").unwrap(),
            attempts: 5,
            reason: UntrustedText::record("postmark refused the mail with status 503"),
        };
        (
            MailUndelivered::observed(mail, MailSentFor::Tenant(tenant_id)),
            AuditContext::system().with_tenant(tenant_id),
        )
    }

    /// A failed password-reset email notifies a user with branding update
    /// and viewing rights but excludes a user with only user viewing rights.
    #[test]
    fn a_lost_mail_tells_whoever_manages_mail_and_no_one_else() {
        let (mia, sam) = (UserId::new(), UserId::new());
        let mail_rights = [
            SystemPermission::Branding(BrandingAction::Update),
            SystemPermission::Branding(BrandingAction::View),
        ];
        let acme = Acme::new()
            .holding(mia, "mia@acme.com", &mail_rights)
            .holding(sam, "sam@acme.com", &[VIEW_USERS]);
        let inboxes = Inboxes::default();
        let use_case = alerting(acme, &inboxes, &Arc::new(FakeAlertThrottle::default()));
        let (event, context) = reset_link_lost();

        run(&use_case, event, context);

        let recipients = inboxes.tenant_recipients();
        assert!(recipients.contains(&mia));
        assert!(!recipients.contains(&sam));
    }

    /// Supplies the tenant and organization members whose shared feed is being exercised.
    fn organization_ports(
        tenant: Tenant,
        members: impl IntoIterator<Item = OrgUser>,
    ) -> FanOutPorts {
        FanOutPorts {
            tenants: Arc::new(FakeTenantStore::holding(tenant)),
            audience: AudiencePorts {
                org_user_store: Arc::new(org_user_store_with(members)),
                ..AudiencePorts::fakes()
            },
            ..FanOutPorts::fakes()
        }
    }

    /// A refresh-token reuse alert on the organization plane notifies only
    /// its owner and administrator, excluding ordinary members, viewers and billing.
    #[test]
    fn an_alert_on_the_organizations_plane_reaches_only_admins_and_owners() {
        let organization_id = OrganizationId::new();
        let tenant = test_tenant_in(organization_id, "acme", "acme.example.com");
        let tenant_id = *tenant.id();
        let maya = test_org_user(organization_id, "maya@acme.com", OrgRole::Member);
        let olivia = test_org_user(organization_id, "olivia@acme.com", OrgRole::Owner);
        let adam = test_org_user(organization_id, "adam@acme.com", OrgRole::Admin);
        let mel = test_org_user(organization_id, "mel@acme.com", OrgRole::Member);
        let vic = test_org_user(organization_id, "vic@acme.com", OrgRole::Viewer);
        let bill = test_org_user(organization_id, "bill@acme.com", OrgRole::Billing);
        let (maya_id, olivia_id, adam_id) = (*maya.id(), *olivia.id(), *adam.id());
        let inboxes = Inboxes::default();
        let use_case = fan_out(
            &inboxes,
            organization_ports(tenant, [maya, olivia, adam, mel, vic, bill]),
        );
        let caller = ActorRef::OrgUser(maya_id);

        let told = run(
            &use_case,
            sample_refresh_token_reused(tenant_id).with_actor(caller.clone()),
            AuditContext::for_caller(organization_id, caller),
        );

        let mut recipients = inboxes.org_recipients();
        recipients.sort_by_key(|id| *id.as_uuid());
        let mut expected = vec![olivia_id, adam_id];
        expected.sort_by_key(|id| *id.as_uuid());
        assert_eq!(told, 2);
        assert_eq!(recipients, expected);
    }
}
