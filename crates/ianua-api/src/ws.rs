//! WebSocket plumbing for live streams.
//!
//! Every streaming endpoint (`/ws/...`, a topic's live messages) is admitted
//! by its handler, then hands the upgraded socket to one of the `stream_*`
//! entry points here, so the bridge from a subscription to a socket is
//! written once. What each stream shows, and the watch that asks the app
//! again whether its caller may still read it, is an [`Admission`].

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use ianua_app::context::CallerContext;
use ianua_app::listing::Page;
use ianua_app::ports::realtime::{NotificationReceiver, NotificationSubscriber, RealtimeMessage};
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::messaging::broker::{StreamTopicRequest, StreamTopicUseCase};
use ianua_app::use_cases::messaging::caller::MessagingCaller;
use ianua_app::use_cases::notifications::{
    NotificationReader, NotificationStream, StreamNarrowing, StreamStanding, UnreadCountUseCase,
};
use ianua_app::use_cases::tenant::lifecycle::{
    GetTenantUseCase, ListTenantsUseCase, TenantLister, TenantRead, TenantViewer,
};
use ianua_app::use_cases::workflows::definitions::{
    GetWorkflowRequest, GetWorkflowUseCase, WhichVersion,
};
use ianua_app::use_cases::workflows::executions::GetUseCase;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::types::{TenantId, WorkflowExecutionId, WorkflowId};
use tokio::time::Instant;

use crate::dto::realtime::{RealtimeFrame, followed_tenants};

/// The close code sent when a stream's caller may no longer read it
/// (RFC 6455 "policy violation").
const NO_LONGER_ADMITTED: u16 = 1008;

/// How often a stream asks the app again whether its caller may still
/// read it, and how long it stays open at most.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamTiming {
    /// The longest a stream goes without asking again.
    pub(crate) recheck: Duration,
    /// The longest a stream stays open; the client then connects again and
    /// is admitted from scratch.
    pub(crate) lifetime: Duration,
}

/// What a stream may pass on: the messages it shows, and the watch that
/// asks the app again whether the caller may still read it.
pub(crate) struct Admission {
    filter: Filter,
    watch: Box<dyn Watch>,
}

/// Which messages of the subject a stream shows.
pub(crate) enum Filter {
    /// Every message on the subject.
    Everything,
    /// Only the setup updates of these tenants, as the caller saw them when
    /// the app was last asked.
    SetupsOf(HashSet<TenantId>),
}

impl Filter {
    /// The setup updates of the tenants on `page`.
    fn setups_of(page: &Page<TenantRead>) -> Self {
        Self::SetupsOf(page.items.iter().map(|read| *read.tenant.id()).collect())
    }
}

impl Admission {
    /// Every message on the subject, while `watch` still admits the
    /// caller.
    pub(crate) fn everything(watch: impl Watch + 'static) -> Self {
        Self {
            filter: Filter::Everything,
            watch: Box::new(watch),
        }
    }

    /// The setups of the tenants on `page`, the ones the caller sees, while
    /// `watch` still admits the caller.
    pub(crate) fn setups_of(page: &Page<TenantRead>, watch: impl Watch + 'static) -> Self {
        Self {
            filter: Filter::setups_of(page),
            watch: Box::new(watch),
        }
    }

    /// Asks the app again, and takes what it shows now. Gives whether the
    /// caller is still admitted.
    async fn renewed(&mut self) -> bool {
        let Some(filter) = self.watch.recheck().await else {
            return false;
        };
        self.filter = filter;
        true
    }

    /// Whether the filter shows `message`.
    fn shows(&self, message: &RealtimeMessage) -> bool {
        match &self.filter {
            Filter::Everything => true,
            Filter::SetupsOf(allowed) => message
                .setup_tenant()
                .is_some_and(|tenant| allowed.contains(tenant)),
        }
    }
}

/// Asks the app again whether a stream's caller may still read it, and
/// what it may show them now.
///
/// A stream stays open long after it was admitted: the caller's session can
/// end, their key be revoked or their access to a tenant or topic be taken
/// away meanwhile. So the app is asked again from time to time, the first
/// refusal closes the stream, and a narrower answer narrows what it shows.
#[async_trait::async_trait]
pub(crate) trait Watch: Send + Sync {
    /// What the stream may show the caller now, or `None` when they may no
    /// longer read it.
    async fn recheck(&self) -> Option<Filter>;
}

/// A caller watching their own notifications, admitted through their
/// inbox.
pub(crate) struct InboxWatch {
    use_case: Arc<UnreadCountUseCase>,
    reader: NotificationReader,
}

impl InboxWatch {
    /// `reader` watching their inbox, admitted through `use_case`.
    pub(crate) fn new(use_case: Arc<UnreadCountUseCase>, reader: NotificationReader) -> Self {
        Self { use_case, reader }
    }
}

#[async_trait::async_trait]
impl Watch for InboxWatch {
    async fn recheck(&self) -> Option<Filter> {
        let admitted = self.use_case.execute(&self.reader, ()).await.is_ok();
        admitted.then_some(Filter::Everything)
    }
}

/// A caller watching their own notifications through the feed the app
/// opened for them. Asked again, the feed narrows to the categories they
/// may still see, and the stream closes once nothing is left or they may
/// no longer read it.
pub(crate) struct FeedWatch {
    narrowing: StreamNarrowing,
    reader: NotificationReader,
}

impl FeedWatch {
    /// `reader` watching `stream`, the feed the app opened for them.
    pub(crate) fn new(stream: &NotificationStream, reader: NotificationReader) -> Self {
        Self {
            narrowing: stream.narrowing(),
            reader,
        }
    }
}

#[async_trait::async_trait]
impl Watch for FeedWatch {
    async fn recheck(&self) -> Option<Filter> {
        match self.narrowing.recheck(&self.reader).await {
            StreamStanding::Open => Some(Filter::Everything),
            StreamStanding::Closed => None,
        }
    }
}

/// A member watching the provisioning of the tenants they see.
pub(crate) struct TenantsWatch {
    use_case: Arc<ListTenantsUseCase>,
    lister: TenantLister,
}

impl TenantsWatch {
    /// `lister` watching the tenants they see, admitted through `use_case`.
    pub(crate) fn new(use_case: Arc<ListTenantsUseCase>, lister: TenantLister) -> Self {
        Self { use_case, lister }
    }
}

#[async_trait::async_trait]
impl Watch for TenantsWatch {
    async fn recheck(&self) -> Option<Filter> {
        let seen = self
            .use_case
            .execute(&self.lister, followed_tenants())
            .await
            .ok()?;
        Some(Filter::setups_of(&seen))
    }
}

/// A member watching one tenant's provisioning.
pub(crate) struct TenantWatch {
    use_case: Arc<GetTenantUseCase>,
    viewer: TenantViewer,
}

impl TenantWatch {
    /// `viewer` watching one tenant, admitted through `use_case`.
    pub(crate) fn new(use_case: Arc<GetTenantUseCase>, viewer: TenantViewer) -> Self {
        Self { use_case, viewer }
    }
}

#[async_trait::async_trait]
impl Watch for TenantWatch {
    async fn recheck(&self) -> Option<Filter> {
        let admitted = self.use_case.execute(&self.viewer, ()).await.is_ok();
        admitted.then_some(Filter::Everything)
    }
}

/// A caller watching a topic, while the app still admits them to it: the
/// topic's class can be raised, the topic paused, or the session ended.
pub(crate) struct TopicWatch {
    use_case: Arc<StreamTopicUseCase>,
    caller: MessagingCaller,
    topic: TopicName,
}

impl TopicWatch {
    /// `caller` watching `topic`, admitted through `use_case`.
    pub(crate) fn new(
        use_case: Arc<StreamTopicUseCase>,
        caller: MessagingCaller,
        topic: TopicName,
    ) -> Self {
        Self {
            use_case,
            caller,
            topic,
        }
    }
}

#[async_trait::async_trait]
impl Watch for TopicWatch {
    async fn recheck(&self) -> Option<Filter> {
        let request = StreamTopicRequest {
            topic_name: self.topic.clone(),
        };
        let admitted = self.use_case.execute(&self.caller, request).await.is_ok();
        admitted.then_some(Filter::Everything)
    }
}

/// A caller watching one workflow run, while the app still lets them read
/// it: their right to view workflows can be taken away, or their session
/// ended.
pub(crate) struct ExecutionWatch {
    use_case: Arc<GetUseCase>,
    caller: CallerContext,
    execution_id: WorkflowExecutionId,
}

impl ExecutionWatch {
    /// `caller` watching `execution_id`, admitted through `use_case`.
    pub(crate) fn new(
        use_case: Arc<GetUseCase>,
        caller: CallerContext,
        execution_id: WorkflowExecutionId,
    ) -> Self {
        Self {
            use_case,
            caller,
            execution_id,
        }
    }
}

#[async_trait::async_trait]
impl Watch for ExecutionWatch {
    async fn recheck(&self) -> Option<Filter> {
        let admitted = self
            .use_case
            .execute(&self.caller, self.execution_id)
            .await
            .is_ok();
        admitted.then_some(Filter::Everything)
    }
}

/// A caller with a workflow's draft open, while the app still lets them
/// read the workflow.
pub(crate) struct DraftWatch {
    use_case: Arc<GetWorkflowUseCase>,
    caller: CallerContext,
    workflow_id: WorkflowId,
}

impl DraftWatch {
    /// `caller` watching `workflow_id`'s draft, admitted through
    /// `use_case`.
    pub(crate) fn new(
        use_case: Arc<GetWorkflowUseCase>,
        caller: CallerContext,
        workflow_id: WorkflowId,
    ) -> Self {
        Self {
            use_case,
            caller,
            workflow_id,
        }
    }
}

#[async_trait::async_trait]
impl Watch for DraftWatch {
    async fn recheck(&self) -> Option<Filter> {
        let request = GetWorkflowRequest {
            workflow_id: self.workflow_id,
            version: WhichVersion::Latest,
        };
        let admitted = self.use_case.execute(&self.caller, request).await.is_ok();
        admitted.then_some(Filter::Everything)
    }
}

/// The subscriber and subject from which a live stream receives its updates.
pub(crate) struct SubjectSubscription {
    /// Opens the notification feed after the WebSocket is connected.
    subscriber: Arc<dyn NotificationSubscriber>,
    /// Identifies the feed and appears in the initial connected frame.
    subject: String,
}

impl SubjectSubscription {
    /// Pairs the selected feed with the subscriber that opens it after upgrade.
    pub(crate) fn new(subscriber: Arc<dyn NotificationSubscriber>, subject: String) -> Self {
        Self {
            subscriber,
            subject,
        }
    }
}

/// Streams a subject to the client, after a `{ "type": "connected",
/// "subject" }` frame, passing on what `admission` lets through.
pub(crate) async fn stream_subject(
    mut socket: WebSocket,
    subscription: SubjectSubscription,
    mut admission: Admission,
    timing: StreamTiming,
) {
    send_connected(&mut socket, &subscription.subject).await;
    let Ok(receiver) = subscription
        .subscriber
        .subscribe_dashboard(&subscription.subject)
        .await
    else {
        return;
    };
    forward(&mut socket, receiver, &mut admission, timing).await;
}

/// Streams a caller's own notifications to the client: the feed the app
/// opened for them, which already drops what they may not see.
pub(crate) async fn stream_inbox(
    mut socket: WebSocket,
    stream: NotificationStream,
    mut admission: Admission,
    timing: StreamTiming,
) {
    let receiver = Box::new(InboxFeed(stream));
    forward(&mut socket, receiver, &mut admission, timing).await;
}

/// The app's filtered notification feed, read as any other subscription.
struct InboxFeed(NotificationStream);

#[async_trait::async_trait]
impl NotificationReceiver for InboxFeed {
    async fn recv(&mut self) -> Option<RealtimeMessage> {
        self.0.next_update().await
    }
}

/// Forwards what `admission` shows as JSON text frames, until the client
/// leaves, the subscription ends, the caller is no longer admitted, or the
/// stream has lasted its lifetime.
///
/// The app is asked again whenever `timing.recheck` has passed since the
/// last answer: before the next message, or on a tick for a quiet stream.
async fn forward(
    socket: &mut WebSocket,
    mut receiver: Box<dyn NotificationReceiver>,
    admission: &mut Admission,
    timing: StreamTiming,
) {
    let ends = tokio::time::sleep(timing.lifetime);
    tokio::pin!(ends);
    let mut ticks = tokio::time::interval_at(Instant::now() + timing.recheck, timing.recheck);
    let mut recheck = Recheck::new(timing.recheck);
    loop {
        tokio::select! {
            () = &mut ends => {
                close_refused(socket).await;
                break;
            }
            _ = ticks.tick() => {
                if !still_admitted(socket, admission, &mut recheck).await {
                    break;
                }
            }
            message = receiver.recv() => {
                let Some(message) = message else { break };
                if !forward_message(socket, &message, admission, &mut recheck).await {
                    break;
                }
            }
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                _ => {}
            },
        }
    }
}

/// Asks the app again whether the caller is still admitted, closing the
/// socket as refused when not.
async fn still_admitted(
    socket: &mut WebSocket,
    admission: &mut Admission,
    recheck: &mut Recheck,
) -> bool {
    recheck.checked = Instant::now();
    if admission.renewed().await {
        return true;
    }
    close_refused(socket).await;
    false
}

/// Tracks the last admission check so a busy subscription cannot defer it.
struct Recheck {
    checked: Instant,
    interval: Duration,
}

impl Recheck {
    /// Starts the periodic admission clock when forwarding begins.
    fn new(interval: Duration) -> Self {
        Self {
            checked: Instant::now(),
            interval,
        }
    }

    /// Renews admission once the interval has passed, retaining its last check time.
    async fn renew_if_due(&mut self, admission: &mut Admission) -> bool {
        if self.checked.elapsed() < self.interval {
            return true;
        }
        self.checked = Instant::now();
        admission.renewed().await
    }
}

/// Rechecks an overdue admission before forwarding an allowed update.
async fn forward_message(
    socket: &mut WebSocket,
    message: &RealtimeMessage,
    admission: &mut Admission,
    recheck: &mut Recheck,
) -> bool {
    if !recheck.renew_if_due(admission).await {
        close_refused(socket).await;
        return false;
    }
    !admission.shows(message) || send_frame(socket, message).await
}

/// Sends one update as JSON. `false` when the client is gone.
async fn send_frame(socket: &mut WebSocket, message: &RealtimeMessage) -> bool {
    let Ok(json) = serde_json::to_string(&RealtimeFrame::from(message)) else {
        return true;
    };
    socket.send(Message::Text(json.into())).await.is_ok()
}

/// Closes the socket because the caller may no longer read the stream.
async fn close_refused(socket: &mut WebSocket) {
    let frame = CloseFrame {
        code: NO_LONGER_ADMITTED,
        reason: "no longer admitted".into(),
    };
    let _ = socket.send(Message::Close(Some(frame))).await;
}

/// Sends the `connected` frame naming the stream's `subject`.
async fn send_connected(socket: &mut WebSocket, subject: &str) {
    let connected = serde_json::json!({
        "type": "connected",
        "subject": subject,
    });
    let _ = socket
        .send(Message::Text(connected.to_string().into()))
        .await;
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::provisioning::{SetupProgress, StepOutcome};
    use ianua_app::test_support::acting::{
        ChangingTenantAuthorities, FakeOperatorAuthorities, FakeOrgActors, FakeTenantAuthorities,
        Refusal,
    };
    use ianua_app::test_support::operator::test_operator_caller;
    use ianua_app::test_support::{block_on, test_ctx, test_org_caller};
    use ianua_app::use_cases::notifications::{
        OpenStreamPorts, OpenStreamUseCase, ReaderPorts, UnreadCountPorts,
    };
    use ianua_app::use_cases::tenant::lifecycle::ListTenantsPorts;
    use ianua_domain::domains::tenant::setup::SetupStep;
    use ianua_domain::shared::model::steps::RunOutcome;
    use ianua_domain::types::OrganizationId;

    use super::*;

    /// An inbox watch over operators that `authorities` admits.
    fn operator_inbox(authorities: FakeOperatorAuthorities) -> InboxWatch {
        let mut ports = UnreadCountPorts::fakes();
        ports.readers.operator_authorities = Arc::new(authorities);
        InboxWatch::new(
            Arc::new(UnreadCountUseCase::new(ports)),
            NotificationReader::Operator(test_operator_caller()),
        )
    }

    /// Olga's key still counts: her dashboard stream goes on.
    #[test]
    fn an_operator_who_still_counts_stays_admitted() {
        let watch = operator_inbox(FakeOperatorAuthorities::admitting());

        assert!(block_on(watch.recheck()).is_some());
    }

    /// A signed-out operator loses dashboard admission on the next recheck.
    #[test]
    fn a_revoked_operator_is_let_go_of() {
        let watch = operator_inbox(FakeOperatorAuthorities::refusing(Refusal::SignedOut));

        assert!(block_on(watch.recheck()).is_none());
    }

    /// Every right Sam saw other people's notifications through is taken
    /// away while his tenant feed is open. The stream stays open: notices
    /// about his own account, such as a lock or a factor reset, still reach
    /// him whatever he holds.
    #[test]
    fn a_tenant_feed_keeps_the_readers_own_account_notices() {
        let authorities = Arc::new(ChangingTenantAuthorities::starting(
            FakeTenantAuthorities::holding_everything(),
        ));
        let ports = OpenStreamPorts {
            readers: ReaderPorts {
                tenant_authorities: authorities.clone(),
                ..ReaderPorts::fakes()
            },
            ..OpenStreamPorts::fakes()
        };
        let reader = NotificationReader::Tenant(test_ctx());
        let stream = block_on(OpenStreamUseCase::new(ports).execute(&reader, ())).unwrap();
        let watch = FeedWatch::new(&stream, reader);
        authorities.change_to(FakeTenantAuthorities::holding(&[]));

        assert!(block_on(watch.recheck()).is_some());
    }

    /// Revoked organization authority ends the member's stream admission.
    #[test]
    fn a_member_removed_from_the_organization_is_let_go_of() {
        let watch = TenantsWatch::new(
            Arc::new(ListTenantsUseCase::new(ListTenantsPorts {
                org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
                ..ListTenantsPorts::fakes()
            })),
            TenantLister::Member(test_org_caller()),
        );

        assert!(block_on(watch.recheck()).is_none());
    }

    /// A setup update about `tenant`.
    fn progress_of(tenant: TenantId) -> RealtimeMessage {
        RealtimeMessage::SetupProgress(SetupProgress {
            tenant_id: tenant,
            organization_id: OrganizationId::new(),
            step: SetupStep::SigningKey,
            step_outcome: StepOutcome::Done,
            done_steps: 1,
            total_steps: 3,
            setup: RunOutcome::Running,
            failure_reason: None,
        })
    }

    /// Rechecking admission removes an inaccessible tenant while retaining
    /// access to the other tenant's progress.
    #[test]
    fn a_tenant_taken_away_drops_out_of_the_stream() {
        let tenant = TenantId::new();
        let mut admission = Admission {
            filter: Filter::SetupsOf(HashSet::from([tenant])),
            watch: Box::new(TenantsWatch::new(
                Arc::new(ListTenantsUseCase::new(ListTenantsPorts::fakes())),
                TenantLister::Member(test_org_caller()),
            )),
        };
        assert!(admission.shows(&progress_of(tenant)));

        let admitted = block_on(admission.renewed());

        assert!(admitted);
        assert!(!admission.shows(&progress_of(tenant)));
    }
}
