//! Plan back-channel logout: a recorded sign-out becomes one logout job
//! per app the person signed in to through the ended session that takes
//! logout at its server, keyed by the event and the app, so a repeated
//! delivery of the event plans nothing twice.
//!
//! A session's revocation is the sign-out: a logout, an administrator, a
//! stolen token or a locked account each ends the person's sessions one
//! by one, and each revocation is told to the apps it reached.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::grants::logout_notice::SignedOut;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::data::{FieldValue, RefKind};
use ianua_domain::types::event_type::{AuthenticationEvent, EventType};
use ianua_domain::types::{ActorRef, OAuthClientId, SessionId, UserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::{AuthCodeStore, ConsentedSession, OAuthClientStore};
use crate::ports::shared::PublishedEvent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::flows::logout::back_channel_job::LogoutJobs;
use crate::use_cases::oauth::flows::logout::receivers::{distinct_clients, notices_for};
use crate::use_cases::scheduling::PlanReport;

/// The ports [`PlanBackChannelUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PlanBackChannelPorts {
    /// Where codes are kept, to find the apps the person signed in to.
    pub auth_code_store: Arc<dyn AuthCodeStore>,
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Where logout jobs are queued.
    pub jobs: LogoutJobs,
}

/// Plans the back-channel logouts a recorded sign-out means.
///
/// The event pipeline runs it, for nobody, so its caller is `()`.
pub struct PlanBackChannelUseCase {
    ports: PlanBackChannelPorts,
}

impl PlanBackChannelUseCase {
    /// A planner over `ports`.
    #[must_use]
    pub fn new(ports: PlanBackChannelPorts) -> Self {
        Self { ports }
    }

    /// The apps of `tenant` that hear of `signed_out` over the back
    /// channel.
    async fn told_apps(
        &self,
        tenant: &ScopedTenant,
        signed_out: SignedOut,
    ) -> Result<Vec<OAuthClientId>, AppError> {
        let mut signed_into = self
            .ports
            .auth_code_store
            .consented_sessions(tenant, signed_out)
            .await
            .or_internal()?;
        if let SignedOut::Session { session, .. } = signed_out {
            signed_into.retain(|pair| pair.session == session);
        }
        let ids = distinct_clients(&signed_into);
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let clients = self
            .ports
            .client_store
            .find_by_ids(tenant, &ids)
            .await
            .or_internal()?;
        let clients: HashMap<_, _> = clients
            .iter()
            .map(|client| (*client.id(), client))
            .collect();
        Ok(ids
            .into_iter()
            .filter(|id| hears(clients.get(id).copied(), signed_out, &signed_into))
            .collect())
    }
}

impl Command for PlanBackChannelUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<PlanReport, AppError>;

    /// Queues one logout job for each active app that takes back-channel
    /// logout and that the person reached through the revoked session. Any
    /// event but a session's revocation plans nothing. Records nothing:
    /// planning only queues work, and each posting is recorded when made.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the apps or the sessions cannot be read,
    ///   or a job cannot be queued. The pipeline delivers the event again,
    ///   and what was queued is not queued twice.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<PlanReport, AppError> {
        let record = event.record();
        let (Some(tenant_id), Some(signed_out)) =
            (record.scope.tenant_id().copied(), signed_out_of(&record))
        else {
            return Ok(PlanReport::default());
        };
        let tenant = ScopedTenant::for_background(tenant_id);
        let mut report = PlanReport::default();
        for client_id in self.told_apps(&tenant, signed_out).await? {
            let enqueued = self
                .ports
                .jobs
                .queue(event.id, tenant_id, client_id, signed_out)
                .await?;
            report = report.counting(enqueued);
        }
        Ok(report)
    }
}

/// Whether `client` hears of `signed_out`: it is there, active, and sent at
/// least one logout token for it.
fn hears(
    client: Option<&OAuthClient<ResolvedTenant>>,
    signed_out: SignedOut,
    signed_into: &[ConsentedSession],
) -> bool {
    client
        .filter(|client| client.is_active())
        .is_some_and(|client| !notices_for(client, signed_out, signed_into).is_empty())
}

/// The sign-out `record` is, when it is a session's revocation: the
/// session it names, of the user it names or who revoked it themselves.
fn signed_out_of(record: &AuditRecord) -> Option<SignedOut> {
    let EventType::Authentication(AuthenticationEvent::SessionRevoked) = record.event_type else {
        return None;
    };
    let session = record.payload.get("session_id")?;
    let session = uuid::Uuid::parse_str(session)
        .ok()
        .map(SessionId::from_uuid)?;
    let person = named_user(record).or(match record.actor {
        ActorRef::User(user) => Some(user),
        _ => None,
    })?;
    Some(SignedOut::Session { person, session })
}

/// The user `record`'s payload names under `user`, when someone else
/// revoked their session.
fn named_user(record: &AuditRecord) -> Option<UserId> {
    let FieldValue::Reference(reference) = record.payload.value("user")? else {
        return None;
    };
    if reference.kind() != RefKind::USER {
        return None;
    }
    uuid::Uuid::parse_str(reference.id())
        .ok()
        .map(UserId::from_uuid)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::clients::settings::{ChannelLogout, SessionRequired};
    use ianua_domain::domains::oauth::grants::authorization_code::AuthorizationCode;
    use ianua_domain::test_support::events::{sample_session_revoked, sample_tenant_event};
    use ianua_domain::types::{AuditRecordId, HttpsUrl};

    use super::*;
    use crate::test_support::oauth::{
        FakeAuthCodeStore, FakeOAuthClientStore, client_with, code_row, hash_of, stored_client,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_session_id,
    };
    use crate::use_cases::oauth::flows::logout::back_channel_job::BACK_CHANNEL_LOGOUT_JOB;

    struct Setup {
        uc: PlanBackChannelUseCase,
        queue: Arc<FakeJobQueue>,
        ann: UserId,
        codes: Arc<FakeAuthCodeStore>,
        clients: Arc<FakeOAuthClientStore>,
    }

    /// Ann signed in to `app` through the test session.
    fn signed_in_to(app: OAuthClient<ResolvedTenant>) -> Setup {
        let ann = UserId::new();
        let tenant = test_ctx().tenant();
        let codes = Arc::new(FakeAuthCodeStore::empty());
        let code = AuthorizationCode::reconstitute(code_row(&app, ann)).unwrap();
        block_on(codes.save(&tenant, &code)).unwrap();
        let queue = Arc::new(FakeJobQueue::new());
        let clients = Arc::new(FakeOAuthClientStore::holding(&tenant, app));
        let uc = PlanBackChannelUseCase::new(PlanBackChannelPorts {
            auth_code_store: codes.clone(),
            client_store: clients.clone(),
            jobs: LogoutJobs {
                queue: queue.clone(),
                attempts: NonZeroU32::new(5).unwrap(),
            },
        });
        Setup {
            uc,
            queue,
            ann,
            codes,
            clients,
        }
    }

    /// An app taking back-channel logout at its server.
    fn listening_app() -> OAuthClient<ResolvedTenant> {
        client_with("Portal", &[GrantType::AuthorizationCode], |row| {
            row.settings.logout.back_channel = ChannelLogout::At {
                uri: HttpsUrl::new("https://app.example.com/backchannel").unwrap(),
                session: SessionRequired::Required,
            };
        })
    }

    /// Ann's test session was revoked, recorded under `id`.
    fn revoked(setup: &Setup, id: AuditRecordId) -> PublishedEvent {
        PublishedEvent {
            id,
            event: sample_session_revoked(test_ctx().tenant_id(), setup.ann, test_session_id()),
            context: AuditContext::system(),
        }
    }

    fn plan(setup: &Setup, event: PublishedEvent) -> PlanReport {
        block_on(setup.uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            event,
        ))
        .unwrap()
    }

    /// An admin revokes Ann's session, which she used the portal through.
    /// One job is queued to tell the portal.
    #[test]
    fn an_app_reached_through_the_session_gets_one_job() {
        let setup = signed_in_to(listening_app());

        let report = plan(&setup, revoked(&setup, AuditRecordId::new()));

        assert_eq!(report.queued, 1);
        assert_eq!(setup.queue.jobs_of(BACK_CHANNEL_LOGOUT_JOB).len(), 1);
    }

    /// Two apps reached through the ended session each get a job, but
    /// their client records are loaded together.
    #[test]
    fn logout_planning_reads_the_clients_together() {
        let setup = signed_in_to(listening_app());
        let second = listening_app();
        let tenant = test_ctx().tenant();
        block_on(setup.clients.save(&tenant, &second)).unwrap();
        let mut row = code_row(&second, setup.ann);
        row.code_hash = hash_of("second logout code");
        block_on(
            setup
                .codes
                .save(&tenant, &AuthorizationCode::reconstitute(row).unwrap()),
        )
        .unwrap();

        let report = plan(&setup, revoked(&setup, AuditRecordId::new()));

        assert_eq!(report.queued, 2);
        assert_eq!(setup.clients.id_reads().len(), 1);
    }

    /// The pipeline delivers the revocation twice. The second planning
    /// queues nothing.
    #[test]
    fn a_repeated_event_plans_nothing_twice() {
        let setup = signed_in_to(listening_app());
        let id = AuditRecordId::new();

        plan(&setup, revoked(&setup, id));
        let second = plan(&setup, revoked(&setup, id));

        assert_eq!((second.queued, second.already_queued), (0, 1));
    }

    /// An app with no back-channel address gets no job.
    #[test]
    fn an_app_without_a_back_channel_gets_no_job() {
        let setup = signed_in_to(stored_client("Portal", &[GrantType::AuthorizationCode]));

        let report = plan(&setup, revoked(&setup, AuditRecordId::new()));

        assert_eq!(report.queued, 0);
    }

    /// A topic was paused: no sign-out, nothing planned.
    #[test]
    fn an_event_that_is_no_sign_out_plans_nothing() {
        let setup = signed_in_to(listening_app());
        let event = PublishedEvent {
            id: AuditRecordId::new(),
            event: sample_tenant_event(test_ctx().tenant_id()),
            context: AuditContext::system(),
        };

        assert_eq!(plan(&setup, event), PlanReport::default());
    }
}
