//! Every sink's planner: notification fan-out, webhooks, signals,
//! back-channel logout, audit streams, message pushes, workflow starts on
//! an event, live updates of workflow runs and drafts, checks of the
//! workflows an account that changed still serves, and tenants' setups and
//! teardowns.
//!
//! Each planner but the fan-out reads tenants' events alone: each answers
//! an event of no tenant with nothing to do, so hearing the organizations'
//! and the platform's would only hand it work to throw away.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_app::use_cases::audit::{PlanStreamsPorts, PlanStreamsUseCase, StreamJobs};
use ianua_app::use_cases::messaging::broker::{PlanPushesPorts, PlanPushesUseCase, PushJobs};
use ianua_app::use_cases::notifications::{
    AudiencePorts, DeliveryPorts, FanOutPorts, FanOutUseCase, InboxPorts, PreferencePorts,
};
use ianua_app::use_cases::oauth::flows::{
    LogoutJobs, PlanBackChannelPorts, PlanBackChannelUseCase,
};
use ianua_app::use_cases::signals::delivery as signals;
use ianua_app::use_cases::tenant::{setup, teardown};
use ianua_app::use_cases::webhooks::delivery as webhooks;
use ianua_app::use_cases::workflows::executions::{
    EventStarts, PlanEventStartsPorts, PlanEventStartsUseCase, PublishLivePorts, PublishLiveUseCase,
};
use ianua_app::use_cases::workflows::published::holds::{
    AccountChecks, PlanAccountChecksPorts, PlanAccountChecksUseCase,
};
use ianua_domain::shared::config::DomainLimits;
use ianua_infra::bus::BusNotificationPublisher;
use ianua_infra::cache::CacheAlertThrottle;
use ianua_infra::http::HttpWebhookBodies;
use ianua_infra::postgres::audit::PgAuditStreamStore;
use ianua_infra::postgres::identity::PgUserStore;
use ianua_infra::postgres::messaging::PgSubscriptionStore;
use ianua_infra::postgres::notifications::{
    PgMemberPreferenceStore, PgNotificationDestinationStore, PgNotificationPreferenceStore,
    PgOperatorPreferenceStore, PgOrgNotificationStore, PgPlatformNotificationStore,
    PgTenantNotificationStore,
};
use ianua_infra::postgres::oauth::{PgAuthCodeStore, PgOAuthClientStore};
use ianua_infra::postgres::operator::PgOperatorStore;
use ianua_infra::postgres::organization::{PgOrgUserStore, PgTenantMemberRoster};
use ianua_infra::postgres::signals::{PgSignalStreamStore, PgSuspendedAgents};
use ianua_infra::postgres::tenant::{PgTenantSetupStore, PgTenantTeardownStore};
use ianua_infra::postgres::webhooks::PgWebhookStore;
use ianua_infra::postgres::workflows::{PgWorkflowExecutionStore, PgWorkflowStore};

use crate::worker::consumers::{Hears, Planned, Planner, Told};
use crate::worker::parts::Parts;

/// The most agents a tenant-wide stop of its agents is signalled for, one
/// signal each: past it the rest are not signalled, so one stop cannot
/// queue jobs without bound.
const FLEET_SIGNALS: NonZeroU32 = NonZeroU32::MIN.saturating_add(999);

/// Every planner, one for each sink.
pub(super) fn planners(parts: &Parts<'_>) -> Vec<Arc<dyn Planner>> {
    vec![
        notifications(parts),
        webhook_deliveries(parts),
        signal_dispatches(parts),
        back_channel_logout(parts),
        audit_streams(parts),
        message_pushes(parts),
        workflow_starts(parts),
        workflow_live(parts),
        account_checks(parts),
        tenant_setup(parts),
        tenant_teardown(parts),
    ]
}

/// The fan-out telling the people who run a plane about its events, by
/// their inbox, their dashboard, mail and their organization's
/// destinations.
fn notifications(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let ports = FanOutPorts {
        tenants: Arc::clone(&parts.tenants),
        inboxes: InboxPorts {
            platform_store: Arc::new(PgPlatformNotificationStore::new(Arc::clone(databases))),
            org_store: Arc::new(PgOrgNotificationStore::new(Arc::clone(databases))),
            tenant_store: Arc::new(PgTenantNotificationStore::new(Arc::clone(databases))),
            publisher: Arc::new(BusNotificationPublisher::new(
                Arc::clone(&platform.bus),
                platform.keys.broadcast_seal.clone(),
            )),
        },
        outward: DeliveryPorts {
            mailer: Arc::clone(&parts.mail.mailer),
            destinations: Arc::new(PgNotificationDestinationStore::new(Arc::clone(databases))),
            jobs: Arc::clone(&parts.jobs),
            alert_throttle: Arc::new(CacheAlertThrottle::new(Arc::clone(&platform.shared_state))),
        },
        preferences: PreferencePorts {
            preference_store: Arc::new(PgNotificationPreferenceStore::new(Arc::clone(databases))),
            member_preferences: Arc::new(PgMemberPreferenceStore::new(Arc::clone(databases))),
            operator_preferences: Arc::new(PgOperatorPreferenceStore::new(Arc::clone(databases))),
        },
        audience: notification_audience(parts),
    };
    let most = u32::try_from(parts.config.limits.notification_max_fanout).unwrap_or(u32::MAX);
    Told::of(FanOutUseCase::new(ports, most))
}

/// Resolves notification recipients from account standing, memberships and workflow actors.
fn notification_audience(parts: &Parts<'_>) -> AudiencePorts {
    let platform = parts.platform;
    let databases = &platform.databases;
    AudiencePorts {
        operator_store: Arc::new(PgOperatorStore::new(Arc::clone(databases))),
        org_user_store: Arc::new(PgOrgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        user_store: Arc::new(PgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        access_records: Arc::clone(&platform.access_records),
        organizations: Arc::clone(&parts.organizations),
        member_roster: Arc::new(PgTenantMemberRoster::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        executions: Arc::new(PgWorkflowExecutionStore::new(Arc::clone(databases))),
    }
}

/// The deliveries of a tenant's events to its webhook subscriptions.
fn webhook_deliveries(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let platform = parts.platform;
    let use_case = webhooks::PlanUseCase::new(webhooks::PlanPorts {
        webhook_store: Arc::new(PgWebhookStore::new(Arc::clone(&platform.databases))),
        bodies: Arc::new(HttpWebhookBodies),
        jobs: webhooks::WebhookJobs {
            queue: Arc::clone(&parts.jobs),
        },
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    Planned::of("webhooks", Hears::Tenants, use_case)
}

/// The security signals a tenant's events mean, for its signal streams.
fn signal_dispatches(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let use_case = signals::PlanUseCase::new(
        signals::PlanPorts {
            stream_store: Arc::new(PgSignalStreamStore::new(Arc::clone(databases))),
            suspended_agents: Arc::new(PgSuspendedAgents::new(Arc::clone(databases))),
            access_records: Arc::clone(&platform.access_records),
            jobs: signals::SignalJobs {
                queue: Arc::clone(&parts.jobs),
                attempts: parts.attempts,
            },
        },
        FLEET_SIGNALS,
    );
    Planned::of("signals", Hears::Tenants, use_case)
}

/// The logout notices a revoked session owes the apps it signed in to.
fn back_channel_logout(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let databases = &parts.platform.databases;
    let use_case = PlanBackChannelUseCase::new(PlanBackChannelPorts {
        auth_code_store: Arc::new(PgAuthCodeStore::new(Arc::clone(databases))),
        client_store: Arc::new(PgOAuthClientStore::new(Arc::clone(databases))),
        jobs: LogoutJobs {
            queue: Arc::clone(&parts.jobs),
            attempts: parts.attempts,
        },
    });
    Planned::of("back_channel_logout", Hears::Tenants, use_case)
}

/// The records a tenant's audit streams send to its SIEM.
fn audit_streams(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let use_case = PlanStreamsUseCase::new(PlanStreamsPorts {
        stream_store: Arc::new(PgAuditStreamStore::new(Arc::clone(
            &parts.platform.databases,
        ))),
        jobs: StreamJobs {
            queue: Arc::clone(&parts.jobs),
            attempts: parts.attempts,
        },
    });
    Planned::of("audit_streams", Hears::Tenants, use_case)
}

/// The pushes of messages published on a topic to its push subscriptions.
fn message_pushes(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let use_case = PlanPushesUseCase::new(PlanPushesPorts {
        subscription_store: Arc::new(PgSubscriptionStore::new(Arc::clone(
            &parts.platform.databases,
        ))),
        jobs: PushJobs {
            queue: Arc::clone(&parts.jobs),
            attempts: parts.attempts,
        },
    });
    Planned::of("message_pushes", Hears::Tenants, use_case)
}

/// What happens in workflow runs, and changes to drafts, pushed to whoever
/// watches them in the builder.
fn workflow_live(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let platform = parts.platform;
    let use_case = PublishLiveUseCase::new(PublishLivePorts {
        publisher: Arc::new(BusNotificationPublisher::new(
            Arc::clone(&platform.bus),
            platform.keys.broadcast_seal.clone(),
        )),
    });
    Planned::of("workflow_live", Hears::Tenants, use_case)
}

/// The workflow versions in service that start on a tenant's event.
fn workflow_starts(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let use_case = PlanEventStartsUseCase::new(PlanEventStartsPorts {
        workflows: Arc::new(PgWorkflowStore::new(Arc::clone(&parts.platform.databases))),
        jobs: EventStarts {
            queue: Arc::clone(&parts.jobs),
            attempts: parts.attempts,
        },
    });
    Planned::of("workflow_starts", Hears::Tenants, use_case)
}

/// The checks of the versions in service an account that was switched off
/// or narrowed still serves.
fn account_checks(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let use_case = PlanAccountChecksUseCase::new(PlanAccountChecksPorts {
        jobs: AccountChecks {
            queue: Arc::clone(&parts.jobs),
            attempts: parts.attempts,
        },
    });
    Planned::of("workflow_account_checks", Hears::Tenants, use_case)
}

/// The setup a tenant announced as provisioned begins.
fn tenant_setup(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let use_case = setup::PlanUseCase::new(setup::PlanPorts {
        setups: Arc::new(PgTenantSetupStore::new(Arc::clone(
            &parts.platform.databases,
        ))),
        tenants: Arc::clone(&parts.tenants),
        steps: setup::SetupSteps::new(
            setup::SETUP_STEP_JOB,
            Arc::clone(&parts.jobs),
            parts.attempts,
        ),
    });
    Planned::of("tenant_setup", Hears::Tenants, use_case)
}

/// The teardown a deleted tenant begins.
fn tenant_teardown(parts: &Parts<'_>) -> Arc<dyn Planner> {
    let use_case = teardown::PlanUseCase::new(teardown::PlanPorts {
        teardowns: Arc::new(PgTenantTeardownStore::new(Arc::clone(
            &parts.platform.databases,
        ))),
        tenants: Arc::clone(&parts.tenants),
        steps: teardown::TeardownSteps::new(
            teardown::TEARDOWN_STEP_JOB,
            Arc::clone(&parts.jobs),
            parts.attempts,
        ),
    });
    Planned::of("tenant_teardown", Hears::Tenants, use_case)
}
