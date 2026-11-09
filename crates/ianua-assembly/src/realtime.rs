//! What the live streams need: the port they subscribe through and the use
//! cases that admit a caller to a stream. How many streams each caller holds
//! and how long they last are the HTTP layer's own.
//!
//! Subscribing is not a use case: it only listens. Whether the caller may
//! listen is, so each stream asks one of the app's use cases first, and is
//! refused with its answer.

use std::sync::Arc;

use ianua_app::ports::realtime::NotificationSubscriber;
use ianua_app::use_cases::notifications::{
    OpenStreamPorts, OpenStreamUseCase, ReaderPorts, UnreadCountPorts, UnreadCountUseCase,
};
use ianua_app::use_cases::tenant::lifecycle::{
    GetTenantPorts, GetTenantUseCase, ListTenantsPorts, ListTenantsUseCase,
};

use crate::deps::Adapters;

/// The live streams' port and admissions.
#[derive(Clone)]
pub struct RealtimeState {
    /// Hands a socket the updates published for it.
    pub live: Arc<dyn NotificationSubscriber>,
    /// Admits a caller to their own notifications: it works out whose
    /// inbox they read, once their session or key still counts.
    pub inbox: Arc<UnreadCountUseCase>,
    /// Opens a caller's own notification feed, filtered to what they may
    /// see.
    pub open_inbox: Arc<OpenStreamUseCase>,
    /// The tenants a member sees, whose provisioning they may watch.
    pub tenants: Arc<ListTenantsUseCase>,
    /// Admits a member to one tenant's provisioning, when they may see it.
    pub tenant: Arc<GetTenantUseCase>,
}

/// Builds the live streams' state over `a`.
pub fn build(a: &Adapters) -> RealtimeState {
    RealtimeState {
        live: a.notification_subscriber.clone(),
        open_inbox: Arc::new(OpenStreamUseCase::new(OpenStreamPorts {
            subscriber: a.notification_subscriber.clone(),
            readers: readers(a),
        })),
        inbox: Arc::new(UnreadCountUseCase::new(UnreadCountPorts {
            platform_store: a.platform_notification_store.clone(),
            org_store: a.org_notification_store.clone(),
            tenant_store: a.tenant_notification_store.clone(),
            readers: readers(a),
        })),
        tenants: Arc::new(ListTenantsUseCase::new(ListTenantsPorts {
            tenant_store: a.tenant_store.clone(),
            setup_store: a.tenant_setup_store.clone(),
            org_actors: a.org_actors.clone(),
            operator_authorities: a.operator_authorities.clone(),
        })),
        tenant: Arc::new(GetTenantUseCase::new(GetTenantPorts {
            tenant_store: a.tenant_store.clone(),
            setup_store: a.tenant_setup_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            org_actors: a.org_actors.clone(),
            operator_authorities: a.operator_authorities.clone(),
        })),
    }
}

/// Resolves the platform, organization or tenant inbox a caller may read.
fn readers(a: &Adapters) -> ReaderPorts {
    ReaderPorts {
        tenant_authorities: a.tenant_authorities.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
    }
}
