//! The activity use cases the API serves: the contribution calendar of an
//! organization or a tenant.

use std::sync::Arc;

use ianua_app::use_cases::activity::{GetCalendarPorts, GetCalendarUseCase};

use crate::deps::Adapters;

/// The activity use cases.
#[derive(Clone)]
pub struct ActivityState {
    pub calendar: Arc<GetCalendarUseCase>,
}

/// Builds the activity use cases over `a`.
pub fn build(a: &Adapters) -> ActivityState {
    ActivityState {
        calendar: Arc::new(GetCalendarUseCase::new(GetCalendarPorts {
            activity: a.activity_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            org_actors: a.org_actors.clone(),
            tenant_grants: a.org_tenant_grant_store.clone(),
        })),
    }
}
