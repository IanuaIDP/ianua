//! Who is signed in to the organization right now, placed on a map.

use std::sync::Arc;

use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::permission::{OrgPermission, OrgSessionAction};
use ianua_domain::types::{Fact, IpAddress, SessionId};
use time::OffsetDateTime;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::authentication::Geolocator;
use crate::ports::organization::{OrgSessionSortField, OrgSessionStore};
use crate::use_case::Query;

/// A single active session, with where its address was placed.
pub struct ActiveSessionInfo {
    /// The existing sign-in whose activity and location are shown.
    pub session_id: SessionId,
    /// The address it signed in from, if known.
    pub ip_address: Option<IpAddress>,
    /// Where that address is, when it could be placed.
    pub geo: Option<IpGeolocation>,
    /// When the session was opened.
    pub created_at: OffsetDateTime,
}

/// Which page of the active sessions to return, in what order.
pub struct ListActiveSessionsRequest {
    /// The fields and directions to order by.
    pub sort: SortOrder<OrgSessionSortField>,
    /// Which page of the ordered sessions to return.
    pub page: PageRequest,
}

/// The ports [`ListActiveSessionsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListActiveSessionsPorts {
    /// Members' sessions.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// Places a session's address.
    pub geolocator: Arc<dyn Geolocator>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Lists the active sessions of the caller's organization.
pub struct ListActiveSessionsUseCase {
    ports: ListActiveSessionsPorts,
}

impl ListActiveSessionsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListActiveSessionsPorts) -> Self {
        Self { ports }
    }

    /// Where `ip` is, or nothing when there is no address or it cannot be
    /// placed. A geolocator that fails places nothing rather than failing
    /// the list.
    async fn place_of(&self, ip: Fact<&IpAddress>) -> Option<IpGeolocation> {
        let Fact::Known(ip) = ip else {
            return None;
        };
        self.ports.geolocator.locate(ip).await.ok().flatten()
    }
}

impl Query for ListActiveSessionsUseCase {
    type Caller = OrgCaller;
    type Input = ListActiveSessionsRequest;
    type Output = Result<Page<ActiveSessionInfo>, AppError>;

    /// One page of the organization's active sessions, ordered as asked,
    /// each placed on the map when its address can be.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the organization turns the caller away,
    ///   or they may not see who is signed in.
    /// - `AppError::Internal` when the session store fails.
    async fn execute(
        &self,
        caller: &OrgCaller,
        request: ListActiveSessionsRequest,
    ) -> Result<Page<ActiveSessionInfo>, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        ensure_may_see_sessions(&actor.control()?, &organization)?;
        let ListActiveSessionsRequest { sort, page } = request;
        let Page {
            items: sessions,
            next,
            limit,
        } = self
            .ports
            .sessions
            .list_active(organization.id(), &sort, &page)
            .await
            .map_err(AppError::from_domain)?;
        let mut items = Vec::with_capacity(sessions.len());
        for session in sessions {
            items.push(ActiveSessionInfo {
                session_id: *session.id(),
                ip_address: session.ip_address().cloned().known().cloned(),
                geo: self.place_of(session.ip_address()).await,
                created_at: session.created_at(),
            });
        }
        Ok(Page { items, next, limit })
    }
}

/// Refuses a caller who may not see who is signed in to `organization`.
fn ensure_may_see_sessions(
    control: &OrgControl<'_>,
    organization: &Organization,
) -> Result<(), AppError> {
    control
        .ensure_may(
            organization.id(),
            OrgPermission::Sessions(OrgSessionAction::View),
        )
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::organization::access::session::OrgSession;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{OrgUserId, TenantId};

    use super::*;
    use crate::listing::Sort;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        RecordingOrgSessionStore, org_session_for, password_only,
    };
    use crate::test_support::{block_on, test_org_caller};

    struct Nowhere;

    #[async_trait]
    impl Geolocator for Nowhere {
        async fn locate(&self, _: &IpAddress) -> Result<Option<IpGeolocation>, DomainError> {
            Ok(None)
        }
    }

    fn a_session() -> OrgSession {
        org_session_for(
            OrgUserId::new(),
            test_org_caller().organization_id(),
            TenantId::new(),
            password_only(),
        )
    }

    fn use_case(actors: FakeOrgActors) -> ListActiveSessionsUseCase {
        ListActiveSessionsUseCase::new(ListActiveSessionsPorts {
            sessions: Arc::new(RecordingOrgSessionStore::holding([
                a_session(),
                a_session(),
            ])),
            geolocator: Arc::new(Nowhere),
            org_actors: Arc::new(actors),
        })
    }

    fn first_page(sort: SortOrder<OrgSessionSortField>) -> ListActiveSessionsRequest {
        ListActiveSessionsRequest {
            sort,
            page: PageRequest::default(),
        }
    }

    fn list(use_case: &ListActiveSessionsUseCase) -> Result<Page<ActiveSessionInfo>, AppError> {
        block_on(use_case.execute(&test_org_caller(), first_page(SortOrder::default())))
    }

    /// Sam, a plain member of Acme, looks at who is signed in. Both active
    /// sessions are on the page.
    #[test]
    fn every_active_session_is_listed() {
        let page = list(&use_case(FakeOrgActors::in_role(OrgRole::Member))).unwrap();

        assert_eq!(page.items.len(), 2);
    }

    /// Olivia orders the sessions oldest first. The older one leads.
    #[test]
    fn sessions_are_ordered_as_asked() {
        let use_case = use_case(FakeOrgActors::in_role(OrgRole::Owner));
        let sort = SortOrder::single(Sort::ascending(OrgSessionSortField::CreatedAt));

        let page = block_on(use_case.execute(&test_org_caller(), first_page(sort))).unwrap();

        assert!(page.items[0].created_at <= page.items[1].created_at);
    }

    /// A signed-out session cannot list the organization's active sessions.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(&use_case(FakeOrgActors::refusing(Refusal::SignedOut)));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Listing active sessions propagates the organization actor's forbidden response.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let result = list(&use_case(FakeOrgActors::refusing(Refusal::Forbidden)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An owner's API key without session-view scope cannot list active sessions.
    #[test]
    fn a_key_without_the_sessions_scope_is_refused() {
        let result = list(&use_case(FakeOrgActors::through_key(
            OrgRole::Owner,
            Vec::new(),
        )));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
