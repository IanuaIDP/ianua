//! The start page: the apps a person may open, each asked of the gateway's
//! own access decision as a `GET` of the address the app opens at.
//!
//! Pat signs in and sees the projects app and the wiki, but not the payroll
//! app his role does not reach. The question is the one the gateway would
//! decide if Pat opened the app now, from his session as it stands: what
//! he holds, how strongly he signed in. What only a real request shows,
//! his country, his device, the request's risk, is unknown here, so a rule
//! that needs it refuses, as the gateway would without it. An app that
//! asks him to prove more first is listed as such. Nothing here grants
//! anything: opening the app is decided again by the gateway.

use std::sync::Arc;

use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authorization::held::Held;
use ianua_domain::domains::proxy::access::decision::{Challenge, Outcome};
use ianua_domain::domains::proxy::access::question::{
    Asked, Circumstances, DpopBinding, MethodClaim,
};
use ianua_domain::domains::proxy::request::context::{Caller, CallerClaims, UserSignIn};
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{
    CanonicalPath, Expiry, Fact, HostName, HttpMethod, Label, PrincipalRef, RouteId,
};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::routing::RouteStore;
use crate::services::authorization::held::held;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::proxy::credentials::Identification;
use crate::use_cases::proxy::credentials::held::claims_of;
use crate::use_cases::proxy::credentials::outcome::proven;
use crate::use_cases::proxy::{DecideAccessRequest, DecideAccessUseCase};

/// The most routes one start page reads, more than any plan allows.
const ROUTES_READ: u32 = 500;

/// One app on a person's start page.
pub struct OpenableApp {
    /// The route the app is served through.
    pub route_id: RouteId,
    /// The app's name, as its route is named.
    pub name: Label,
    /// The path it opens at.
    pub path: CanonicalPath,
    /// The company's addresses it answers on.
    pub hosts: RouteHosts,
    /// Whether it opens at once or asks for more first.
    pub opens: Opening,
}

/// How an app on the start page opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opening {
    /// At once.
    Now,
    /// After the person proves more, such as a stronger sign-in.
    AfterMore(Challenge),
}

/// The ports [`ListOpenableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListOpenablePorts {
    /// Keeps the tenant's routes.
    pub route_store: Arc<dyn RouteStore>,
    /// What the person holds, from the tenant's records.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The gateway's own access decision.
    pub decide: Arc<DecideAccessUseCase>,
}

/// Lists the apps the person signed in may open.
pub struct ListOpenableUseCase {
    ports: ListOpenablePorts,
}

impl ListOpenableUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListOpenablePorts) -> Self {
        Self { ports }
    }

    /// The tenant's active routes, in priority order.
    async fn active_routes(
        &self,
        tenant: &ScopedTenant,
    ) -> Result<Vec<Route<ResolvedTenant>>, AppError> {
        let page = PageRequest::first(Limit::internal(ROUTES_READ));
        let routes = self
            .ports
            .route_store
            .list_all(
                tenant,
                Some(RouteStatus::Active),
                &SortOrder::default(),
                &page,
            )
            .await
            .or_internal()?;
        Ok(routes.items)
    }

    /// How `route` opens for `asker`, or `None` when it does not.
    async fn opening(
        &self,
        tenant: &ScopedTenant,
        asker: &Asker,
        route: &Route<ResolvedTenant>,
    ) -> Option<OpenableApp> {
        let path = route.landing()?;
        let request = DecideAccessRequest {
            route_id: *route.id(),
            identification: asker.identification(),
            asked: opening_request(route, &path),
            circumstances: Circumstances::unknown(),
        };
        let opens = match self.ports.decide.execute(tenant, request).await.outcome() {
            Outcome::Permit => Opening::Now,
            Outcome::Challenge(challenge) => Opening::AfterMore(challenge),
            Outcome::Deny(_) => return None,
        };
        Some(OpenableApp {
            route_id: *route.id(),
            name: route.name().clone(),
            path,
            hosts: route.hosts().clone(),
            opens,
        })
    }
}

impl Query for ListOpenableUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<OpenableApp>, AppError>;

    /// The apps the person signed in may open now, in priority order.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Internal` when the routes or what the person holds
    ///   cannot be read.
    async fn execute(&self, caller: &CallerContext, (): ()) -> Result<Vec<OpenableApp>, AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let tenant = caller.tenant();
        let user_id = *person.account.id();
        let holds = held(
            self.ports.access_records.as_ref(),
            &tenant,
            PrincipalRef::User(user_id),
        )
        .await
        .or_internal()?;
        let asker = Asker {
            caller: Caller::User {
                user_id,
                sign_in: UserSignIn::Session(*person.session.id()),
            },
            holds,
            assurance: person.session.assurance_level(),
        };
        let mut apps = Vec::new();
        for route in self.active_routes(&tenant).await? {
            apps.extend(self.opening(&tenant, &asker, &route).await);
        }
        Ok(apps)
    }
}

/// The person as the gateway's identity stage would prove them from their
/// session.
struct Asker {
    caller: Caller,
    holds: Held,
    assurance: AssuranceLevel,
}

impl Asker {
    /// The proof the decision takes, made now so it is fresh.
    fn identification(&self) -> Identification {
        let claims = CallerClaims {
            current_aal: Fact::Known(self.assurance),
            ..claims_of(&self.holds)
        };
        proven(
            self.caller.clone(),
            Expiry::Never,
            self.holds.clone(),
            claims,
            DpopBinding::Unbound,
        )
    }
}

/// A `GET` of `path` on the first address `route` answers on.
fn opening_request(route: &Route<ResolvedTenant>, path: &CanonicalPath) -> Asked {
    let host = match route.hosts() {
        RouteHosts::Only(names) => names
            .as_slice()
            .first()
            .and_then(|name| HostName::new(name.as_str()).ok())
            .map_or(Fact::Unknown, Fact::Known),
        RouteHosts::Any => Fact::Unknown,
    };
    Asked {
        method: Fact::Known(HttpMethod::Get),
        path: Fact::Known(path.clone()),
        method_claim: MethodClaim::AsSent,
        host,
    }
}
