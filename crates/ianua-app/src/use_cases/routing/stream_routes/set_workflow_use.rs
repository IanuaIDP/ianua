//! Set workflow use: open a stream route to the tenant's workflows with a
//! login of the system behind it, so a Protected data step may reach it as
//! the person its run acts for, or close it again and forget the login.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::stream::{
    CertificateName, LoginTls, LoginUser, StreamRoute, TlsAuthority, WorkflowLogin,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::StreamRouteId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::ports::routing::{StreamRouteLogins, StreamRouteStore};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::existing_stream_route;

/// Whether workflows may reach a stream route, and with which login.
#[derive(Debug)]
pub enum StreamWorkflowChange {
    /// Open it, signing in as `user` with `password` over a connection
    /// protected as `tls` asks.
    Open {
        /// The user name the login signs in as.
        user: LoginUser,
        /// Its password, sealed before it is kept.
        password: Secret,
        /// How the connection to the system is protected.
        tls: TlsRequest,
    },
    /// Close it, forgetting the login.
    Close,
}

/// How the caller asks the connection to the system to be protected.
#[derive(Debug)]
pub enum TlsRequest {
    /// TLS to the system itself, its certificate chaining to `authority`
    /// and naming `name`.
    Required {
        /// The authority the certificate chains to.
        authority: TlsAuthority,
        /// The name the certificate is for.
        name: CertificateName,
    },
    /// None, for a system serving no TLS.
    Off,
}

/// Which stream route, and how its workflow use changes.
#[derive(Debug)]
pub struct SetStreamWorkflowUseRequest {
    /// The socket-routing rule whose workflow access will change.
    pub stream_route_id: StreamRouteId,
    /// Open it with a login, or close it.
    pub change: StreamWorkflowChange,
}

/// The ports [`SetStreamWorkflowUseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SetStreamWorkflowUsePorts {
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Keeps each stream route's login apart from the route.
    pub logins: Arc<dyn StreamRouteLogins>,
    /// Seals the login's password before it is kept.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Keeps the route, its login and the record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Opens a stream route to workflows with a login, or closes it.
pub struct SetStreamWorkflowUseUseCase {
    ports: SetStreamWorkflowUsePorts,
}

impl SetStreamWorkflowUseUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SetStreamWorkflowUsePorts) -> Self {
        Self { ports }
    }

    /// Applies `change` to `route` on behalf of `control`, and answers the
    /// login to keep: a new one, its password sealed for the route alone,
    /// or none, so the one kept is forgotten.
    async fn changed(
        &self,
        tenant: &ScopedTenant,
        route: &mut StreamRoute<ResolvedTenant>,
        change: StreamWorkflowChange,
        control: &RoutingControl<'_>,
    ) -> Result<Option<WorkflowLogin>, AppError> {
        let StreamWorkflowChange::Open {
            user,
            password,
            tls,
        } = change
        else {
            route
                .close_to_workflows(control)
                .map_err(AppError::from_domain)?;
            return Ok(None);
        };
        let tls = requested_tls(route, tls)?;
        let place = stream_route_login_place(tenant, route.id());
        let sealed = sealed_text(self.ports.encryptor.as_ref(), password.expose(), &place).await?;
        let login = WorkflowLogin::new(user, sealed, tls);
        route
            .open_to_workflows(&login, control)
            .map_err(AppError::from_domain)?;
        Ok(Some(login))
    }

    /// Keeps `login` for `route`, or forgets the one kept when there is
    /// none.
    async fn keep_login(
        &self,
        tenant: &ScopedTenant,
        route: &StreamRoute<ResolvedTenant>,
        login: Option<&WorkflowLogin>,
    ) -> Result<(), AppError> {
        let logins = self.ports.logins.as_ref();
        match login {
            Some(login) => logins.keep(tenant, route.id(), login).await,
            None => logins.forget(tenant, route.id()).await,
        }
        .or_internal()
    }

    /// Saves `route`, keeps or forgets its `login`, and records what was
    /// raised, all together or not at all.
    async fn keep(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        route: &mut StreamRoute<ResolvedTenant>,
        login: Option<&WorkflowLogin>,
    ) -> Result<(), AppError> {
        let tenant = caller.tenant();
        let events = route.take_events(&tenant);
        kept_together(self.ports.unit_of_work.as_ref(), async {
            self.ports
                .stream_route_store
                .save(&tenant, route)
                .await
                .map_err(AppError::from_domain)?;
            self.keep_login(&tenant, route, login).await?;
            auditor
                .dispatch_by(&caller.actor(), events)
                .await
                .or_internal()
        })
        .await
    }
}

impl Command for SetStreamWorkflowUseUseCase {
    type Caller = CallerContext;
    type Input = SetStreamWorkflowUseRequest;
    type Output = Result<(), AppError>;

    /// Opens the stream route to workflows with the login, its password
    /// sealed for this route alone, and records
    /// `routing.stream_route_opened_to_workflows` naming the login's user;
    /// or closes it, forgetting the login, and records
    /// `routing.stream_route_closed_to_workflows`. A closed route takes no
    /// run pass from the next connection on.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` if the stream route doesn't exist.
    /// - `AppError::Domain` if it is open or closed already, or TLS is
    ///   held to the backends' shared host when they are on different
    ///   hosts.
    /// - `AppError::Internal` on sealing, storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: SetStreamWorkflowUseRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut route = existing_stream_route(
            self.ports.stream_route_store.as_ref(),
            &tenant,
            &request.stream_route_id,
        )
        .await?;
        let login = self
            .changed(&tenant, &mut route, request.change, &control)
            .await?;
        self.keep(caller, auditor, &mut route, login.as_ref()).await
    }
}

/// The protection `request` asks for on `route`, a certificate's name taken
/// from the backends when the caller gives none.
fn requested_tls(
    route: &StreamRoute<ResolvedTenant>,
    request: TlsRequest,
) -> Result<LoginTls, AppError> {
    match request {
        TlsRequest::Required { authority, name } => route
            .tls_check(authority, name)
            .map(LoginTls::Required)
            .map_err(AppError::from_domain),
        TlsRequest::Off => Ok(LoginTls::Off),
    }
}

/// Where the workflow login of stream route `id` of `tenant` is sealed for:
/// a password sealed for one route opens for no other.
pub(crate) fn stream_route_login_place(tenant: &ScopedTenant, id: &StreamRouteId) -> SealedFor {
    SealedFor::new(SealOwner::from(tenant), SealedField::StreamRouteLogin, id)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::stream::StreamWorkflowUse;
    use ianua_domain::domains::routing::stream::access::StreamAccess;
    use ianua_domain::types::SealedSecret;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::routing::{FakeStreamRouteLogins, FakeStreamRouteStore, tunnel_on};
    use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const PASSWORD: &str = "reader password";

    struct Fixture {
        routes: Arc<FakeStreamRouteStore>,
        logins: Arc<FakeStreamRouteLogins>,
        audit: Arc<FakeEventDispatcher>,
        route_id: StreamRouteId,
        use_case: SetStreamWorkflowUseUseCase,
    }

    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let route = tunnel_on(15432, StreamAccess::People(RoutePolicy::Authenticated));
        let routes = Arc::new(FakeStreamRouteStore::empty());
        block_on(routes.save(&test_ctx().tenant(), &route)).unwrap();
        let logins = Arc::new(FakeStreamRouteLogins::default());
        Fixture {
            use_case: SetStreamWorkflowUseUseCase::new(SetStreamWorkflowUsePorts {
                stream_route_store: routes.clone(),
                tenant_authorities: Arc::new(authorities),
                logins: logins.clone(),
                encryptor: Arc::new(FakeEncryptor),
                unit_of_work: Fake::fake(),
            }),
            routes,
            logins,
            audit: Arc::new(FakeEventDispatcher::new()),
            route_id: *route.id(),
        }
    }

    fn open() -> StreamWorkflowChange {
        StreamWorkflowChange::Open {
            user: LoginUser::new("workflows_reader").unwrap(),
            password: Secret::new(PASSWORD),
            tls: TlsRequest::Required {
                authority: TlsAuthority::PublicRoots,
                name: CertificateName::SharedBackendHost,
            },
        }
    }

    fn run(f: &Fixture, change: StreamWorkflowChange) -> Result<(), AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            SetStreamWorkflowUseRequest {
                stream_route_id: f.route_id,
                change,
            },
        ))
    }

    fn workflow_use(f: &Fixture) -> StreamWorkflowUse {
        block_on(f.routes.find_by_id(&test_ctx().tenant(), &f.route_id))
            .unwrap()
            .unwrap()
            .workflow_use()
    }

    fn kept_login(f: &Fixture) -> Option<WorkflowLogin> {
        block_on(f.logins.find(&test_ctx().tenant(), &f.route_id)).unwrap()
    }

    /// Ann opens the orders database to workflows with a reader login. The
    /// route is open, the login is kept apart from it with the password
    /// sealed for this route alone, and the opening is recorded.
    #[test]
    fn opening_keeps_the_login_sealed_for_the_route() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        run(&f, open()).unwrap();

        let place = stream_route_login_place(&test_ctx().tenant(), &f.route_id);
        let expected: SealedSecret = FakeEncryptor::sealed_for(PASSWORD, &place);
        let login = kept_login(&f).unwrap();
        assert_eq!(workflow_use(&f), StreamWorkflowUse::Open);
        assert_eq!(login.user().as_str(), "workflows_reader");
        assert_eq!(login.password(), &expected);
        assert!(matches!(
            login.tls(),
            LoginTls::Required(check) if check.server_name().as_str() == "db.example.com"
        ));
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.stream_route_opened_to_workflows"]
        );
    }

    /// Ann closes it again: the login is forgotten and the closing is
    /// recorded.
    #[test]
    fn closing_forgets_the_login() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        run(&f, open()).unwrap();

        run(&f, StreamWorkflowChange::Close).unwrap();

        assert_eq!(workflow_use(&f), StreamWorkflowUse::Closed);
        assert_eq!(kept_login(&f), None);
        assert_eq!(
            f.audit.records.lock().unwrap()[1],
            "routing.stream_route_closed_to_workflows"
        );
    }

    /// Opening a stream route to workflows without tenant rights is
    /// forbidden. Workflow use stays closed, no login is kept and no opening
    /// event is recorded.
    #[test]
    fn a_viewer_opens_nothing() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, open());

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(workflow_use(&f), StreamWorkflowUse::Closed);
        assert_eq!(kept_login(&f), None);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }
}
