//! Whether workflows may reach a stream route, as a Protected data step
//! does, and the login kept for them.
//!
//! A stream route is closed to workflows until an administrator opens it
//! with a login of the system behind it, such as a database user made for
//! workflows. Opening it changes nothing about who may reach it: each
//! connection a workflow opens is still decided by the route's access as
//! the run's person. What a step may do once through is what that login
//! may do, decided by the system itself, never by reading what the step
//! asks.
//!
//! The route says only whether it is open. The login is kept apart from
//! it, where the gateway, which reads every route, never reads it: only the
//! worker making a step's call needs it.

use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::events::{StreamRouteClosedToWorkflows, StreamRouteOpenedToWorkflows};
use crate::domains::routing::stream::StreamRoute;
use crate::domains::routing::stream::access::StreamAccess;
use crate::domains::routing::stream::login_tls::LoginTls;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::SealedSecret;

text_value! {
    /// The user name a stream route's workflow login signs in as, such as
    /// `workflows_reader`.
    pub struct LoginUser;
}

impl TextValue for LoginUser {
    const FIELD: &'static str = "login_user";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=128)
    }
}

/// The login kept for workflows on a stream route open to them: a user
/// name, its password sealed by the crypto adapter, and how the connection
/// to the system is protected. The domain never reads the password, and it
/// never prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowLogin {
    user: LoginUser,
    password: SealedSecret,
    tls: LoginTls,
}

impl WorkflowLogin {
    /// The login signing in as `user` with the sealed `password`, over a
    /// connection protected as `tls` says.
    #[must_use]
    pub fn new(user: LoginUser, password: SealedSecret, tls: LoginTls) -> Self {
        Self {
            user,
            password,
            tls,
        }
    }

    /// How the connection to the system is protected.
    #[must_use]
    pub fn tls(&self) -> &LoginTls {
        &self.tls
    }

    /// The user name it signs in as.
    #[must_use]
    pub fn user(&self) -> &LoginUser {
        &self.user
    }

    /// Its password, sealed.
    #[must_use]
    pub fn password(&self) -> &SealedSecret {
        &self.password
    }
}

/// Whether workflows may reach a stream route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StreamWorkflowUse {
    /// Workflows may not reach it, as every stream route starts.
    #[default]
    Closed,
    /// A Protected data step may reach it as the run's person, signing in
    /// with the login kept for it.
    Open,
}

impl StreamWorkflowUse {
    /// The stored form, `closed` or `open`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
        }
    }
}

impl<T: TenantScope> StreamRoute<T> {
    /// Whether workflows may reach this stream route.
    #[must_use]
    pub fn workflow_use(&self) -> StreamWorkflowUse {
        self.workflow_use
    }

    /// Lets workflows reach this stream route, signing in with `login`,
    /// which the caller keeps apart from the route. Raises
    /// `routing.stream_route_opened_to_workflows`, naming the login's user.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] when the route lets no people in: a
    ///   run reaches it as its person, so it would never be admitted.
    /// - [`DomainError::InvalidTransition`] when it is open already: close
    ///   it first to change the login, so the record shows each login used.
    pub fn open_to_workflows(
        &mut self,
        login: &WorkflowLogin,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        if !matches!(self.access, StreamAccess::People(_)) {
            return Err(DomainError::invalid(message!(
                "routing-a-stream-route-opened-to-workflows-lets-people-in",
                "only a stream route that lets people in can be opened to workflows, since a run reaches it as its person"
            )));
        }
        if self.workflow_use == StreamWorkflowUse::Open {
            return Err(DomainError::invalid_transition(message!(
                "routing-the-stream-route-is-open-to-workflows-already",
                "the stream route is open to workflows already"
            )));
        }
        self.workflow_use = StreamWorkflowUse::Open;
        self.touch();
        self.raised.raise(StreamRouteOpenedToWorkflows {
            stream_route_id: self.id,
            name: self.name.clone(),
            login_user: login.user().clone(),
            tls: login.tls().as_str(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Stops workflows reaching this stream route; the caller forgets its
    /// login, and a connection already open is not cut. Raises
    /// `routing.stream_route_closed_to_workflows`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] when it is closed already.
    pub fn close_to_workflows(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        if self.workflow_use == StreamWorkflowUse::Closed {
            return Err(DomainError::invalid_transition(message!(
                "routing-the-stream-route-is-closed-to-workflows-already",
                "the stream route is closed to workflows already"
            )));
        }
        self.workflow_use = StreamWorkflowUse::Closed;
        self.touch();
        self.raised.raise(StreamRouteClosedToWorkflows {
            stream_route_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::routing::fixtures::{routing_admin, routing_editor, routing_viewer};
    use crate::domains::routing::matching::host::RouteHosts;
    use crate::domains::routing::policy::RoutePolicy;
    use crate::domains::routing::stream::{
        CreateStreamRouteParams, ListenPort, StreamBackend, StreamPolicy, StreamProtocol,
        StreamTimeouts, TlsAuthority, TlsCheck,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{HostName, Label};

    /// Ann's orders database behind a signed-in tunnel, its creation taken
    /// out.
    fn orders_database() -> StreamRoute<ResolvedTenant> {
        let mut route = StreamRoute::create(
            CreateStreamRouteParams {
                name: Label::new("name", "orders-db").unwrap(),
                protocol: StreamProtocol::Tcp,
                listen_port: ListenPort::new(15432).unwrap(),
                sni: RouteHosts::Any,
                policy: StreamPolicy::Tunnel,
                access: StreamAccess::People(RoutePolicy::Authenticated),
                backends: vec![StreamBackend::new("db.internal", 5432, 100).unwrap()],
                timeouts: StreamTimeouts::default(),
            },
            &routing_admin(),
        )
        .unwrap();
        raised_names(&mut route);
        route
    }

    fn reader_login() -> WorkflowLogin {
        WorkflowLogin::new(
            LoginUser::new("workflows_reader").unwrap(),
            SealedSecret::new("v1.AAECAwQF").unwrap(),
            LoginTls::Required(TlsCheck::new(
                TlsAuthority::PublicRoots,
                HostName::new("db.internal").unwrap(),
            )),
        )
    }

    /// Ann opens the orders database to workflows with a reader login: it
    /// is open, and the record names the login's user and never its
    /// password. Closing it is recorded too.
    #[test]
    fn a_stream_route_is_opened_with_a_login_and_closed() {
        let mut route = orders_database();
        assert_eq!(route.workflow_use(), StreamWorkflowUse::Closed);

        route
            .open_to_workflows(&reader_login(), &routing_editor())
            .unwrap();
        let opened = raised(&mut route);
        route.close_to_workflows(&routing_editor()).unwrap();

        assert_eq!(opened.len(), 1);
        assert_eq!(
            opened[0].event_type().as_str(),
            "routing.stream_route_opened_to_workflows"
        );
        assert!(matches!(
            opened[0].payload().value("login_user"),
            Some(FieldValue::Text(user)) if user == "workflows_reader"
        ));
        assert!(matches!(
            opened[0].payload().value("tls"),
            Some(FieldValue::Text(tls)) if tls == "required"
        ));
        assert_eq!(route.workflow_use(), StreamWorkflowUse::Closed);
        assert_eq!(
            raised_names(&mut route),
            ["routing.stream_route_closed_to_workflows"]
        );
    }

    /// A viewer cannot open a stream route to workflows. It stays closed
    /// and raises no event.
    #[test]
    fn a_viewer_opens_no_stream_route_to_workflows() {
        let mut route = orders_database();

        let refused = route.open_to_workflows(&reader_login(), &routing_viewer());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(route.workflow_use(), StreamWorkflowUse::Closed);
        assert!(raised_names(&mut route).is_empty());
    }

    /// Opening a stream route already open to workflows is an invalid
    /// transition, even with the same login.
    #[test]
    fn an_open_stream_route_is_not_opened_again() {
        let mut route = orders_database();
        route
            .open_to_workflows(&reader_login(), &routing_editor())
            .unwrap();

        let again = route.open_to_workflows(&reader_login(), &routing_editor());

        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
    }

    /// A public route admitting any holder cannot be opened to workflows.
    /// Its workflow access remains closed.
    #[test]
    fn a_route_letting_no_people_in_is_not_opened_to_workflows() {
        let mut route = orders_database();
        route
            .change_admission(
                StreamPolicy::Public,
                StreamAccess::AnyHolder,
                &routing_editor(),
            )
            .unwrap();

        let refused = route.open_to_workflows(&reader_login(), &routing_editor());

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert_eq!(route.workflow_use(), StreamWorkflowUse::Closed);
    }

    /// The login prints its user name and never its password.
    #[test]
    fn a_login_never_prints_its_password() {
        let printed = format!("{:?}", reader_login());

        assert!(printed.contains("workflows_reader"));
        assert!(!printed.contains("AAECAwQF"));
    }
}
