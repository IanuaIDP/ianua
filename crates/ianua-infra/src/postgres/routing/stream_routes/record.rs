//! A stream route as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::routing::stream::{
    ListenPort, StreamPolicy, StreamProtocol, StreamRoute, StreamRouteRow, StreamTimeouts,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, Seconds, StreamRouteId, TenantId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::routing::hosts::{hosts_column, hosts_from};

const STREAM_ROUTE: Stored = Stored("stream route");

const ACCESS: Kept = Kept {
    entity: STREAM_ROUTE.0,
    column: "access",
    shape: 1,
};

const BACKENDS: Kept = Kept {
    entity: STREAM_ROUTE.0,
    column: "backends",
    shape: 1,
};

/// A stream route as it is read, with its tenant. The store's checked
/// queries fill it.
pub(super) struct StreamRouteRecord {
    pub(super) tenant_id: Uuid,
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) protocol: String,
    pub(super) listen_port: i32,
    pub(super) sni: Option<Vec<String>>,
    pub(super) policy: String,
    pub(super) access: Value,
    pub(super) backends: Value,
    pub(super) connect_timeout_secs: i32,
    pub(super) idle_timeout_secs: i32,
    pub(super) status: String,
    pub(super) workflow_use: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl StreamRouteRecord {
    /// The stream route the record holds, with its tenant, rebuilt through
    /// the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the stream
    /// route keeps.
    pub(super) fn into_listed(
        self,
    ) -> Result<(TenantId, StreamRoute<ResolvedTenant>), DomainError> {
        let tenant = TenantId::from_uuid(self.tenant_id);
        self.into_stream_route().map(|route| (tenant, route))
    }

    /// The stream route the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the stream
    /// route keeps.
    pub(super) fn into_stream_route(self) -> Result<StreamRoute<ResolvedTenant>, DomainError> {
        let timeouts = StreamTimeouts::new(
            Seconds::new(seconds_from(self.connect_timeout_secs)?),
            Seconds::new(seconds_from(self.idle_timeout_secs)?),
        );
        let listen_port = ListenPort::new(port_from(self.listen_port)?);
        StreamRoute::reconstitute(StreamRouteRow {
            id: StreamRouteId::from_uuid(self.id),
            name: STREAM_ROUTE.value("name", Label::new("name", self.name))?,
            protocol: StreamProtocol::from_stored(&self.protocol)?,
            listen_port: STREAM_ROUTE.value("listen port", listen_port)?,
            sni: hosts_from(STREAM_ROUTE, self.sni)?,
            policy: StreamPolicy::from_stored(&self.policy)?,
            access: ACCESS.open(self.access)?,
            backends: BACKENDS.open(self.backends)?,
            timeouts: STREAM_ROUTE.value("timeouts", timeouts)?,
            status: STREAM_ROUTE.choice(&self.status)?,
            workflow_use: STREAM_ROUTE.choice(&self.workflow_use)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A stored port, as the port number it must be.
fn port_from(stored: i32) -> Result<u16, DomainError> {
    u16::try_from(stored)
        .map_err(|_| DomainError::corrupt_row(STREAM_ROUTE.0, "a port out of range"))
}

/// A stored timeout, as the seconds it must be.
fn seconds_from(stored: i32) -> Result<u32, DomainError> {
    u32::try_from(stored)
        .map_err(|_| DomainError::corrupt_row(STREAM_ROUTE.0, "a negative timeout"))
}

/// A stream route's columns, as they are written.
pub(super) struct StreamRouteColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) protocol: &'static str,
    pub(super) listen_port: i32,
    pub(super) sni: Option<Vec<String>>,
    pub(super) policy: &'static str,
    pub(super) access: Value,
    pub(super) backends: Value,
    pub(super) connect_timeout_secs: i32,
    pub(super) idle_timeout_secs: i32,
    pub(super) status: &'static str,
    pub(super) workflow_use: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> StreamRouteColumns<'a> {
    /// The columns `route` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out as JSON, or a timeout does not fit its column.
    pub(super) fn of(route: &'a StreamRoute<ResolvedTenant>) -> Result<Self, DomainError> {
        let timeouts = route.timeouts();
        Ok(Self {
            id: route.id().as_uuid(),
            name: route.name().as_str(),
            protocol: route.protocol().as_str(),
            listen_port: i32::from(route.listen_port().get()),
            sni: hosts_column(route.sni()),
            policy: route.policy().as_str(),
            access: ACCESS.seal(route.access())?,
            backends: BACKENDS.seal(&route.backends())?,
            connect_timeout_secs: i32::try_from(timeouts.connect_secs().get())
                .map_err(DomainError::infra)?,
            idle_timeout_secs: i32::try_from(timeouts.idle_secs().get())
                .map_err(DomainError::infra)?,
            status: route.status().word(),
            workflow_use: route.workflow_use().word(),
            created_at: route.created_at(),
            updated_at: route.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::stream::StreamBackend;
    use ianua_domain::domains::routing::stream::access::StreamAccess;
    use serde_json::json;

    use super::*;

    /// Who may pass is written in the shape pinned here, and a row in that
    /// shape reads back.
    #[test]
    fn the_access_is_stored_in_its_pinned_shape() {
        let access = StreamAccess::People(RoutePolicy::Authenticated);
        let stored = json!({"v": 1, "value": {"people": "Authenticated"}});

        assert_eq!(ACCESS.seal(&access).unwrap(), stored);
        assert_eq!(ACCESS.open::<StreamAccess>(stored).unwrap(), access);
    }

    /// The backends are written in the shape pinned here, and a row in that
    /// shape reads back.
    #[test]
    fn the_backends_are_stored_in_their_pinned_shape() {
        let backends = vec![StreamBackend::new("db.example.com", 5432, 1).unwrap()];
        let stored = json!({"v": 1, "value": [
            {"host": "db.example.com", "port": 5432, "weight": 1}
        ]});

        assert_eq!(BACKENDS.seal(&backends).unwrap(), stored);
        assert_eq!(
            BACKENDS.open::<Vec<StreamBackend>>(stored).unwrap(),
            backends
        );
    }
}
