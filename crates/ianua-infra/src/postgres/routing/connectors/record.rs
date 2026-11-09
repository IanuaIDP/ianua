//! A private-network connector as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::routing::connector::{
    ConnectorEnrollment, LastSeen, PrivateConnector, PrivateConnectorRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectorId, Label, PublicKeyPin, TokenHash};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

pub(super) const CONNECTOR: Stored = Stored("connector");

pub(super) const SCOPE: Kept = Kept {
    entity: CONNECTOR.0,
    column: "scope",
    shape: 1,
};

/// A connector as it is read. The store's checked queries fill it.
pub(super) struct ConnectorRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) scope: Value,
    pub(super) code_hash: Option<String>,
    pub(super) code_expires_at: Option<OffsetDateTime>,
    pub(super) public_key: Option<String>,
    pub(super) certificate_expires_at: Option<OffsetDateTime>,
    pub(super) enrolled_at: Option<OffsetDateTime>,
    pub(super) status: String,
    pub(super) last_seen_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

/// Where a stored connector stands with its enrollment, as its five
/// columns hold it.
struct EnrollmentColumns {
    code_hash: Option<String>,
    code_expires_at: Option<OffsetDateTime>,
    public_key: Option<String>,
    certificate_expires_at: Option<OffsetDateTime>,
    enrolled_at: Option<OffsetDateTime>,
}

impl ConnectorRecord {
    /// The connector the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the connector
    /// keeps.
    pub(super) fn into_connector(self) -> Result<PrivateConnector<ResolvedTenant>, DomainError> {
        let enrollment = enrollment_from(EnrollmentColumns {
            code_hash: self.code_hash,
            code_expires_at: self.code_expires_at,
            public_key: self.public_key,
            certificate_expires_at: self.certificate_expires_at,
            enrolled_at: self.enrolled_at,
        })?;
        PrivateConnector::reconstitute(PrivateConnectorRow {
            id: ConnectorId::from_uuid(self.id),
            name: CONNECTOR.value("name", Label::new("name", self.name))?,
            scope: SCOPE.open(self.scope)?,
            enrollment,
            status: CONNECTOR.choice(&self.status)?,
            last_seen: self.last_seen_at.map_or(LastSeen::Never, LastSeen::At),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The enrollment a stored connector is in: awaiting it with a code, or
/// enrolled with a key and a certificate's end, never both or neither.
fn enrollment_from(columns: EnrollmentColumns) -> Result<ConnectorEnrollment, DomainError> {
    match columns {
        EnrollmentColumns {
            code_hash: Some(code_hash),
            code_expires_at: Some(expires_at),
            public_key: None,
            certificate_expires_at: None,
            enrolled_at: None,
        } => Ok(ConnectorEnrollment::Awaiting {
            code_hash: TokenHash::from_stored(code_hash),
            expires_at,
        }),
        EnrollmentColumns {
            code_hash: None,
            code_expires_at: None,
            public_key: Some(public_key),
            certificate_expires_at: Some(certificate_expires_at),
            enrolled_at: Some(enrolled_at),
        } => Ok(ConnectorEnrollment::Enrolled {
            key: CONNECTOR.value("public_key", PublicKeyPin::parse(&public_key))?,
            certificate_expires_at,
            enrolled_at,
        }),
        EnrollmentColumns { .. } => Err(DomainError::corrupt_row(
            CONNECTOR.0,
            "an enrollment neither awaited nor done, or both",
        )),
    }
}

/// A connector's columns, as they are written. When the gateway last saw
/// it is the gateway's to write, never the store's.
pub(super) struct ConnectorColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) scope: Value,
    pub(super) code_hash: Option<&'a str>,
    pub(super) code_expires_at: Option<OffsetDateTime>,
    pub(super) public_key: Option<String>,
    pub(super) certificate_expires_at: Option<OffsetDateTime>,
    pub(super) enrolled_at: Option<OffsetDateTime>,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

/// The enrollment columns of a connector being written.
struct WrittenEnrollment<'a> {
    code_hash: Option<&'a str>,
    code_expires_at: Option<OffsetDateTime>,
    public_key: Option<String>,
    certificate_expires_at: Option<OffsetDateTime>,
    enrolled_at: Option<OffsetDateTime>,
}

impl<'a> ConnectorColumns<'a> {
    /// The columns `connector` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its scope cannot be
    /// written out as JSON.
    pub(super) fn of(connector: &'a PrivateConnector<ResolvedTenant>) -> Result<Self, DomainError> {
        let enrollment = written_enrollment(connector.enrollment());
        Ok(Self {
            id: connector.id().as_uuid(),
            name: connector.name().as_str(),
            scope: SCOPE.seal(connector.scope())?,
            code_hash: enrollment.code_hash,
            code_expires_at: enrollment.code_expires_at,
            public_key: enrollment.public_key,
            certificate_expires_at: enrollment.certificate_expires_at,
            enrolled_at: enrollment.enrolled_at,
            status: connector.status().word(),
            created_at: connector.created_at(),
            updated_at: connector.updated_at(),
        })
    }
}

/// The columns `enrollment` is written to.
fn written_enrollment(enrollment: &ConnectorEnrollment) -> WrittenEnrollment<'_> {
    match enrollment {
        ConnectorEnrollment::Awaiting {
            code_hash,
            expires_at,
        } => WrittenEnrollment {
            code_hash: Some(code_hash.as_str()),
            code_expires_at: Some(*expires_at),
            public_key: None,
            certificate_expires_at: None,
            enrolled_at: None,
        },
        ConnectorEnrollment::Enrolled {
            key,
            certificate_expires_at,
            enrolled_at,
        } => WrittenEnrollment {
            code_hash: None,
            code_expires_at: None,
            public_key: Some(key.to_string()),
            certificate_expires_at: Some(*certificate_expires_at),
            enrolled_at: Some(*enrolled_at),
        },
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::routing::connector::scope::ConnectorScope;
    use ianua_domain::types::DomainName;
    use serde_json::json;

    use super::*;

    /// What a connector may reach is written in the shape pinned here, and
    /// a row in that shape reads back.
    #[test]
    fn the_scope_is_stored_in_its_pinned_shape() {
        let scope = ConnectorScope::new(
            Vec::new(),
            vec![DomainName::new("intranet.example.com").unwrap()],
        )
        .unwrap();
        let stored = json!({"v": 1, "value": {
            "networks": [],
            "domains": ["intranet.example.com"]
        }});

        assert_eq!(SCOPE.seal(&scope).unwrap(), stored);
        assert_eq!(SCOPE.open::<ConnectorScope>(stored).unwrap(), scope);
    }
}
