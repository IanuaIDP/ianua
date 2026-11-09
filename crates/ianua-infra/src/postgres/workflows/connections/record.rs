//! A pending connection as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::workflows::account::connection::{
    ConnectionStage, PendingConnection, PendingConnectionRow, ServicePlace,
};
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{Label, PendingConnectionId, SealedSecret, TenantId, TokenHash};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::workflows::connections::words::StageKind;
use crate::postgres::workflows::operation_scope;

const CONNECTION: Stored = Stored("pending connection");

const STARTED_BY: Kept = Kept {
    entity: CONNECTION.0,
    column: "started_by",
    shape: 1,
};

/// A connection as it is read. The store's checked queries fill it.
pub(super) struct ConnectionRecord {
    pub(super) id: Uuid,
    pub(super) integration: String,
    pub(super) name: String,
    pub(super) sharing: String,
    pub(super) operations: Option<Vec<String>>,
    pub(super) place: Option<String>,
    pub(super) started_by: Value,
    pub(super) state_hash: String,
    pub(super) verifier_sealed: String,
    pub(super) stage: String,
    pub(super) credential_sealed: Option<String>,
    pub(super) code_hash: Option<String>,
    pub(super) expires_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl ConnectionRecord {
    /// The connection the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the
    /// connection keeps.
    pub(super) fn into_connection(self) -> Result<PendingConnection<ResolvedTenant>, DomainError> {
        let stage = stage_from(
            CONNECTION.choice(&self.stage)?,
            self.credential_sealed,
            self.code_hash,
        )?;
        PendingConnection::reconstitute(PendingConnectionRow {
            id: PendingConnectionId::from_uuid(self.id),
            integration: CONNECTION.value("integration", IntegrationKey::new(self.integration))?,
            name: CONNECTION.value("name", Label::new("name", self.name))?,
            sharing: CONNECTION.choice(&self.sharing)?,
            scope: operation_scope::read(CONNECTION, self.operations)?,
            place: self
                .place
                .map(|place| CONNECTION.value("place", ServicePlace::new(place)))
                .transpose()?,
            started_by: STARTED_BY.open(self.started_by)?,
            state: TokenHash::from_stored(self.state_hash),
            verifier: CONNECTION.value("verifier", SealedSecret::new(self.verifier_sealed))?,
            stage,
            expires_at: self.expires_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// How far a connection of `kind` got, with the answer its columns hold.
fn stage_from(
    kind: StageKind,
    credential: Option<String>,
    code: Option<String>,
) -> Result<ConnectionStage, DomainError> {
    match (kind, credential, code) {
        (StageKind::AwaitingService, None, None) => Ok(ConnectionStage::AwaitingService),
        (StageKind::Answered, Some(credential), Some(code)) => Ok(ConnectionStage::Answered {
            credential: CONNECTION.value("credential", SealedSecret::new(credential))?,
            code: TokenHash::from_stored(code),
        }),
        (StageKind::Spent, None, None) => Ok(ConnectionStage::Spent),
        (StageKind::AwaitingService | StageKind::Answered | StageKind::Spent, _, _) => Err(
            DomainError::corrupt_row(CONNECTION.0, "a stage its columns contradict"),
        ),
    }
}

/// A connection's columns, as they are written.
pub(super) struct ConnectionColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) integration: &'a str,
    pub(super) name: &'a str,
    pub(super) sharing: &'static str,
    pub(super) operations: Option<Vec<String>>,
    pub(super) place: Option<&'a str>,
    pub(super) started_by: Value,
    pub(super) state_hash: &'a str,
    pub(super) verifier_sealed: &'a str,
    pub(super) stage: &'static str,
    pub(super) credential_sealed: Option<&'a str>,
    pub(super) code_hash: Option<&'a str>,
    pub(super) expires_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> ConnectionColumns<'a> {
    /// The columns `connection` is written to. Its verifier and credential
    /// are written in the sealed form they already hold.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when who began it cannot be
    /// written out.
    pub(super) fn of(
        connection: &'a PendingConnection<ResolvedTenant>,
    ) -> Result<Self, DomainError> {
        let (credential_sealed, code_hash) = match connection.stage() {
            ConnectionStage::AwaitingService | ConnectionStage::Spent => (None, None),
            ConnectionStage::Answered { credential, code } => {
                (Some(credential.as_str()), Some(code.as_str()))
            }
        };
        Ok(Self {
            id: connection.id().as_uuid(),
            integration: connection.integration().as_str(),
            name: connection.name().as_str(),
            sharing: connection.sharing().word(),
            operations: operation_scope::written(connection.scope()),
            place: connection.place().map(ServicePlace::as_str),
            started_by: STARTED_BY.seal(connection.started_by())?,
            state_hash: connection.state().as_str(),
            verifier_sealed: connection.verifier().as_str(),
            stage: StageKind::of(connection.stage()).word(),
            credential_sealed,
            code_hash,
            expires_at: connection.expires_at(),
            created_at: connection.created_at(),
            updated_at: connection.updated_at(),
        })
    }
}

/// Where a connection found by its state was begun, as its row holds it.
pub(super) struct StateHit {
    pub(super) tenant_id: Uuid,
    pub(super) id: Uuid,
}

impl StateHit {
    /// The tenant it was begun in.
    pub(super) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }
}

#[cfg(test)]
mod tests {
    //! The shape the JSON column is stored in today. A row written now is
    //! read for years, so when this fails, raise the column's shape and add
    //! the step that reads the old one.

    use ianua_domain::types::Human;
    use serde_json::json;

    use super::*;
    use crate::test_support::rows::workflows::ann;

    /// Who began a connection is written in the shape pinned here, and
    /// reads back.
    #[test]
    fn who_began_it_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "account": {"User": "00000000-0000-0000-0000-000000000a11"},
            "person": "ann@acme.example"
        }});

        assert_eq!(STARTED_BY.seal(&ann()).unwrap(), stored);
        assert_eq!(STARTED_BY.open::<Human>(stored).unwrap(), ann());
    }
}
