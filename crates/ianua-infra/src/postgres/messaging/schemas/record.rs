//! An event schema as its rows hold it, the schema's own and one per
//! version: read back into the aggregate, and written out from it.

use std::collections::HashMap;

use ianua_domain::domains::messaging::schema::{
    EventSchema, EventSchemaRow, SchemaDefinition, SchemaVersion,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{EventSchemaId, Label};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::messaging::creators::{CreatorColumns, creator_from};

const SCHEMA: Stored = Stored("event schema");

/// A schema as it is read, without its versions. The store's checked
/// queries fill it.
pub(super) struct SchemaRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) schema_name: String,
    pub(super) description: Option<String>,
    pub(super) format: String,
    pub(super) compatibility: String,
    pub(super) created_by_kind: String,
    pub(super) created_by_id: Uuid,
    pub(super) created_by_person: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

/// One version of a schema as it is read.
pub(super) struct VersionRecord {
    pub(super) schema_id: Uuid,
    pub(super) version: i64,
    pub(super) definition: String,
    pub(super) created_at: OffsetDateTime,
}

/// The versions of every schema read, each schema's in the order they were
/// read.
pub(super) struct Versions(HashMap<Uuid, Vec<VersionRecord>>);

impl Versions {
    /// `records`, by the schema each belongs to, keeping their order.
    pub(super) fn of(records: Vec<VersionRecord>) -> Self {
        let mut by_schema: HashMap<Uuid, Vec<VersionRecord>> = HashMap::new();
        for record in records {
            by_schema.entry(record.schema_id).or_default().push(record);
        }
        Self(by_schema)
    }

    /// The versions of the schema `id`, taken out, or none.
    pub(super) fn take(&mut self, id: &Uuid) -> Vec<VersionRecord> {
        self.0.remove(id).unwrap_or_default()
    }
}

impl VersionRecord {
    /// The version the record holds, through its own checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the number or the
    /// definition no longer passes its rules.
    fn into_version(self) -> Result<SchemaVersion, DomainError> {
        Ok(SchemaVersion {
            version: u32::try_from(self.version)
                .map_err(|_| DomainError::corrupt_row(SCHEMA.0, "a version number out of range"))?,
            definition: SCHEMA.value("definition", SchemaDefinition::new(self.definition))?,
            created_at: self.created_at,
        })
    }
}

impl SchemaRecord {
    /// The schema the record holds, with `versions`, its own in order,
    /// rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the schema
    /// keeps, such as versions missing or out of sequence.
    pub(super) fn into_schema(
        self,
        versions: Vec<VersionRecord>,
    ) -> Result<EventSchema<ResolvedTenant>, DomainError> {
        let versions = versions
            .into_iter()
            .map(VersionRecord::into_version)
            .collect::<Result<Vec<_>, _>>()?;
        EventSchema::reconstitute(EventSchemaRow {
            id: EventSchemaId::from_uuid(self.id),
            name: SCHEMA.value("name", Label::new("name", self.name))?,
            schema_name: SCHEMA
                .value("schema name", Label::new("schema_name", self.schema_name))?,
            description: self
                .description
                .map(|text| SCHEMA.value("description", Label::new("description", text)))
                .transpose()?,
            format: SCHEMA.choice(&self.format)?,
            compatibility: SCHEMA.choice(&self.compatibility)?,
            versions,
            created_by: creator_from(
                SCHEMA,
                &self.created_by_kind,
                self.created_by_id,
                self.created_by_person,
            )?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A schema's columns, as they are written.
pub(super) struct SchemaColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) schema_name: &'a str,
    pub(super) description: Option<&'a str>,
    pub(super) format: &'static str,
    pub(super) compatibility: &'static str,
    pub(super) created_by: CreatorColumns<'a>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> SchemaColumns<'a> {
    /// The columns `schema` is written to.
    pub(super) fn of(schema: &'a EventSchema<ResolvedTenant>) -> Self {
        Self {
            id: schema.id().as_uuid(),
            name: schema.name().as_str(),
            schema_name: schema.schema_name().as_str(),
            description: schema.description().map(Label::as_str),
            format: schema.format().word(),
            compatibility: schema.compatibility().word(),
            created_by: CreatorColumns::of(schema.created_by()),
            created_at: schema.created_at(),
            updated_at: schema.updated_at(),
        }
    }
}

/// The versions a save adds, one list per column and one place per
/// version, as one statement writes them.
pub(super) struct VersionColumns {
    pub(super) numbers: Vec<i64>,
    pub(super) definitions: Vec<String>,
    pub(super) created_at: Vec<OffsetDateTime>,
}

impl VersionColumns {
    /// The columns of the versions of `schema` numbered past `stored`, the
    /// latest the store holds already. A published version never changes,
    /// so the others are not sent again.
    pub(super) fn after(schema: &EventSchema<ResolvedTenant>, stored: i64) -> Self {
        let added: Vec<&SchemaVersion> = schema
            .versions()
            .iter()
            .filter(|version| i64::from(version.version) > stored)
            .collect();
        Self {
            numbers: added
                .iter()
                .map(|version| i64::from(version.version))
                .collect(),
            definitions: added
                .iter()
                .map(|version| version.definition.as_str().to_owned())
                .collect(),
            created_at: added.iter().map(|version| version.created_at).collect(),
        }
    }
}
