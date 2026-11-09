//! An import and the records it was sent, as their rows hold them: read
//! back into the aggregate, and written out from it.

use ianua_domain::domains::identity::account::import::password_hash::ImportedPasswordHash;
use ianua_domain::domains::identity::account::import::refusal::{FailedRecord, RecordLine};
use ianua_domain::domains::identity::account::import::run::{UserImport, UserImportRow};
use ianua_domain::domains::identity::account::import::state::{ImportState, ImportStatus};
use ianua_domain::domains::identity::account::import::{
    AccountImport, ImportRecord, ImportedPassword,
};
use ianua_domain::domains::identity::account::profile_values::{
    Department, EmployeeNumber, ExternalId, FamilyName, GivenName, PhoneNumber, PreferredUsername,
};
use ianua_domain::domains::identity::account::user_profile::{DirectoryRecords, PersonalDetails};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::{DisplayName, Email, HttpsUrl, Setting, UserId, UserImportId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const IMPORT: Stored = Stored("user import");

const STARTED_BY: Kept = Kept {
    entity: IMPORT.0,
    column: "started_by",
    shape: 1,
};

/// An import as it is read, without its records. The store's checked
/// queries fill it.
pub(super) struct RunRecord {
    pub(super) id: Uuid,
    pub(super) started_by: Value,
    pub(super) status: String,
    pub(super) ended_at: Option<OffsetDateTime>,
    pub(super) total: i32,
    pub(super) done: i32,
    pub(super) imported: i32,
    pub(super) refused_lines: Vec<i32>,
    pub(super) refused_reasons: Vec<String>,
    pub(super) created_at: OffsetDateTime,
}

/// One record an import was sent, as it is read.
pub(super) struct SentRecord {
    pub(super) email: String,
    pub(super) display_name: String,
    pub(super) given_name: Option<String>,
    pub(super) family_name: Option<String>,
    pub(super) preferred_username: Option<String>,
    pub(super) picture: Option<String>,
    pub(super) phone_number: Option<String>,
    pub(super) external_id: Option<String>,
    pub(super) department: Option<String>,
    pub(super) manager_id: Option<Uuid>,
    pub(super) employee_number: Option<String>,
    pub(super) password_hash: Option<String>,
}

impl RunRecord {
    /// The import the record holds with the records `sent`, in line order,
    /// rebuilt through the domain's checks, each name checked against
    /// `limits`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, the records read are not as many as
    /// the import was sent, or the row breaks a rule the import keeps.
    pub(super) fn into_import(
        self,
        sent: Vec<SentRecord>,
        limits: &DomainLimits,
    ) -> Result<UserImport<ResolvedTenant>, DomainError> {
        if usize::try_from(self.total).ok() != Some(sent.len()) {
            return Err(DomainError::corrupt_row(
                IMPORT.0,
                "records it was sent are missing or added",
            ));
        }
        let records = sent
            .into_iter()
            .map(|record| record.into_record(limits))
            .collect::<Result<_, _>>()?;
        UserImport::reconstitute(UserImportRow {
            id: UserImportId::from_uuid(self.id),
            records,
            started_by: STARTED_BY.open(self.started_by)?,
            state: state_from(IMPORT.choice(&self.status)?, self.ended_at)?,
            done: u32::try_from(self.done).map_err(DomainError::infra)?,
            imported: u32::try_from(self.imported).map_err(DomainError::infra)?,
            refused: refusals_from(self.refused_lines, &self.refused_reasons)?,
            created_at: self.created_at,
        })
    }
}

impl SentRecord {
    /// The record as the domain holds it, its name checked against
    /// `limits`.
    fn into_record(self, limits: &DomainLimits) -> Result<ImportRecord, DomainError> {
        let details = PersonalDetails {
            given_name: setting("given name", self.given_name, GivenName::new)?,
            family_name: setting("family name", self.family_name, FamilyName::new)?,
            preferred_username: setting(
                "preferred username",
                self.preferred_username,
                PreferredUsername::new,
            )?,
            picture: setting("picture", self.picture, HttpsUrl::new)?,
            phone_number: setting("phone number", self.phone_number, PhoneNumber::new)?,
        };
        let records = DirectoryRecords {
            external_id: setting("external id", self.external_id, ExternalId::new)?,
            department: setting("department", self.department, Department::new)?,
            manager: Setting::from_stored(self.manager_id.map(UserId::from_uuid)),
            employee_number: setting("employee number", self.employee_number, EmployeeNumber::new)?,
        };
        let password = password_from(self.password_hash.as_deref())?;
        Ok(ImportRecord {
            account: AccountImport {
                email: IMPORT.value("email", Email::new(self.email))?,
                display_name: IMPORT.value(
                    "display name",
                    DisplayName::new(self.display_name, &limits.display_name),
                )?,
                details,
                records,
            },
            password,
        })
    }
}

/// An import's columns, as they are written, without its records.
pub(super) struct RunColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) started_by: Value,
    pub(super) status: &'static str,
    pub(super) ended_at: Option<OffsetDateTime>,
    pub(super) total: i32,
    pub(super) done: i32,
    pub(super) imported: i32,
    pub(super) refused_lines: Vec<i32>,
    pub(super) refused_reasons: Vec<String>,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> RunColumns<'a> {
    /// The columns `import` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when who started it cannot be
    /// written out as JSON, or a count does not fit its column.
    pub(super) fn of(import: &'a UserImport<ResolvedTenant>) -> Result<Self, DomainError> {
        let counts = import.counts();
        let refused = import.refused();
        Ok(Self {
            id: import.id().as_uuid(),
            started_by: STARTED_BY.seal(import.started_by())?,
            status: import.status().word(),
            ended_at: import.state().ended_at(),
            total: i32::try_from(counts.total).map_err(DomainError::infra)?,
            done: i32::try_from(import.done()).map_err(DomainError::infra)?,
            imported: i32::try_from(counts.imported).map_err(DomainError::infra)?,
            refused_lines: refused
                .iter()
                .map(|failed| i32::try_from(failed.line().get()).map_err(DomainError::infra))
                .collect::<Result<_, _>>()?,
            refused_reasons: refused
                .iter()
                .map(|failed| failed.reason().word().to_owned())
                .collect(),
            created_at: import.created_at(),
        })
    }
}

/// The records an import was sent, as the columns they are written to,
/// one list per column, in line order.
#[derive(Default)]
pub(super) struct SentColumns {
    pub(super) lines: Vec<i32>,
    pub(super) emails: Vec<String>,
    pub(super) display_names: Vec<String>,
    pub(super) given_names: Vec<Option<String>>,
    pub(super) family_names: Vec<Option<String>>,
    pub(super) preferred_usernames: Vec<Option<String>>,
    pub(super) pictures: Vec<Option<String>>,
    pub(super) phone_numbers: Vec<Option<String>>,
    pub(super) external_ids: Vec<Option<String>>,
    pub(super) departments: Vec<Option<String>>,
    pub(super) manager_ids: Vec<Option<Uuid>>,
    pub(super) employee_numbers: Vec<Option<String>>,
    pub(super) password_hashes: Vec<Option<String>>,
}

impl SentColumns {
    /// The columns the records of `import` are written to, each on the
    /// line it stood on, counted from one.
    pub(super) fn of(import: &UserImport<ResolvedTenant>) -> Self {
        import
            .records()
            .iter()
            .zip(1_i32..)
            .fold(Self::default(), |mut columns, (record, line)| {
                columns.push(line, record);
                columns
            })
    }

    /// Appends one imported account and its credential at the same column position.
    fn push(&mut self, line: i32, record: &ImportRecord) {
        let account = &record.account;
        self.lines.push(line);
        self.emails.push(account.email.as_str().to_owned());
        self.display_names
            .push(account.display_name.as_str().to_owned());
        self.push_details(&account.details);
        self.push_directory(&account.records);
        self.password_hashes.push(match &record.password {
            ImportedPassword::NotCarried => None,
            ImportedPassword::Hash(hash) => Some(hash.hash().as_str().to_owned()),
        });
    }

    /// Appends personal profile fields in the order their columns are stored.
    fn push_details(&mut self, details: &PersonalDetails) {
        self.given_names
            .push(text_of(details.given_name.value().map(GivenName::as_str)));
        self.family_names
            .push(text_of(details.family_name.value().map(FamilyName::as_str)));
        self.preferred_usernames.push(text_of(
            details
                .preferred_username
                .value()
                .map(PreferredUsername::as_str),
        ));
        self.pictures
            .push(text_of(details.picture.value().map(HttpsUrl::as_str)));
        self.phone_numbers.push(text_of(
            details.phone_number.value().map(PhoneNumber::as_str),
        ));
    }

    /// Appends the imported directory fields without changing their optional values.
    fn push_directory(&mut self, records: &DirectoryRecords) {
        self.external_ids
            .push(text_of(records.external_id.value().map(ExternalId::as_str)));
        self.departments
            .push(text_of(records.department.value().map(Department::as_str)));
        self.manager_ids
            .push(records.manager.value().map(|manager| *manager.as_uuid()));
        self.employee_numbers.push(text_of(
            records.employee_number.value().map(EmployeeNumber::as_str),
        ));
    }
}

/// Validates a carried password hash or records that the import supplied none.
fn password_from(hash: Option<&str>) -> Result<ImportedPassword, DomainError> {
    match hash {
        None => Ok(ImportedPassword::NotCarried),
        Some(hash) => Ok(ImportedPassword::Hash(
            IMPORT.value("password hash", ImportedPasswordHash::parse(hash))?,
        )),
    }
}

fn text_of(text: Option<&str>) -> Option<String> {
    text.map(str::to_owned)
}

/// The value a stored column holds, read back through `read`, or unset
/// when the column is empty.
fn setting<T>(
    what: &'static str,
    stored: Option<String>,
    read: impl Fn(String) -> Result<T, ValidationError>,
) -> Result<Setting<T>, DomainError> {
    stored
        .map(|text| IMPORT.value(what, read(text)))
        .transpose()
        .map(Setting::from_stored)
}

/// The state a stored status and end time record.
fn state_from(
    status: ImportStatus,
    ended_at: Option<OffsetDateTime>,
) -> Result<ImportState, DomainError> {
    match (status, ended_at) {
        (ImportStatus::Pending, None) => Ok(ImportState::Pending),
        (ImportStatus::Running, None) => Ok(ImportState::Running),
        (ImportStatus::Finished, Some(at)) => Ok(ImportState::Finished { at }),
        (ImportStatus::Failed, Some(at)) => Ok(ImportState::Failed { at }),
        (ImportStatus::Pending | ImportStatus::Running, Some(_))
        | (ImportStatus::Finished | ImportStatus::Failed, None) => Err(DomainError::corrupt_row(
            IMPORT.0,
            "an end time that contradicts its status",
        )),
    }
}

/// The refusals the stored lines and reasons, paired in order, record.
fn refusals_from(lines: Vec<i32>, reasons: &[String]) -> Result<Vec<FailedRecord>, DomainError> {
    if lines.len() != reasons.len() {
        return Err(DomainError::corrupt_row(
            IMPORT.0,
            "refused lines without their reasons",
        ));
    }
    lines
        .into_iter()
        .zip(reasons)
        .map(|(line, reason)| {
            let line = u32::try_from(line).map_err(DomainError::infra)?;
            Ok(FailedRecord::new(
                RecordLine::new(line).map_err(|_| {
                    DomainError::corrupt_row(IMPORT.0, "a refused line no import has")
                })?,
                IMPORT.choice(reason)?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::types::ActorRef;
    use serde_json::json;

    use super::*;

    /// Who started an import is written in the shape pinned here, and a row
    /// in that shape reads back the same.
    #[test]
    fn who_started_an_import_is_stored_in_its_pinned_shape() {
        let ann = UserId::from_uuid(Uuid::from_u128(7));
        let stored = json!({"v": 1, "value": {"User": "00000000-0000-0000-0000-000000000007"}});
        let system = json!({"v": 1, "value": "System"});

        assert_eq!(STARTED_BY.seal(&ActorRef::User(ann)).unwrap(), stored);
        let read: ActorRef = STARTED_BY.open(stored.clone()).unwrap();
        assert_eq!(STARTED_BY.seal(&read).unwrap(), stored);
        assert_eq!(STARTED_BY.seal(&ActorRef::System).unwrap(), system);
    }
}
