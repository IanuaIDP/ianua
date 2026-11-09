//! Fakes for imports of accounts: an in-memory store that can be told to
//! fail, as a database that goes away halfway through an import would.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::account::import::password_hash::ImportedPasswordHash;
use ianua_domain::domains::identity::account::import::run::{UserImport, UserImportRow};
use ianua_domain::domains::identity::account::import::{
    AccountImport, ImportBatch, ImportRecord, ImportedPassword,
};
use ianua_domain::domains::identity::account::user_profile::{DirectoryRecords, PersonalDetails};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DisplayName, Email, UserImportId};

use crate::ports::TenantScoped;
use crate::ports::identity::UserImportStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authentication::Plane;
use crate::test_support::tenant::cfg;

/// In-memory imports, kept as rows in their tenant.
pub struct FakeUserImportStore {
    rows: Mutex<Vec<(Plane, UserImportRow)>>,
    saves_left: Mutex<usize>,
}

impl Default for FakeUserImportStore {
    fn default() -> Self {
        Self {
            rows: Mutex::new(Vec::new()),
            saves_left: Mutex::new(usize::MAX),
        }
    }
}

impl FakeUserImportStore {
    /// No imports.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Takes `saves` more saves, then fails the next one, as a store that
    /// went away for a moment, and takes every save after it.
    pub fn fail_once_after(&self, saves: usize) {
        *self.saves_left.lock().unwrap() = saves;
    }

    /// The import with `id` in the test tenant, as last saved.
    ///
    /// # Panics
    ///
    /// When a kept row no longer rebuilds.
    #[must_use]
    pub fn stored(&self, id: &UserImportId) -> Option<UserImport<ResolvedTenant>> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|(plane, row)| *plane == Plane::test_tenant() && row.id == *id)
            .map(|(_, row)| UserImport::reconstitute(copy_row(row)).expect("a kept row rebuilds"))
    }

    /// How many imports are held, across tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.rows.lock().unwrap().len()
    }

    fn put(&self, plane: Plane, import: &UserImport<ResolvedTenant>) {
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|(held_on, row)| !(*held_on == plane && row.id == *import.id()));
        rows.push((plane, row_of(import)));
    }

    fn take_a_save(&self) -> Result<(), DomainError> {
        let mut left = self.saves_left.lock().unwrap();
        if *left == 0 {
            *left = usize::MAX;
            return Err(DomainError::infra_msg("the import store went away"));
        }
        *left = left.saturating_sub(1);
        Ok(())
    }
}

/// A batch of `count` records, `person0@acme.test` onwards, the first
/// carrying a bcrypt hash and the rest no password.
///
/// # Panics
///
/// When `count` is zero or past the largest batch.
#[must_use]
pub fn import_batch(count: usize) -> ImportBatch {
    import_batch_of(0..count)
}

/// A batch of the records numbered `numbers`, `person{n}@acme.test` each,
/// so two batches with numbers apart name no address twice.
///
/// # Panics
///
/// When `numbers` is empty or longer than the largest batch.
#[must_use]
pub fn import_batch_of(numbers: std::ops::Range<usize>) -> ImportBatch {
    ImportBatch::new(numbers.map(import_record).collect()).expect("a batch of distinct records")
}

/// The record for `person{n}@acme.test`, the first carrying a bcrypt hash.
fn import_record(n: usize) -> ImportRecord {
    let password = match n {
        0 => {
            ImportedPassword::Hash(ImportedPasswordHash::parse(TEST_BCRYPT).expect("a bcrypt hash"))
        }
        _ => ImportedPassword::NotCarried,
    };
    ImportRecord {
        account: AccountImport {
            email: Email::new(format!("person{n}@acme.test")).expect("a valid address"),
            display_name: DisplayName::new("Imported Person", &cfg().display_name)
                .expect("a valid name"),
            details: PersonalDetails::default(),
            records: DirectoryRecords::default(),
        },
        password,
    }
}

/// A bcrypt hash in its usual encoded form.
const TEST_BCRYPT: &str = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";

/// The row storage would keep for `import`.
fn row_of(import: &UserImport<ResolvedTenant>) -> UserImportRow {
    UserImportRow {
        id: *import.id(),
        records: import.records().to_vec(),
        started_by: import.started_by().clone(),
        state: import.state(),
        done: import.done(),
        imported: import.counts().imported,
        refused: import.refused().to_vec(),
        created_at: import.created_at(),
    }
}

/// A copy of `row`, which does not implement `Clone`.
fn copy_row(row: &UserImportRow) -> UserImportRow {
    UserImportRow {
        id: row.id,
        records: row.records.clone(),
        started_by: row.started_by.clone(),
        state: row.state,
        done: row.done,
        imported: row.imported,
        refused: row.refused.clone(),
        created_at: row.created_at,
    }
}

impl TenantScoped for FakeUserImportStore {}

#[async_trait]
impl UserImportStore for FakeUserImportStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        import: &UserImport<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.take_a_save()?;
        self.put(Plane::of(tenant_id), import);
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &UserImportId,
    ) -> Result<Option<UserImport<ResolvedTenant>>, DomainError> {
        let plane = Plane::of(tenant_id);
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|(held_on, row)| *held_on == plane && row.id == *id)
            .map(|(_, row)| UserImport::reconstitute(copy_row(row)))
            .transpose()
    }
}

impl Fake for Arc<dyn UserImportStore> {
    fn fake() -> Self {
        Arc::new(FakeUserImportStore::empty())
    }
}
