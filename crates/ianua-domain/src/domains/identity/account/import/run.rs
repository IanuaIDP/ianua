//! One import as it is worked through: the records an admin sent, checked
//! when they came, and how far the worker has got with them.
//!
//! Ten thousand accounts do not fit in one request, nor in one
//! transaction. So the import is kept first and worked through later in
//! chunks of `CHUNK_RECORDS`, each kept whole with the progress it made.
//! A worker that stops halfway picks up at the first record no chunk has
//! taken, so nobody is imported twice. A record that cannot become an
//! account, because its address is taken by then, is set aside with its
//! line and the reason, and the rest go on.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::identity::account::creator::{AccountCreator, AccountOpening};
use crate::domains::identity::account::import::refusal::{FailedRecord, RecordLine, RecordRefusal};
use crate::domains::identity::account::import::state::{ImportState, ImportStatus};
use crate::domains::identity::account::import::{ImportBatch, ImportRecord, ImportedPassword};
use crate::domains::identity::account::user::User;
use crate::domains::identity::events::profile::{UserImportStarted, UsersImported};
use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{ActorRef, UserId, UserImportId};

/// How many records one chunk of an import takes.
pub(crate) const CHUNK_RECORDS: usize = 500;

/// How many records an import holds and what became of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportCounts {
    /// Every record sent.
    pub total: u32,
    /// The accounts opened so far.
    pub imported: u32,
    /// The records refused so far.
    pub failed: u32,
    /// The records no chunk has taken yet.
    pub remaining: u32,
}

/// One record of a chunk, with where it stood in the request.
#[derive(Debug, Clone, Copy)]
pub struct ChunkEntry<'a> {
    /// Where it stood.
    pub line: RecordLine,
    /// The account input to validate and open at this position.
    pub record: &'a ImportRecord,
}

/// The next records of an import to work through, at most
/// `CHUNK_RECORDS`.
#[derive(Debug, Clone, Copy)]
pub struct ImportChunk<'a> {
    start: usize,
    records: &'a [ImportRecord],
}

impl<'a> ImportChunk<'a> {
    /// Each record, with its line.
    pub fn entries(self) -> impl Iterator<Item = ChunkEntry<'a>> {
        let Self { start, records } = self;
        records
            .iter()
            .enumerate()
            .map(move |(offset, record)| ChunkEntry {
                line: RecordLine::of_index(start.saturating_add(offset)),
                record,
            })
    }

    /// Where the chunk ends, to record its outcome against.
    #[must_use]
    pub fn end(&self) -> ChunkEnd {
        ChunkEnd(self.start.saturating_add(self.records.len()))
    }
}

/// Where a chunk ended: the first record after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkEnd(usize);

/// What a chunk did with its records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkOutcome {
    /// Where the chunk ended.
    pub end: ChunkEnd,
    /// The accounts it opened.
    pub imported: u32,
    /// The records it refused, in the order they came.
    pub refused: Vec<FailedRecord>,
}

/// What one record of a chunk became.
pub enum Opening<T: TenantScope> {
    /// An account, with the password the record brought.
    Opened {
        /// The account.
        user: Box<User<T>>,
        /// The supplied credential material to install with the newly opened account.
        password: ImportedPassword,
    },
    /// Nothing: the record is set aside.
    Refused(FailedRecord),
}

/// An import of accounts from another system's records.
#[derive(Debug)]
pub struct UserImport<T: TenantScope> {
    id: UserImportId,
    batch: ImportBatch,
    started_by: ActorRef,
    state: ImportState,
    done: usize,
    imported: u32,
    refused: Vec<FailedRecord>,
    created_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// An import as storage keeps it, checked again by
/// [`UserImport::reconstitute`].
pub struct UserImportRow {
    /// The import's id.
    pub id: UserImportId,
    /// Every record sent, in the order they came.
    pub records: Vec<ImportRecord>,
    /// Who sent them.
    pub started_by: ActorRef,
    /// Where it stands, with when it ended.
    pub state: ImportState,
    /// How many records the finished chunks took, from the first.
    pub done: u32,
    /// The accounts opened.
    pub imported: u32,
    /// The records refused, in the order they came.
    pub refused: Vec<FailedRecord>,
    /// When it was kept.
    pub created_at: OffsetDateTime,
}

/// The leave to open accounts an import was given when it was kept.
///
/// Only [`UserImport::open`] uses one, for an import refused at
/// [`UserImport::start`] unless its sender might import accounts.
struct KeptImport;

impl Sealed for KeptImport {}

impl<T: TenantScope> AccountCreator<T> for KeptImport {
    fn ensure_may_open(&self, opening: AccountOpening) -> Result<(), DomainError> {
        match opening {
            AccountOpening::Import => Ok(()),
            AccountOpening::Registration | AccountOpening::Invitation => {
                Err(DomainError::forbidden(message!(
                    "identity-a-kept-import-opens-imported-accounts",
                    "a kept import opens imported accounts only"
                )))
            }
        }
    }
}

impl<T: TenantScope> UserImport<T> {
    /// Keeps `batch` to import, sent by `started_by`, as `creator` allows
    /// importing. Raises `identity.user_import_started`.
    ///
    /// Sam may only view users. Without the check, he sends ten thousand
    /// accounts for mailboxes of his own, and the worker opens them long
    /// after anyone looked at who asked.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `creator` may not import accounts.
    pub fn start(
        batch: ImportBatch,
        started_by: ActorRef,
        creator: &impl AccountCreator<T>,
    ) -> Result<Self, DomainError> {
        creator.ensure_may_open(AccountOpening::Import)?;
        let mut import = Self {
            id: UserImportId::new(),
            batch,
            started_by,
            state: ImportState::Pending,
            done: 0,
            imported: 0,
            refused: Vec::new(),
            created_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        import.raised.raise(UserImportStarted {
            import_id: import.id,
            records: import.counts().total,
            occurred_at: import.created_at,
        });
        Ok(import)
    }

    /// Rebuilds an import from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row holds records no
    ///   import takes, counts that do not add up, refusals out of order or
    ///   past the records taken, a state its progress contradicts, or an
    ///   end before it was kept.
    pub fn reconstitute(row: UserImportRow) -> Result<Self, DomainError> {
        let done = usize::try_from(row.done).unwrap_or(usize::MAX);
        ensure_row_consistent(&row, done)?;
        let batch = ImportBatch::new(row.records)
            .map_err(|_| DomainError::corrupt_row("user import", "records no import takes"))?;
        Ok(Self {
            id: row.id,
            batch,
            started_by: row.started_by,
            state: row.state,
            done,
            imported: row.imported,
            refused: row.refused,
            created_at: row.created_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The import's id.
    #[must_use]
    pub fn id(&self) -> &UserImportId {
        &self.id
    }

    /// Every record sent, in the order they came.
    #[must_use]
    pub fn records(&self) -> &[ImportRecord] {
        self.batch.records()
    }

    /// Who sent them, whom each account it opens is recorded against.
    #[must_use]
    pub fn started_by(&self) -> &ActorRef {
        &self.started_by
    }

    /// Where it stands, with when it ended.
    #[must_use]
    pub fn state(&self) -> ImportState {
        self.state
    }

    /// Where it stands.
    #[must_use]
    pub fn status(&self) -> ImportStatus {
        self.state.status()
    }

    /// How many records the finished chunks took, from the first.
    #[must_use]
    pub fn done(&self) -> u32 {
        u32::try_from(self.done).unwrap_or(u32::MAX)
    }

    /// How many records it holds and what became of them.
    #[must_use]
    pub fn counts(&self) -> ImportCounts {
        let total = u32::try_from(self.batch.records().len()).unwrap_or(u32::MAX);
        ImportCounts {
            total,
            imported: self.imported,
            failed: u32::try_from(self.refused.len()).unwrap_or(u32::MAX),
            remaining: total.saturating_sub(self.done()),
        }
    }

    /// The records refused so far, in the order they came.
    #[must_use]
    pub fn refused(&self) -> &[FailedRecord] {
        &self.refused
    }

    /// When it was kept.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Takes the import up: a pending one starts running, and one already
    /// running, taken up again after the worker stopped, goes on.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it has ended.
    pub fn take_up(&mut self) -> Result<(), DomainError> {
        if self.state == ImportState::Running {
            return Ok(());
        }
        self.move_to(ImportStatus::Running, crate::shared::clock::now())
    }

    /// The next records to work through, or none once every record is
    /// taken.
    #[must_use]
    pub fn next_chunk(&self) -> Option<ImportChunk<'_>> {
        let records = self.batch.records().get(self.done..)?;
        if records.is_empty() {
            return None;
        }
        let taken = records.len().min(CHUNK_RECORDS);
        Some(ImportChunk {
            start: self.done,
            records: records.get(..taken)?,
        })
    }

    /// What the record of `entry` becomes: a new account, opened under the
    /// leave this import was kept with, or a refusal. Opening raises
    /// `identity.user_imported` on the account.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the account cannot be opened for a
    ///   reason no refusal names.
    pub fn open(&self, entry: ChunkEntry<'_>) -> Result<Opening<T>, DomainError> {
        let id = UserId::new();
        if entry.record.account.records.names_as_own_manager(&id) {
            let refusal = FailedRecord::new(entry.line, RecordRefusal::OwnManager);
            return Ok(Opening::Refused(refusal));
        }
        let user = User::import(id, entry.record.account.clone(), &KeptImport)?;
        Ok(Opening::Opened {
            user: Box::new(user),
            password: entry.record.password.clone(),
        })
    }

    /// Records what the chunk ending at `outcome.end` did. Once the last
    /// chunk is in, the import is finished at `now` and raises
    /// `identity.users_imported`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the import is not running.
    /// - [`DomainError::Conflict`] when the chunk is not the next one, or
    ///   its counts do not cover its records.
    pub fn record_chunk(
        &mut self,
        outcome: ChunkOutcome,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if self.state != ImportState::Running {
            return Err(DomainError::invalid_transition(message!(
                "identity-only-a-running-import-records-chunks",
                "only a running import records chunks"
            )));
        }
        self.ensure_covers(&outcome)?;
        self.done = outcome.end.0;
        self.imported = self.imported.saturating_add(outcome.imported);
        self.refused.extend(outcome.refused);
        if self.next_chunk().is_some() {
            return Ok(());
        }
        self.end(ImportStatus::Finished, now)
    }

    /// Gives up on the import at `now`. The chunks it finished stay.
    /// Raises `identity.users_imported`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it has ended.
    pub fn give_up(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        self.end(ImportStatus::Failed, now)
    }

    fn ensure_covers(&self, outcome: &ChunkOutcome) -> Result<(), DomainError> {
        let expected = self.next_chunk().map(|chunk| chunk.end());
        let worked = usize::try_from(outcome.imported)
            .unwrap_or(usize::MAX)
            .saturating_add(outcome.refused.len());
        let taken = outcome.end.0.saturating_sub(self.done);
        if expected != Some(outcome.end) || worked != taken {
            return Err(DomainError::conflict(message!(
                "identity-the-chunk-is-not-the-next",
                "the chunk is not the next one, or its counts do not cover it"
            )));
        }
        Ok(())
    }

    fn end(&mut self, status: ImportStatus, now: OffsetDateTime) -> Result<(), DomainError> {
        self.move_to(status, now)?;
        let counts = self.counts();
        self.raised.raise(UsersImported {
            import_id: self.id,
            status,
            imported: counts.imported,
            refused: counts.failed,
            occurred_at: now,
        });
        Ok(())
    }

    fn move_to(&mut self, to: ImportStatus, now: OffsetDateTime) -> Result<(), DomainError> {
        self.status().try_transition(to)?;
        self.state = ImportState::moved_to(to, now);
        Ok(())
    }
}

impl<T: TenantScope> Raises for UserImport<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses a stored import whose counts, refusals, state and times do not
/// agree, `done` being the records it has taken.
fn ensure_row_consistent(row: &UserImportRow, done: usize) -> Result<(), DomainError> {
    let worked = usize::try_from(row.imported)
        .unwrap_or(usize::MAX)
        .saturating_add(row.refused.len());
    RowCheck::of("user import")
        .holds(worked == done, "counts that do not add up")
        .holds(
            refusals_in_order(&row.refused, done),
            "refusals out of order",
        )
        .holds(
            row.state.fits_progress(done, row.records.len()),
            "a state its progress contradicts",
        )
        .in_order_if(
            row.created_at,
            row.state.ended_at(),
            "ended before it was kept",
        )
        .finish()
}

/// Whether `refused` runs in line order, every line among the first `done`
/// records.
fn refusals_in_order(refused: &[FailedRecord], done: usize) -> bool {
    let last_done = u32::try_from(done).unwrap_or(u32::MAX);
    let ordered = refused
        .iter()
        .zip(refused.iter().skip(1))
        .all(|(earlier, later)| earlier.line() < later.line());
    ordered
        && refused
            .iter()
            .all(|failed| failed.line().get() <= last_done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::granter::HeldByGranter;
    use crate::domains::identity::account::import::AccountImport;
    use crate::domains::identity::account::user_profile::{DirectoryRecords, PersonalDetails};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::DisplayNameLimits;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::user_adder;
    use crate::test_support::events::raised_names;
    use crate::types::{DisplayName, Email};

    fn record(n: usize) -> ImportRecord {
        ImportRecord {
            account: AccountImport {
                email: Email::new(format!("person{n}@acme.com")).unwrap(),
                display_name: DisplayName::new("Imported", &DisplayNameLimits::default()).unwrap(),
                details: PersonalDetails::default(),
                records: DirectoryRecords::default(),
            },
            password: ImportedPassword::NotCarried,
        }
    }

    fn batch_of(count: usize) -> ImportBatch {
        ImportBatch::new((0..count).map(record).collect()).unwrap()
    }

    fn started(count: usize) -> UserImport<ResolvedTenant> {
        let mut import = UserImport::start(
            batch_of(count),
            ActorRef::User(UserId::new()),
            &user_adder(),
        )
        .unwrap();
        import.take_up().unwrap();
        let _ = raised_names(&mut import);
        import
    }

    fn all_opened(import: &UserImport<ResolvedTenant>) -> ChunkOutcome {
        let chunk = import.next_chunk().unwrap();
        ChunkOutcome {
            end: chunk.end(),
            imported: u32::try_from(chunk.entries().count()).unwrap(),
            refused: Vec::new(),
        }
    }

    fn row(state: ImportState, done: u32, imported: u32) -> UserImportRow {
        UserImportRow {
            id: UserImportId::new(),
            records: (0..3).map(record).collect(),
            started_by: ActorRef::User(UserId::new()),
            state,
            done,
            imported,
            refused: Vec::new(),
            created_at: crate::shared::clock::now() - time::Duration::minutes(1),
        }
    }

    /// Ann sends three accounts. The import is kept pending, with nothing
    /// done yet and all three still to go, and its start is recorded.
    #[test]
    fn a_kept_import_waits_with_every_record_to_go() {
        let mut import: UserImport<ResolvedTenant> =
            UserImport::start(batch_of(3), ActorRef::User(UserId::new()), &user_adder()).unwrap();

        assert_eq!(raised_names(&mut import), ["identity.user_import_started"]);
        assert_eq!(import.status(), ImportStatus::Pending);
        assert_eq!(
            import.counts(),
            ImportCounts {
                total: 3,
                imported: 0,
                failed: 0,
                remaining: 3
            }
        );
    }

    /// A sender holding no user-creation authority cannot start an import.
    #[test]
    fn a_sender_who_may_not_create_users_is_refused() {
        let viewer = HeldByGranter::assumed(&[], &[]);

        let refused = UserImport::<ResolvedTenant>::start(
            batch_of(1),
            ActorRef::User(UserId::new()),
            &viewer,
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// An import of 1,200 records is worked through as 500, 500 and 200,
    /// the lines of the second chunk starting at 501.
    #[test]
    fn records_are_taken_in_chunks_of_five_hundred() {
        let mut import = started(1_200);
        let mut sizes = Vec::new();
        let mut first_lines = Vec::new();

        while let Some(chunk) = import.next_chunk() {
            sizes.push(chunk.entries().count());
            first_lines.push(chunk.entries().next().unwrap().line.get());
            let outcome = all_opened(&import);
            import
                .record_chunk(outcome, crate::shared::clock::now())
                .unwrap();
        }

        assert_eq!(sizes, [500, 500, 200]);
        assert_eq!(first_lines, [1, 501, 1_001]);
        assert_eq!(import.status(), ImportStatus::Finished);
    }

    /// The last chunk is in, one record refused. The import finishes and
    /// raises one summary of what it did.
    #[test]
    fn the_last_chunk_finishes_the_import_with_one_summary() {
        let mut import = started(2);
        let refused = vec![FailedRecord::new(
            RecordLine::new(2).unwrap(),
            RecordRefusal::AddressTaken,
        )];
        let end = import.next_chunk().unwrap().end();

        import
            .record_chunk(
                ChunkOutcome {
                    end,
                    imported: 1,
                    refused,
                },
                crate::shared::clock::now(),
            )
            .unwrap();

        assert_eq!(import.status(), ImportStatus::Finished);
        assert_eq!(import.counts().failed, 1);
        assert_eq!(raised_names(&mut import), ["identity.users_imported"]);
    }

    /// A worker reports a chunk whose counts leave a record unaccounted
    /// for. It is refused and the import does not move on.
    #[test]
    fn a_chunk_whose_counts_do_not_cover_it_is_refused() {
        let mut import = started(3);
        let end = import.next_chunk().unwrap().end();

        let refused = import.record_chunk(
            ChunkOutcome {
                end,
                imported: 2,
                refused: Vec::new(),
            },
            crate::shared::clock::now(),
        );

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(import.done(), 0);
    }

    /// The import has not been taken up. A chunk reported for it is
    /// refused.
    #[test]
    fn a_pending_import_records_no_chunk() {
        let mut import: UserImport<ResolvedTenant> =
            UserImport::start(batch_of(1), ActorRef::User(UserId::new()), &user_adder()).unwrap();
        let outcome = all_opened(&import);

        let refused = import.record_chunk(outcome, crate::shared::clock::now());

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
    }

    /// The worker stopped after the first of three chunks and takes the
    /// import up again. It goes on from record 501, not from the first.
    #[test]
    fn an_import_taken_up_again_goes_on_where_it_stopped() {
        let mut import = started(1_200);
        let outcome = all_opened(&import);
        import
            .record_chunk(outcome, crate::shared::clock::now())
            .unwrap();

        import.take_up().unwrap();

        let next = import.next_chunk().unwrap();
        assert_eq!(next.entries().next().unwrap().line.get(), 501);
    }

    /// The worker gives up on an import halfway. It is failed, keeps what
    /// it did, says so once, and cannot be taken up again.
    #[test]
    fn a_given_up_import_cannot_be_taken_up_again() {
        let mut import = started(1_200);
        let outcome = all_opened(&import);
        import
            .record_chunk(outcome, crate::shared::clock::now())
            .unwrap();

        import.give_up(crate::shared::clock::now()).unwrap();

        assert_eq!(import.status(), ImportStatus::Failed);
        assert_eq!(import.counts().imported, 500);
        assert_eq!(raised_names(&mut import), ["identity.users_imported"]);
        assert!(import.take_up().is_err());
    }

    /// A record opens an account waiting on its address, recorded as
    /// imported.
    #[test]
    fn a_record_opens_an_imported_account() {
        let import = started(1);
        let entry = import.next_chunk().unwrap().entries().next().unwrap();

        let Opening::Opened { mut user, .. } = import.open(entry).unwrap() else {
            panic!("the record opens an account");
        };

        assert_eq!(raised_names(&mut *user), ["identity.user_imported"]);
    }

    /// A stored import that opened two accounts from one record done is
    /// refused as corrupt.
    #[test]
    fn a_stored_import_whose_counts_do_not_add_up_is_refused() {
        assert!(refused_as_corrupt(
            &UserImport::<ResolvedTenant>::reconstitute(row(ImportState::Running, 1, 2))
        ));
    }

    /// A stored import called finished with a record still to go is
    /// refused as corrupt.
    #[test]
    fn a_stored_import_finished_with_records_left_is_refused() {
        let finished = ImportState::Finished {
            at: crate::shared::clock::now(),
        };

        assert!(refused_as_corrupt(
            &UserImport::<ResolvedTenant>::reconstitute(row(finished, 2, 2))
        ));
    }

    /// A stored import running with one of three records done rebuilds as
    /// it was kept.
    #[test]
    fn a_consistent_stored_import_rebuilds() {
        let import =
            UserImport::<ResolvedTenant>::reconstitute(row(ImportState::Running, 1, 1)).unwrap();

        assert_eq!(import.counts().remaining, 2);
    }
}
