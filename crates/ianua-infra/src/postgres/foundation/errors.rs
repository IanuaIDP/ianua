//! What a database failure means to the domain.
//!
//! Every Postgres error reaches the domain as `DomainError::Infrastructure`
//! with the error kept as its cause, so the log shows what failed and the
//! caller sees only that the store could not answer. The few failures a
//! store turns into a domain refusal, such as a name already taken, are read
//! here by their constraint, never by the text of the message.

use ianua_domain::shared::errors::DomainError;

/// The Postgres error code for a unique violation.
const UNIQUE_VIOLATION: &str = "23505";

/// The Postgres error code for a foreign key violation.
const FOREIGN_KEY_VIOLATION: &str = "23503";

/// `error` as the domain sees it: the store could not answer, with the
/// cause kept.
pub(crate) fn unanswered(error: sqlx::Error) -> DomainError {
    DomainError::infra(error)
}

/// Whether a write kept every value unique, or found one already taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Uniqueness {
    /// The write went through.
    Kept,
    /// The write repeated a value the constraint keeps unique, and wrote
    /// nothing.
    Taken,
}

/// What `attempt` came to: written, or refused for repeating a value
/// `constraint` keeps unique. Any other failure stays an error.
pub(crate) fn unique_on<T>(
    attempt: Result<T, sqlx::Error>,
    constraint: &str,
) -> Result<Uniqueness, sqlx::Error> {
    match attempt {
        Ok(_) => Ok(Uniqueness::Kept),
        Err(error) if unique_broken(&error) == Some(constraint) => Ok(Uniqueness::Taken),
        Err(error) => Err(error),
    }
}

/// Whether a delete went through, or was refused because rows elsewhere
/// still point at the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reference {
    /// Nothing pointed at the row, and the delete went through.
    Free,
    /// A row the foreign key `constraint` keeps still points at it, and
    /// nothing was deleted.
    Held,
}

/// What `attempt` came to: done, or refused because a row the foreign key
/// `constraint` keeps still points at what it deletes. Any other failure
/// stays an error.
pub(crate) fn referenced_on<T>(
    attempt: Result<T, sqlx::Error>,
    constraint: &str,
) -> Result<Reference, sqlx::Error> {
    match attempt {
        Ok(_) => Ok(Reference::Free),
        Err(error) if broken(&error, FOREIGN_KEY_VIOLATION) == Some(constraint) => {
            Ok(Reference::Held)
        }
        Err(error) => Err(error),
    }
}

/// The constraint a write broke by repeating a unique value, if that is
/// what failed.
fn unique_broken(error: &sqlx::Error) -> Option<&str> {
    broken(error, UNIQUE_VIOLATION)
}

/// The constraint a write broke with the Postgres error `code`, if that is
/// what failed.
fn broken<'e>(error: &'e sqlx::Error, code: &str) -> Option<&'e str> {
    let database = error.as_database_error()?;
    (database.code().as_deref() == Some(code))
        .then(|| database.constraint())
        .flatten()
}
