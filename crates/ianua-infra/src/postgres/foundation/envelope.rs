//! Value objects kept in a JSONB column, each in a versioned envelope.
//!
//! A value made of many parts, such as a sign-in configuration, is kept
//! whole in one column, as the domain writes it out. It is stored as
//! `{"v": 1, "value": …}`, where `v` is the shape the value had when it was
//! written. The domain may change how it writes a value; a stored row does
//! not change with it. So every column has a test that pins the shape it
//! writes today, and a change of shape raises the column's version and adds
//! the step that reads the old one. Reading a version the store has no step
//! for refuses the row rather than guessing.
//!
//! Reading a value back goes through the domain's own checks, so a stored
//! value that no longer passes them is refused as a corrupt row.

use ianua_domain::shared::errors::DomainError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JSONB column holding one kind of value, and the shape it writes now.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Kept {
    /// What the row is, such as `organization`.
    pub(crate) entity: &'static str,
    /// The column, such as `auth_config`.
    pub(crate) column: &'static str,
    /// The shape the column writes now.
    pub(crate) shape: u32,
}

/// A value as it is stored, with the shape it was written in.
#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    v: u32,
    value: T,
}

/// A stored value that could not be read back.
#[derive(Debug, thiserror::Error)]
#[error("the {column} of a stored {entity} does not read")]
struct Unreadable {
    entity: &'static str,
    column: &'static str,
    #[source]
    cause: serde_json::Error,
}

/// A stored value written in a shape the store has no step for.
#[derive(Debug, thiserror::Error)]
#[error("the {column} of a stored {entity} has shape {found}, and this store reads {reads}")]
struct UnknownShape {
    entity: &'static str,
    column: &'static str,
    found: u32,
    reads: u32,
}

impl Kept {
    /// `value` in its envelope, ready to bind to the column.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the value cannot be
    /// written out.
    pub(crate) fn seal<T: Serialize + ?Sized>(self, value: &T) -> Result<Value, DomainError> {
        serde_json::to_value(Envelope {
            v: self.shape,
            value,
        })
        .map_err(|cause| self.unreadable(cause))
    }

    /// The value `stored` holds, read through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the envelope is missing,
    /// its shape is one this store does not read, or the value does not
    /// pass the domain's checks.
    pub(crate) fn open<T: DeserializeOwned>(self, stored: Value) -> Result<T, DomainError> {
        let envelope: Envelope<Value> =
            serde_json::from_value(stored).map_err(|cause| self.unreadable(cause))?;
        if envelope.v != self.shape {
            return Err(DomainError::infra(UnknownShape {
                entity: self.entity,
                column: self.column,
                found: envelope.v,
                reads: self.shape,
            }));
        }
        serde_json::from_value(envelope.value).map_err(|cause| self.unreadable(cause))
    }

    fn unreadable(self, cause: serde_json::Error) -> DomainError {
        DomainError::infra(Unreadable {
            entity: self.entity,
            column: self.column,
            cause,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const NOTE: Kept = Kept {
        entity: "note",
        column: "body",
        shape: 1,
    };

    /// A value is stored with the shape it was written in, and reads back
    /// unchanged.
    #[test]
    fn a_value_reads_back_as_it_was_sealed() {
        let sealed = NOTE.seal(&vec![1, 2, 3]).unwrap();

        assert_eq!(sealed, json!({"v": 1, "value": [1, 2, 3]}));
        assert_eq!(NOTE.open::<Vec<i32>>(sealed).unwrap(), [1, 2, 3]);
    }

    /// An envelope with an unsupported version is refused as corrupt storage.
    #[test]
    fn a_shape_the_store_has_no_step_for_is_refused() {
        let later = json!({"v": 2, "value": [1]});

        let read = NOTE.open::<Vec<i32>>(later);

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// A bare value without its versioned envelope is refused as corrupt storage.
    #[test]
    fn a_value_without_its_envelope_is_refused() {
        let bare = json!([1, 2, 3]);

        let read = NOTE.open::<Vec<i32>>(bare);

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
