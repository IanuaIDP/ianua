//! Where a run came from, as one column keeps it: how deep in a chain of
//! workflows it was started, or nothing outside any workflow. A run and
//! the approvals it raises keep it this way.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::{ChainDepth, EventOrigin};

use crate::postgres::foundation::stored::Stored;

/// The chain depth column `origin` is written to.
pub(crate) fn depth_of(origin: EventOrigin) -> Option<i16> {
    match origin {
        EventOrigin::Outside => None,
        EventOrigin::Execution(depth) => Some(i16::from(depth.get())),
    }
}

/// Where a row of `entity` came from, by the chain depth its column holds.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the depth is outside the
/// range a chain may reach.
pub(crate) fn origin_from(entity: Stored, depth: Option<i16>) -> Result<EventOrigin, DomainError> {
    let Some(depth) = depth else {
        return Ok(EventOrigin::Outside);
    };
    let depth = u8::try_from(depth)
        .map_err(|_| DomainError::corrupt_row(entity.0, "a chain depth outside its range"))?;
    Ok(EventOrigin::Execution(ChainDepth::from_stored(depth)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW: Stored = Stored("agent run");

    /// A run outside any workflow and one two workflows deep each read back
    /// from their column as they were written.
    #[test]
    fn an_origin_reads_back_from_its_column() {
        let deep = EventOrigin::Execution(ChainDepth::from_stored(2).unwrap());

        for origin in [EventOrigin::Outside, deep] {
            assert_eq!(origin_from(ROW, depth_of(origin)).unwrap(), origin);
        }
    }

    /// A negative stored workflow depth is rejected as corrupt.
    #[test]
    fn a_depth_below_nothing_is_refused() {
        let read = origin_from(ROW, Some(-1));

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
