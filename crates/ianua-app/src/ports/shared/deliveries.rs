//! What became of a delivery's note on how its send went.

/// Whether a delivery's note on how its send went was kept.
///
/// A delivery reads its stream, then sends, which takes time. A person who
/// paused, changed or removed the stream meanwhile wins: the note is
/// dropped rather than written over their change, so a pause is never
/// undone and an old destination never comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryNote {
    /// The stream was still as the delivery read it, and the note is kept.
    Kept,
    /// The stream changed or went away after it was read, and nothing was
    /// written.
    Overtaken,
}
