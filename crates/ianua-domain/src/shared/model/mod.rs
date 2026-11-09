//! Building blocks every aggregate uses: the aggregate trait, status moves, two-case flags and limits.

/// The common interface every aggregate root implements.
pub mod aggregate;
/// A limit that is either set or lifted, said in so many words.
pub mod restriction;
/// The check every stored row passes before an aggregate is rebuilt from it.
pub(crate) mod row_check;
/// A plan of steps and what each waits on, and a run of it.
pub mod steps;
/// The error every status machine refuses a move with.
pub mod transition;
/// Yes-or-no settings and facts as types that name both cases.
pub(crate) mod two_cases;
