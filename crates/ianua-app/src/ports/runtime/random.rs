//! Where the chance a generated secret is drawn from comes from.

use ianua_domain::shared::random::RandomSource;

/// A secure source of uniformly distributed choices, shared by every
/// request.
///
/// The infrastructure implements it over the operating system's secure
/// generator, which keeps no state of its own, so a draw needs no lock. A
/// password handed out from it is only as hard to guess as it is.
pub trait SecureRandom: Send + Sync {
    /// A uniformly chosen index below `upper`. `upper` is never zero.
    fn index_below(&self, upper: usize) -> usize;
}

/// Lends the shared secure source to a domain value's generation rules.
impl RandomSource for &dyn SecureRandom {
    fn index_below(&mut self, upper: usize) -> usize {
        SecureRandom::index_below(*self, upper)
    }
}
