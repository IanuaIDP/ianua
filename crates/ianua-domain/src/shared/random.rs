//! The randomness the domain draws on, without depending on a generator.
//!
//! Rules that use chance stay in the domain, such as what a generated
//! password must contain. An adapter or a test picks where the chance
//! comes from.

/// A source of uniformly distributed choices.
///
/// The infrastructure implements it over the operating system's secure
/// generator. Anything that draws a secret from it relies on that.
pub trait RandomSource {
    /// A uniformly chosen index below `upper`. `upper` is never zero.
    fn index_below(&mut self, upper: usize) -> usize;
}
