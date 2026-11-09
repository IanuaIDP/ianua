//! Who did something: a named account, or the platform itself.

/// Who did something: an account of kind `A`, or the platform on its own.
///
/// The platform acts alone for a default made at provisioning or an
/// automatic expiry. A bare missing actor looks the same as one left out by
/// mistake, and an audit trail cannot tell the two apart. So the platform
/// is a value someone writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActedBy<A> {
    /// This account did it.
    By(A),
    /// The platform did it, with nobody asking.
    Platform,
}

impl<A> ActedBy<A> {
    /// The actor a stored column records. No actor means the platform.
    #[must_use]
    pub fn from_stored(actor: Option<A>) -> Self {
        actor.map_or(Self::Platform, Self::By)
    }

    /// The account, when one acted. Storage keeps it in this form.
    #[must_use]
    pub fn account(&self) -> Option<&A> {
        match self {
            Self::By(actor) => Some(actor),
            Self::Platform => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored actor id reads back as that account, and an empty column as
    /// the platform. The account reads back out of it unchanged.
    #[test]
    fn a_stored_actor_reads_back_as_the_account_and_nothing_as_the_platform() {
        assert_eq!(ActedBy::from_stored(Some(7)), ActedBy::By(7));
        assert_eq!(ActedBy::<u8>::from_stored(None), ActedBy::Platform);
        assert_eq!(ActedBy::By(7).account(), Some(&7));
    }
}
