//! Whose privacy a member's request is about: their own, or another
//! member's they act on.

use ianua_domain::types::OrgUserId;

/// Whose account a member's privacy request is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgWhose {
    /// The member signed in to the caller's session, for their own account.
    Own,
    /// Another member of the organization, whom the caller acts for.
    Member(OrgUserId),
}

impl OrgWhose {
    /// The member the request is about, `caller` for their own.
    #[must_use]
    pub fn member(self, caller: &OrgUserId) -> OrgUserId {
        match self {
            Self::Own => *caller,
            Self::Member(member) => member,
        }
    }
}
