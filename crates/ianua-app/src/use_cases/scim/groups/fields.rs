//! What a directory says about a group: the whole record, or one change to
//! it; and a group as it reads one back.

use ianua_domain::domains::authorization::group::Group;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Label, UserId};

/// A group the directory keeps, and the users in it.
pub struct ScimGroup {
    /// The directory-managed membership container returned to the client.
    pub group: Group<ResolvedTenant>,
    /// The users in it.
    pub members: Vec<UserId>,
}

/// Everything a directory says about a group when it sends the whole
/// record.
pub struct ScimGroupFields {
    /// The group's name (SCIM `displayName`).
    pub name: Label,
    /// Its members, by user id.
    pub members: Vec<UserId>,
}

/// One change a directory asks for.
pub enum ScimGroupChange {
    /// A new name.
    Rename(Label),
    /// Put these users in the group.
    AddMembers(Vec<UserId>),
    /// Take these users out of the group.
    RemoveMembers(Vec<UserId>),
    /// Make these users, and only these, the group's members.
    ReplaceMembers(Vec<UserId>),
}

impl ScimGroupChange {
    /// How many members the change names; a rename names none.
    #[must_use]
    pub fn members_named(&self) -> usize {
        match self {
            Self::Rename(_) => 0,
            Self::AddMembers(members)
            | Self::RemoveMembers(members)
            | Self::ReplaceMembers(members) => members.len(),
        }
    }
}
