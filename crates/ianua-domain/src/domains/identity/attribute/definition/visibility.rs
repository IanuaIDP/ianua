//! How an attribute may be queried, and who may see it.

use crate::shared::model::two_cases::two_cases;

two_cases! {
    /// Whether every user must hold a value for an attribute.
    #[derive(Default)]
    pub enum Requirement {
        /// Every user must.
        Required => true,
        /// A user may leave it empty.
        #[default]
        Optional => false,
    }
}

two_cases! {
    /// Whether an attribute holds information that needs more than the
    /// permission to view users.
    #[derive(Default)]
    pub enum AttributeSensitivity {
        /// It does, such as a salary or a health note.
        Sensitive => true,
        /// It does not.
        #[default]
        Ordinary => false,
    }
}

two_cases! {
    /// Whether a user list may be filtered by an attribute.
    #[derive(Default)]
    pub enum Filtering {
        /// It may.
        Filterable => true,
        /// It may not.
        #[default]
        NotFilterable => false,
    }
}

two_cases! {
    /// Whether a user list may be sorted by an attribute.
    #[derive(Default)]
    pub enum Sorting {
        /// It may.
        Sortable => true,
        /// It may not.
        #[default]
        NotSortable => false,
    }
}

two_cases! {
    /// Whether an attribute is returned with each user in a listing.
    #[derive(Default)]
    pub enum Listing {
        /// It is.
        Listed => true,
        /// It is not.
        #[default]
        Unlisted => false,
    }
}

two_cases! {
    /// Whether an attribute is in use or hidden pending deletion.
    pub enum AttributeUse {
        /// Hidden pending deletion. Nothing new is stored under it.
        Archived => true,
        /// In use.
        InUse => false,
    }
}

/// How an attribute may be queried, and who may see it at all.
///
/// By default an attribute is not listed, not filterable and not sortable.
/// It is also optional and not sensitive. So declaring an attribute nobody
/// asked to show cannot widen what a user list reveals by accident.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttributeVisibility {
    /// Whether every user must hold a value.
    pub required: Requirement,
    /// Whether the attribute holds information that needs more than the
    /// permission to view users, such as a salary or a health note.
    ///
    /// Someone who may only view users cannot read, filter or sort a
    /// sensitive attribute. Filtering counts too. Sam could filter the list
    /// to `income > 100000` and count the results, learning the value
    /// without reading the field.
    pub sensitive: AttributeSensitivity,
    /// Whether a user list may be filtered by this attribute.
    pub filterable: Filtering,
    /// Whether a user list may be sorted by this attribute.
    pub sortable: Sorting,
    /// Whether the attribute is returned with each user in a listing.
    pub listed: Listing,
}
