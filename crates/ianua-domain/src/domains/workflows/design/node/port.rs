//! The ways out of a step, which edges leave by.

/// A way out of a step, which edges leave by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Port {
    /// On, once the step has done its work.
    Next,
    /// On, from a condition that held.
    WhenTrue,
    /// On, from a condition that did not hold.
    WhenFalse,
}

impl Port {
    /// A stable name for the way out.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Next => "next",
            Self::WhenTrue => "when_true",
            Self::WhenFalse => "when_false",
        }
    }
}
