//! Whether something configured is switched on.

use crate::shared::model::two_cases::two_cases;

two_cases! {
    /// Whether a configured thing is switched on.
    ///
    /// It covers pipeline stages, policy rules and SCIM endpoints. Switching
    /// off is kept apart from deleting, so a thing turned off keeps its
    /// settings.
    pub enum Enablement {
        /// On. It takes part.
        Enabled => true,
        /// Off. It is skipped.
        Disabled => false,
    }
}
