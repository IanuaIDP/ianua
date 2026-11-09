//! How notifications reach an organization member or an operator: reading
//! and changing their own choices, one channel per category.

pub(crate) mod get_member_preferences;
pub(crate) mod get_operator_preferences;
mod lookup;
pub(crate) mod update_member_preferences;
pub(crate) mod update_operator_preferences;

pub use get_member_preferences::{GetMemberPreferencesPorts, GetMemberPreferencesUseCase};
pub use get_operator_preferences::{GetOperatorPreferencesPorts, GetOperatorPreferencesUseCase};
pub use update_member_preferences::{UpdateMemberPreferencesPorts, UpdateMemberPreferencesUseCase};
pub use update_operator_preferences::{
    UpdateOperatorPreferencesPorts, UpdateOperatorPreferencesUseCase,
};
