//! How a member's account closes while their erasure waits, and opens again
//! if it is cancelled.

use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::org_user_status::{
    InvalidOrgUserTransition, OrgUserStatus,
};

impl OrgUser {
    /// Closes an active account while its erasure waits. Any other status
    /// already keeps it from signing in, so it is left as it is.
    pub(crate) fn close_for_erasure(&mut self) -> Result<(), InvalidOrgUserTransition> {
        if self.status != OrgUserStatus::Active {
            return Ok(());
        }
        self.move_to(OrgUserStatus::Closing)
    }

    /// Opens an account closed for an erasure that was cancelled.
    pub(crate) fn reopen_after_erasure(&mut self) -> Result<(), InvalidOrgUserTransition> {
        if self.status != OrgUserStatus::Closing {
            return Ok(());
        }
        self.move_to(OrgUserStatus::Active)
    }
}
