//! Leave to set a new password on an account someone else acts on.

use std::marker::PhantomData;

use crate::isolation::scope::TenantScope;
use crate::types::UserId;

/// Leave to replace one account's password, given to the person acting on
/// it.
///
/// Only [`User::allow_password_reset`](crate::domains::identity::account::user::User::allow_password_reset)
/// makes one. It checks that the person acting holds all the account holds,
/// and that the account is not switched off. The credential store asks for
/// one before it writes a password the account's owner did not choose.
///
/// Sam may edit users. Without this, Sam sets a new password on Ann, an
/// admin, signs in as her and holds what she holds.
#[derive(Debug)]
pub struct AdminPasswordReset<T: TenantScope> {
    user_id: UserId,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AdminPasswordReset<T> {
    /// Leave for `user_id`, made once its account's checks passed.
    pub(crate) fn for_account(user_id: UserId) -> Self {
        Self {
            user_id,
            _scope: PhantomData,
        }
    }

    /// The account whose password may be replaced.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }
}
