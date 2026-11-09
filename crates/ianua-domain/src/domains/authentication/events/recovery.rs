//! Recovery events: recovery codes and password resets.

use time::OffsetDateTime;

use crate::domains::authentication::recovery::reset::ResetInitiator;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, UserId};

/// Recovery codes were generated for a user.
///
/// Happens during MFA enrollment or when the user regenerates their codes.
/// Any earlier set stops working.
#[derive(Debug)]
pub struct RecoveryCodesGenerated {
    /// How many codes were generated.
    pub(crate) count: u8,
    /// When the codes were generated.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RecoveryCodesGenerated => crate::types::event_type::AuthenticationEvent::RecoveryCodesGenerated,
    fn payload(&self) -> EventData {
        EventData::new().field("count", self.count.to_string())
    }
}

/// A recovery code was used to authenticate.
///
/// The user could not use their MFA device and used a backup code instead.
/// Security monitoring should flag it. The user may need help enrolling
/// again.
#[derive(Debug)]
pub struct RecoveryCodeUsed {
    /// How many unused codes remain after this one.
    pub(crate) remaining: usize,
    /// When the code was used.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RecoveryCodeUsed => crate::types::event_type::AuthenticationEvent::RecoveryCodeUsed,
    fn payload(&self) -> EventData {
        EventData::new().field("remaining", self.remaining.to_string())
    }
}

/// A password reset was requested.
///
/// A reset link goes to the user's email. The link carries a token that is
/// checked before the password can be changed.
#[derive(Debug)]
pub struct PasswordResetRequested {
    /// The user who needs a reset.
    pub(crate) user_id: UserId,
    /// That user's readable label, taken when the event is written. An admin
    /// or the platform may start the reset, so the user is not always the
    /// actor.
    pub(crate) user_label: EventLabel,
    /// Who initiated the reset.
    pub(crate) initiator: ResetInitiator,
    /// When the request was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PasswordResetRequested => crate::types::event_type::AuthenticationEvent::PasswordResetRequested,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .field("initiator", self.initiator.as_str())
    }
}

/// A password reset was completed. The user set a new password.
#[derive(Debug)]
pub struct PasswordResetCompleted {
    /// When the reset was completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PasswordResetCompleted => crate::types::event_type::AuthenticationEvent::PasswordResetCompleted,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}
