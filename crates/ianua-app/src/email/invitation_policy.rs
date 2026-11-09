//! How invitations are sent, shared by tenant and organization invitations
//! alike: how long the link lasts, where it points, and how soon another may
//! be asked for.

use ianua_domain::types::{HttpsUrl, Lifetime};

use crate::email::ResendCooldown;

/// The settings every invitation is sent under.
#[derive(Debug, Clone)]
pub struct InvitationPolicy {
    /// How long the invitation link stays good.
    pub lifetime: Lifetime,
    /// The address the invitation link is built on.
    pub base_url: HttpsUrl,
    /// The wait before another invitation email may be asked for.
    pub resend_cooldown: ResendCooldown,
}
