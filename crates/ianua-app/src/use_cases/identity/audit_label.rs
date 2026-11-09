//! How identity events name the user they are about.

use ianua_domain::types::{EventLabel, UserId};

use crate::ports::shared::AuditLabelResolver;
use crate::tenancy::ScopedTenant;

/// The label of the user with `user_id`, or their id when it cannot be read.
///
/// Best effort: a failed label read must not fail the change it describes.
pub(in crate::use_cases::identity) async fn resolved_user_label(
    resolver: &dyn AuditLabelResolver,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> EventLabel {
    resolver
        .user(tenant, user_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| EventLabel::of(&user_id.to_string()))
}
