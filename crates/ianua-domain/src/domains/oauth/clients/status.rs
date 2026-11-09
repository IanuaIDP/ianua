/// Whether an OAuth client is active or revoked.
///
/// The only move is `Active` to `Revoked`, for example after a security
/// incident. A revoked client never comes back. A new client is made
/// instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OAuthClientStatus {
    /// The client works and can get tokens.
    Active,

    /// The client is revoked for good. Tokens it already holds should be
    /// refused.
    Revoked,
}

/// A refused OAuth client status change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move an OAuth client from {from:?} to {to:?}")]
pub struct InvalidOAuthClientTransition {
    /// The current status.
    pub from: OAuthClientStatus,
    /// The status asked for.
    pub to: OAuthClientStatus,
}

impl OAuthClientStatus {
    /// Moves to `to`.
    ///
    /// # Errors
    ///
    /// - [`InvalidOAuthClientTransition`] for any move other than `Active`
    ///   to `Revoked`.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidOAuthClientTransition> {
        let allowed = matches!((self, to), (Self::Active, Self::Revoked));

        if allowed {
            Ok(to)
        } else {
            Err(InvalidOAuthClientTransition { from: self, to })
        }
    }

    /// The stable name of the status, which lists sort by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    /// Whether the client works.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }

    /// Whether the client is revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        *self == Self::Revoked
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidOAuthClientTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// An active client answers active and not revoked. A revoked one answers
    /// the other way. A check that answered for an extra status would let it
    /// through everywhere it is asked.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (OAuthClientStatus::Active, (true, false)),
            (OAuthClientStatus::Revoked, (false, true)),
        ];

        for (status, (active, revoked)) in cases {
            assert_eq!(status.is_active(), active, "{status:?}");
            assert_eq!(status.is_revoked(), revoked, "{status:?}");
        }
    }

    /// An active client may be revoked.
    #[test]
    fn active_to_revoked() {
        assert!(
            OAuthClientStatus::Active
                .try_transition(OAuthClientStatus::Revoked)
                .is_ok()
        );
    }

    /// A revoked client cannot move back to active or to revoked again.
    #[test]
    fn revoked_is_terminal() {
        for to in [OAuthClientStatus::Active, OAuthClientStatus::Revoked] {
            assert!(OAuthClientStatus::Revoked.try_transition(to).is_err());
        }
    }

    /// Moving active to active is refused.
    #[test]
    fn no_self_transitions() {
        assert!(
            OAuthClientStatus::Active
                .try_transition(OAuthClientStatus::Active)
                .is_err()
        );
    }

    /// Active and revoked turn into JSON as "Active" and "Revoked" and read
    /// back. Renaming a variant fails here instead of changing stored data.
    #[cfg(feature = "serde")]
    #[test]
    fn oauth_client_status_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&OAuthClientStatus::Active).unwrap(),
            r#""Active""#
        );
        assert_eq!(
            serde_json::to_string(&OAuthClientStatus::Revoked).unwrap(),
            r#""Revoked""#
        );
        assert_eq!(
            serde_json::from_str::<OAuthClientStatus>(r#""Active""#).unwrap(),
            OAuthClientStatus::Active
        );
        assert_eq!(
            serde_json::from_str::<OAuthClientStatus>(r#""Revoked""#).unwrap(),
            OAuthClientStatus::Revoked
        );
    }
}
