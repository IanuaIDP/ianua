/// DNS verification status for a registered domain.
///
/// The allowed moves:
/// - `Pending` → `Verified`, when the DNS proof is found.
/// - `Verified` → `Failed`, when the proof disappears.
/// - `Failed` → `Verified`, when the proof is back.
///
/// A claim that is never proved stays pending until it lapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VerificationStatus {
    /// DNS records have not been verified yet.
    Pending,
    /// DNS verification succeeded.
    Verified,
    /// The domain was verified, but its proof no longer holds.
    Failed,
}

/// Rejected verification status transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a domain's verification from {from:?} to {to:?}")]
pub struct InvalidVerificationTransition {
    /// The current state.
    pub from: VerificationStatus,
    /// The attempted target state.
    pub to: VerificationStatus,
}

impl VerificationStatus {
    /// Gives the new status when moving from `self` to `to` is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidVerificationTransition`] for any move not listed on
    ///   [`VerificationStatus`].
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidVerificationTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Pending | Self::Failed, Self::Verified) | (Self::Verified, Self::Failed)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidVerificationTransition { from: self, to })
        }
    }
}

/// TLS certificate status for domains serving HTTPS traffic.
///
/// The allowed moves:
/// - `NotRequired`, `Provisioning` or `Expired` → `Active`, when a
///   certificate is issued. Asking for one already says traffic arrives over
///   TLS.
/// - `NotRequired` → `Provisioning`, when a certificate is asked for.
/// - `Provisioning` → `Expired`, when provisioning times out.
/// - `Active` → `Expired`, when the certificate lapses without renewal.
/// - `Expired` → `Provisioning`, on renewal.
/// - `Active` or `Expired` → `NoCertificate`, when the tenant removes the
///   certificate it uploaded, live or lapsed.
/// - `NoCertificate` → `Provisioning` or `Active`, when the tenant asks for
///   one through ACME or uploads another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TlsStatus {
    /// No certificate is needed, because the domain serves no traffic.
    NotRequired,
    /// A certificate is being issued through ACME, such as Let's Encrypt.
    Provisioning,
    /// Certificate is active and serving traffic.
    Active,
    /// Certificate has expired and needs renewal.
    Expired,
    /// No certificate serves the name: the tenant removed the one it
    /// uploaded, and has not uploaded or asked for another. Nothing renews
    /// it on its own.
    NoCertificate,
}

/// Rejected TLS status transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a domain's certificate from {from:?} to {to:?}")]
pub struct InvalidTlsTransition {
    /// The current state.
    pub from: TlsStatus,
    /// The attempted target state.
    pub to: TlsStatus,
}

impl TlsStatus {
    /// Gives the new status when moving from `self` to `to` is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidTlsTransition`] for any move not listed on [`TlsStatus`].
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTlsTransition> {
        let allowed = matches!(
            (self, to),
            (
                Self::NotRequired | Self::NoCertificate,
                Self::Provisioning | Self::Active
            ) | (Self::Provisioning, Self::Active | Self::Expired)
                | (Self::Active, Self::Expired | Self::NoCertificate)
                | (
                    Self::Expired,
                    Self::Provisioning | Self::Active | Self::NoCertificate
                )
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidTlsTransition { from: self, to })
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(
    InvalidVerificationTransition,
    InvalidTlsTransition
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Acme's DNS proof for a new domain is found. Pending moves to verified.
    #[test]
    fn verification_pending_to_verified() {
        assert!(
            VerificationStatus::Pending
                .try_transition(VerificationStatus::Verified)
                .is_ok()
        );
    }

    /// A later check no longer finds a verified domain's DNS proof. Verified
    /// moves to failed.
    #[test]
    fn a_verified_domain_whose_proof_disappears_fails() {
        assert!(
            VerificationStatus::Verified
                .try_transition(VerificationStatus::Failed)
                .is_ok()
        );
    }

    /// The tenant puts a failed domain's DNS proof back. Failed moves to
    /// verified again.
    #[test]
    fn a_failed_domain_is_verified_again_when_its_proof_returns() {
        assert!(
            VerificationStatus::Failed
                .try_transition(VerificationStatus::Verified)
                .is_ok()
        );
    }

    /// A domain that was never proved is marked failed. It is refused, since
    /// failed means a proof that once held is gone.
    #[test]
    fn a_pending_domain_cannot_fail() {
        assert!(
            VerificationStatus::Pending
                .try_transition(VerificationStatus::Failed)
                .is_err()
        );
    }

    /// A verified domain is moved back to pending, or verified again. Both
    /// are refused.
    #[test]
    fn a_verified_domain_never_returns_to_pending() {
        assert!(
            VerificationStatus::Verified
                .try_transition(VerificationStatus::Pending)
                .is_err()
        );
        assert!(
            VerificationStatus::Verified
                .try_transition(VerificationStatus::Verified)
                .is_err()
        );
    }

    /// A pending domain is moved to pending. It is refused.
    #[test]
    fn verification_no_self_transitions() {
        assert!(
            VerificationStatus::Pending
                .try_transition(VerificationStatus::Pending)
                .is_err()
        );
    }

    /// A certificate being issued arrives. Provisioning moves to active.
    #[test]
    fn tls_provisioning_to_active() {
        assert!(
            TlsStatus::Provisioning
                .try_transition(TlsStatus::Active)
                .is_ok()
        );
    }

    /// An active certificate lapses without renewal. Active moves to expired.
    #[test]
    fn tls_active_to_expired() {
        assert!(TlsStatus::Active.try_transition(TlsStatus::Expired).is_ok());
    }

    /// Acme removes the certificate it uploaded, whether it still serves or
    /// already lapsed. Either way the domain has no certificate, and can get
    /// one again by upload or through ACME.
    #[test]
    fn a_removed_certificate_leaves_no_certificate_until_another_comes() {
        for from in [TlsStatus::Active, TlsStatus::Expired] {
            assert!(from.try_transition(TlsStatus::NoCertificate).is_ok());
        }
        for to in [TlsStatus::Active, TlsStatus::Provisioning] {
            assert!(TlsStatus::NoCertificate.try_transition(to).is_ok());
        }
    }

    /// A domain with no certificate cannot transition to expired, since
    /// there is no certificate to renew.
    #[test]
    fn a_domain_without_a_certificate_does_not_expire() {
        assert!(
            TlsStatus::NoCertificate
                .try_transition(TlsStatus::Expired)
                .is_err()
        );
    }

    /// An expired certificate is renewed. Expired moves to provisioning.
    #[test]
    fn tls_expired_can_renew() {
        assert!(
            TlsStatus::Expired
                .try_transition(TlsStatus::Provisioning)
                .is_ok()
        );
    }

    /// A domain registered without TLS may move to provisioning or straight
    /// to active. It cannot move to expired, since it never had a
    /// certificate.
    #[test]
    fn tls_not_required_can_be_given_a_certificate() {
        assert!(
            TlsStatus::NotRequired
                .try_transition(TlsStatus::Active)
                .is_ok()
        );
        assert!(
            TlsStatus::NotRequired
                .try_transition(TlsStatus::Provisioning)
                .is_ok()
        );
        assert!(
            TlsStatus::NotRequired
                .try_transition(TlsStatus::Expired)
                .is_err()
        );
    }

    /// A new certificate arrives for an expired one. Expired moves straight
    /// to active.
    #[test]
    fn an_expired_certificate_can_be_replaced_directly() {
        assert!(TlsStatus::Expired.try_transition(TlsStatus::Active).is_ok());
    }

    /// An active certificate is moved back to provisioning. It is refused.
    #[test]
    fn tls_active_cannot_go_back_to_provisioning() {
        assert!(
            TlsStatus::Active
                .try_transition(TlsStatus::Provisioning)
                .is_err()
        );
    }

    /// Provisioning, active and expired are each moved to themselves. All
    /// three are refused.
    #[test]
    fn tls_no_self_transitions() {
        assert!(
            TlsStatus::Provisioning
                .try_transition(TlsStatus::Provisioning)
                .is_err()
        );
        assert!(TlsStatus::Active.try_transition(TlsStatus::Active).is_err());
        assert!(
            TlsStatus::Expired
                .try_transition(TlsStatus::Expired)
                .is_err()
        );
    }
}
