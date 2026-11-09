event_types! {
    /// The events the crypto context publishes.
    pub enum CryptoEvent {
        /// A signing key was created.
        KeyCreated => "crypto.key_created",
        /// A signing key was rotated.
        KeyRotated => "crypto.key_rotated",
        /// A signing key was revoked.
        KeyRevoked => "crypto.key_revoked",
        /// An algorithm migration was planned.
        MigrationPlanned => "crypto.migration_planned",
        /// An algorithm migration started, and its new key was created.
        MigrationStarted => "crypto.migration_started",
        /// The target key was promoted to primary signer.
        MigrationPromoted => "crypto.migration_promoted",
        /// An algorithm migration completed successfully.
        MigrationCompleted => "crypto.migration_completed",
        /// An algorithm migration was rolled back.
        MigrationRolledBack => "crypto.migration_rolled_back",
        /// A planned migration was cancelled before starting.
        MigrationCancelled => "crypto.migration_cancelled",
        /// An assertion key was made where none signed.
        AssertionKeyCreated => "crypto.assertion_key_created",
        /// An assertion key was rotated by age.
        AssertionKeyRotated => "crypto.assertion_key_rotated",
        /// A rotated assertion key was retired after the overlap.
        AssertionKeyRetired => "crypto.assertion_key_retired",
    }
}

impl CryptoEvent {
    /// Whether other members hear about this event.
    ///
    /// The platform makes, rotates and retires assertion keys on its own
    /// schedule, with nobody asking and nothing anyone could do about it:
    /// only the audit trail needs each one.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::AssertionKeyCreated | Self::AssertionKeyRotated | Self::AssertionKeyRetired
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nightly sweep rotates Acme's assertion key. Colleagues are not
    /// told of the platform's housekeeping, but they are told when Ann
    /// rotates the tenant's signing key.
    #[test]
    fn an_assertion_key_rotation_is_not_notified_but_a_signing_key_rotation_is() {
        assert!(!CryptoEvent::AssertionKeyRotated.is_notifiable());
        assert!(!CryptoEvent::AssertionKeyCreated.is_notifiable());
        assert!(!CryptoEvent::AssertionKeyRetired.is_notifiable());
        assert!(CryptoEvent::KeyRotated.is_notifiable());
    }
}
