event_types! {
    /// The events the consumers context publishes.
    pub enum ConsumersEvent {
        /// A new consumer was created.
        ConsumerCreated => "consumers.consumer_created",
        /// A consumer was disabled.
        ConsumerDisabled => "consumers.consumer_disabled",
        /// A consumer was re-enabled.
        ConsumerEnabled => "consumers.consumer_enabled",
        /// A consumer was renamed.
        ConsumerRenamed => "consumers.consumer_renamed",
        /// A consumer's description was changed or cleared.
        DescriptionChanged => "consumers.description_changed",
        /// The most sensitive data a consumer may receive changed.
        ClearanceChanged => "consumers.clearance_changed",
        /// A consumer's credentials were rotated.
        CredentialRotated => "consumers.credential_rotated",
        /// A consumer's old credential was stopped before its overlap ran
        /// out.
        CredentialOverlapEnded => "consumers.credential_overlap_ended",
        /// When a consumer's credential stops working changed.
        CredentialExpiryChanged => "consumers.credential_expiry_changed",
        /// How many requests a consumer may send changed.
        QuotaChanged => "consumers.quota_changed",
        /// A consumer was deleted.
        ConsumerDeleted => "consumers.consumer_deleted",
    }
}
