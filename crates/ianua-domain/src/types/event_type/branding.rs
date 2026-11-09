event_types! {
    /// The events the branding context publishes.
    pub enum BrandingEvent {
        /// Tenant branding was updated.
        Updated => "branding.updated",
        /// The tenant's mail was moved to another provider.
        MailProviderChanged => "branding.mail_provider_changed",
        /// A test mail was sent through the tenant's own mail provider.
        MailProviderTested => "branding.mail_provider_tested",
    }
}

impl BrandingEvent {
    /// Whether other members hear about this event.
    ///
    /// A test send checks a provider someone already switched to, and that
    /// switch was told. Only the audit trail needs the test.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(self, Self::MailProviderTested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fay switches Acme's mail to SendGrid and tests it. Colleagues hear of
    /// the switch, not of the test.
    #[test]
    fn a_test_send_is_not_notified_but_the_switch_is() {
        assert!(!BrandingEvent::MailProviderTested.is_notifiable());
        assert!(BrandingEvent::MailProviderChanged.is_notifiable());
    }
}
