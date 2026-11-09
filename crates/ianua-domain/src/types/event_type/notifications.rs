event_types! {
    /// The events the notifications context publishes.
    pub enum NotificationsEvent {
        /// A notification was marked as read.
        NotificationRead => "notifications.notification_read",
        /// All notifications were marked as read in bulk.
        AllNotificationsRead => "notifications.all_notifications_read",
        /// Notification preferences were updated.
        PreferencesUpdated => "notifications.preferences_updated",
        /// An email could not be delivered after every retry.
        MailUndelivered => "notifications.mail_undelivered",
        /// An organization added a place outside the app its notifications go
        /// to, such as a Slack channel.
        DestinationAdded => "notifications.destination_added",
        /// An organization changed where one of its destinations points, its
        /// name or what it receives.
        DestinationChanged => "notifications.destination_changed",
        /// An organization stopped sending to one of its destinations for now.
        DestinationPaused => "notifications.destination_paused",
        /// An organization sent to a paused destination again.
        DestinationResumed => "notifications.destination_resumed",
        /// An organization removed one of its destinations.
        DestinationRemoved => "notifications.destination_removed",
        /// An organization member changed how a category reaches them.
        MemberPreferencesUpdated => "notifications.member_preferences_updated",
        /// An operator changed how a category reaches them.
        OperatorPreferencesUpdated => "notifications.operator_preferences_updated",
        /// A workflow step sent a person a notice by name.
        NoticeSent => "notifications.notice_sent",
        /// A workflow step offered a person to ask for access, by name.
        AccessOffered => "notifications.access_offered",
    }
}

impl NotificationsEvent {
    /// Whether this event belongs in the audit trail.
    ///
    /// Read receipts are one user's screen state. They fire each time the
    /// notification list is opened and say nothing about who did what to the
    /// organization. Recording them would bury the actions the audit log is
    /// for. They are still published, so read state can sync across a
    /// user's devices.
    #[must_use]
    pub fn is_auditable(&self) -> bool {
        match self {
            Self::NotificationRead | Self::AllNotificationsRead => false,
            Self::PreferencesUpdated
            | Self::MailUndelivered
            | Self::DestinationAdded
            | Self::DestinationChanged
            | Self::DestinationPaused
            | Self::DestinationResumed
            | Self::DestinationRemoved
            | Self::MemberPreferencesUpdated
            | Self::OperatorPreferencesUpdated
            | Self::NoticeSent
            | Self::AccessOffered => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant, the string it is published and audited under, and
    /// whether it belongs in the audit trail at all.
    const ALL: &[(NotificationsEvent, &str, bool)] = &[
        (
            NotificationsEvent::NotificationRead,
            "notifications.notification_read",
            false,
        ),
        (
            NotificationsEvent::AllNotificationsRead,
            "notifications.all_notifications_read",
            false,
        ),
        (
            NotificationsEvent::PreferencesUpdated,
            "notifications.preferences_updated",
            true,
        ),
        (
            NotificationsEvent::MailUndelivered,
            "notifications.mail_undelivered",
            true,
        ),
        (
            NotificationsEvent::DestinationAdded,
            "notifications.destination_added",
            true,
        ),
        (
            NotificationsEvent::DestinationChanged,
            "notifications.destination_changed",
            true,
        ),
        (
            NotificationsEvent::DestinationPaused,
            "notifications.destination_paused",
            true,
        ),
        (
            NotificationsEvent::DestinationResumed,
            "notifications.destination_resumed",
            true,
        ),
        (
            NotificationsEvent::DestinationRemoved,
            "notifications.destination_removed",
            true,
        ),
        (
            NotificationsEvent::MemberPreferencesUpdated,
            "notifications.member_preferences_updated",
            true,
        ),
        (
            NotificationsEvent::OperatorPreferencesUpdated,
            "notifications.operator_preferences_updated",
            true,
        ),
    ];
    /// Ann opens her notification list and marks everything read. Neither
    /// read receipt goes in the audit trail. A preference change and an
    /// undelivered mail do.
    #[test]
    fn read_receipts_stay_out_of_the_audit_trail() {
        for (event, text, auditable) in ALL {
            assert_eq!(event.is_auditable(), *auditable, "{text}");
        }
    }
}
