//! How a notification reaches the user.

use std::fmt;

/// Delivery channel for notifications.
///
/// People choose one per notification category. The fan-out reads it for
/// each person it tells: in the app, in the app and by mail, or not at all.
/// Mail goes only to someone who may see the category in the app. What
/// changes how safe a person's own account is reaches them whatever they
/// chose; see [`NotificationReach`](crate::domains::notifications::reach::NotificationReach).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NotificationChannel {
    /// In the app only. The notification appears in the notification center
    /// and the WebSocket stream.
    #[default]
    InApp,
    /// In the app, and also sent as an email.
    InAppAndEmail,
    /// Nothing is delivered for this category.
    Disabled,
}

impl NotificationChannel {
    /// Whether this channel includes in-app delivery.
    #[must_use]
    pub fn includes_in_app(&self) -> bool {
        matches!(self, Self::InApp | Self::InAppAndEmail)
    }

    /// Whether this channel includes email delivery.
    #[must_use]
    pub fn includes_email(&self) -> bool {
        matches!(self, Self::InAppAndEmail)
    }

    /// Whether this channel is completely disabled.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// The string key for persistence.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InApp => "in_app",
            Self::InAppAndEmail => "in_app_and_email",
            Self::Disabled => "disabled",
        }
    }

    /// Parses a channel from its string key.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "in_app" => Some(Self::InApp),
            "in_app_and_email" => Some(Self::InAppAndEmail),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

impl fmt::Display for NotificationChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A user who never picked a channel gets in-app delivery.
    #[test]
    fn default_is_in_app() {
        assert_eq!(NotificationChannel::default(), NotificationChannel::InApp);
    }

    /// The in-app channel shows the notification in the app. It sends no
    /// email and is not disabled.
    #[test]
    fn in_app_includes_in_app_not_email() {
        let c = NotificationChannel::InApp;
        assert!(c.includes_in_app());
        assert!(!c.includes_email());
        assert!(!c.is_disabled());
    }

    /// The in-app and email channel does both, and is not disabled.
    #[test]
    fn in_app_and_email_includes_both() {
        let c = NotificationChannel::InAppAndEmail;
        assert!(c.includes_in_app());
        assert!(c.includes_email());
        assert!(!c.is_disabled());
    }

    /// The disabled channel shows nothing in the app and sends no email.
    #[test]
    fn disabled_includes_neither() {
        let c = NotificationChannel::Disabled;
        assert!(!c.includes_in_app());
        assert!(!c.includes_email());
        assert!(c.is_disabled());
    }

    /// Each channel's stored key parses back to the same channel, so a
    /// saved choice reads back unchanged.
    #[test]
    fn roundtrip_via_from_str() {
        for c in &[
            NotificationChannel::InApp,
            NotificationChannel::InAppAndEmail,
            NotificationChannel::Disabled,
        ] {
            assert_eq!(NotificationChannel::parse(c.as_str()), Some(*c));
        }
    }

    /// The key `push` is not a channel, so it parses to nothing. It is not
    /// read as some other channel.
    #[test]
    fn from_str_unknown_returns_none() {
        assert_eq!(NotificationChannel::parse("push"), None);
    }

    /// Each channel prints as its stored key, such as `in_app_and_email`.
    /// That printed name parses back to the same channel, so the user's
    /// choice survives being shown and saved.
    #[test]
    fn a_channel_displays_as_the_name_it_parses_back_from() {
        for channel in [
            NotificationChannel::InApp,
            NotificationChannel::InAppAndEmail,
            NotificationChannel::Disabled,
        ] {
            assert_eq!(channel.to_string(), channel.as_str());
            assert_eq!(
                NotificationChannel::parse(&channel.to_string()),
                Some(channel)
            );
        }
        assert_eq!(
            NotificationChannel::InAppAndEmail.to_string(),
            "in_app_and_email"
        );
    }
}
