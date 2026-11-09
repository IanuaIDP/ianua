//! A deployment variant: the settings a stack runs with beside the ones
//! every stack makes for itself.

/// Whether the platform's mail goes out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailSetup {
    /// Through SMTP into the stack's [`Mailbox`](crate::mail::Mailbox).
    Receiver,
    /// Nowhere: `EMAIL_PROVIDER=none`, a deployment with no mail server.
    NotSetUp,
}

/// A deployment variant as named settings. Every stack makes its own
/// database, addresses and secrets; a profile says what else differs, and
/// a later setting of the same name wins over an earlier one.
#[derive(Debug, Clone)]
pub struct Profile {
    name: &'static str,
    mail: MailSetup,
    settings: Vec<(String, String)>,
    dropped: Vec<String>,
    cuttable: bool,
    placed: bool,
}

impl Profile {
    /// Routes this stack's dependencies through local relays so outage tests
    /// can disconnect them without affecting another scenario's servers.
    #[must_use]
    pub fn with_cuttable_parts(mut self) -> Self {
        self.cuttable = true;
        self
    }

    /// Whether startup needs dependency relays for this profile.
    pub(super) fn cuttable(&self) -> bool {
        self.cuttable
    }

    /// This profile with a city database the stack writes itself, placing
    /// a client that stands for an address of one of its
    /// [`cities`](super::cities) in that city, for sign-in risk and the
    /// countries an API key is used from.
    #[must_use]
    pub fn placing_callers(mut self) -> Self {
        self.placed = true;
        self
    }

    /// Whether startup writes the city database for this profile.
    pub(super) fn places_callers(&self) -> bool {
        self.placed
    }
    /// The platform as production runs it, with mail and texts going to
    /// the stack's receivers.
    #[must_use]
    pub fn standard() -> Self {
        Self::named("standard", MailSetup::Receiver)
    }

    /// A deployment with no mail server: `EMAIL_PROVIDER=none`.
    #[must_use]
    pub fn without_mail() -> Self {
        Self::named("without mail", MailSetup::NotSetUp)
    }

    /// This profile with the LDAP directory listening over TLS on a
    /// loopback port the system picks, its certificate and the authority
    /// for its clients' certificates made by the stack, so a scenario binds
    /// and searches it through [`crate::ldap`].
    #[must_use]
    pub fn with_directory(self) -> Self {
        self.with("LDAP_BIND_ADDR", "127.0.0.1:0")
    }

    /// This profile with the setting `name` set to `value`, over what the
    /// stack or the profile would have set.
    #[must_use]
    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.dropped.retain(|dropped| dropped != name);
        self.settings.push((name.to_owned(), value.to_owned()));
        self
    }

    /// This profile with the setting `name` left unset, whatever the stack
    /// would have set.
    #[must_use]
    pub fn without(mut self, name: &str) -> Self {
        self.settings.retain(|(set, _)| set != name);
        self.dropped.push(name.to_owned());
        self
    }

    /// The profile's name, for the logs.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name
    }

    /// Whether the platform's mail goes out.
    #[must_use]
    pub fn mail(&self) -> MailSetup {
        self.mail
    }

    /// The settings this profile sets, in the order given.
    pub(crate) fn settings(&self) -> &[(String, String)] {
        &self.settings
    }

    /// The settings this profile leaves unset.
    pub(crate) fn dropped(&self) -> &[String] {
        &self.dropped
    }

    fn named(name: &'static str, mail: MailSetup) -> Self {
        Self {
            name,
            mail,
            settings: Vec::new(),
            dropped: Vec::new(),
            cuttable: false,
            placed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Setting a value again after dropping it sets it.
    #[test]
    fn a_setting_given_after_it_was_dropped_is_set() {
        let profile = Profile::standard()
            .without("CORS_ORIGIN")
            .with("CORS_ORIGIN", "https://app.s1.test");

        assert!(profile.dropped().is_empty());
        assert_eq!(profile.settings().len(), 1);
    }

    /// Dropping a value after setting it drops it.
    #[test]
    fn a_setting_dropped_after_it_was_given_is_dropped() {
        let profile = Profile::without_mail()
            .with("MFA_ISSUER", "Scenarios")
            .without("MFA_ISSUER");

        assert!(profile.settings().is_empty());
        assert_eq!(profile.dropped(), ["MFA_ISSUER".to_owned()]);
        assert_eq!(profile.mail(), MailSetup::NotSetUp);
    }
}
