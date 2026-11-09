//! How a tenant's settings change, and who may change them.
//!
//! Every change names the person making it and needs their right for that
//! part of the tenant. A change to how the tenant is protected, which is its
//! sign-in settings, mutual TLS or compliance posture, also needs the person
//! to have proved who they are again just now. A closed tenant takes no
//! changes.

use crate::domains::identity::account::control::RecentProof;
use crate::domains::tenant::access::network_security::MtlsConfig;
use crate::domains::tenant::access::sign_in_gate::SignInChange;
use crate::domains::tenant::clone::{ClonePart, TenantClone};
use crate::domains::tenant::compliance::CompliancePosture;
use crate::domains::tenant::compliance_limits::ComplianceLimits;
use crate::domains::tenant::control::{TenantArea, TenantControl};
use crate::domains::tenant::custom_domains::owned_domain::OwnedDomain;
use crate::domains::tenant::environment::TenantEnvironment;
use crate::domains::tenant::events::access::{TenantAuthConfigUpdated, TenantMtlsConfigUpdated};
use crate::domains::tenant::events::custom_domains::TenantPrimaryDomainChanged;
use crate::domains::tenant::events::lifecycle::{
    TenantComplianceChanged, TenantContactEmailChanged, TenantEnvironmentChanged,
    TenantLocaleChanged, TenantReadableAddressChanged, TenantRenamed, TenantTimezoneChanged,
};
use crate::domains::tenant::hosts::ReadableAddress;
use crate::domains::tenant::lifecycle::Tenant;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{DisplayName, DomainName, Email, Locale, Setting, Timezone};

impl Tenant {
    /// Changes the tenant's consent to publishing its readable DNS name and
    /// public certificate transparency entry. An unchanged choice raises
    /// nothing; withdrawing consent cannot erase already published records.
    ///
    /// # Errors
    ///
    /// Returns `Forbidden` without settings authority and `InvalidTransition`
    /// when the tenant is closed.
    pub fn change_readable_address(
        &mut self,
        by: TenantControl<'_>,
        choice: ReadableAddress,
    ) -> Result<(), DomainError> {
        self.ensure_changeable(by, TenantArea::Profile)?;
        if self.readable_address == choice {
            return Ok(());
        }
        let before = std::mem::replace(&mut self.readable_address, choice);
        self.touch();
        self.raise(TenantReadableAddressChanged {
            before,
            after: choice,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Replaces the display name shown in admin UIs and branding. Raises
    /// `tenant.renamed` with both names.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not change the
    ///   tenant's settings.
    /// - [`DomainError::InvalidTransition`] when the tenant is closed.
    pub fn rename(
        &mut self,
        by: TenantControl<'_>,
        display_name: DisplayName,
    ) -> Result<(), DomainError> {
        self.ensure_changeable(by, TenantArea::Profile)?;
        let old_name = std::mem::replace(&mut self.display_name, display_name);
        self.touch();
        self.raise(TenantRenamed {
            old_name,
            new_name: self.display_name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Changes where billing and security notices go. Raises
    /// `tenant.contact_email_changed` with both addresses.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not change the
    ///   tenant's settings.
    /// - [`DomainError::InvalidTransition`] when the tenant is closed.
    pub fn change_contact_email(
        &mut self,
        by: TenantControl<'_>,
        email: Email,
    ) -> Result<(), DomainError> {
        self.ensure_changeable(by, TenantArea::Profile)?;
        let old_email = std::mem::replace(&mut self.contact_email, email);
        self.touch();
        self.raise(TenantContactEmailChanged {
            old_email,
            new_email: self.contact_email.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Changes the default timezone. Raises `tenant.timezone_changed` with
    /// both timezones.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not change the
    ///   tenant's settings.
    /// - [`DomainError::InvalidTransition`] when the tenant is closed.
    pub fn change_timezone(
        &mut self,
        by: TenantControl<'_>,
        timezone: Timezone,
    ) -> Result<(), DomainError> {
        self.ensure_changeable(by, TenantArea::Profile)?;
        let old_timezone = std::mem::replace(&mut self.timezone, timezone);
        self.touch();
        self.raise(TenantTimezoneChanged {
            old_timezone,
            new_timezone: self.timezone.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Changes the default locale. Raises `tenant.locale_changed` with both
    /// locales.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not change the
    ///   tenant's settings.
    /// - [`DomainError::InvalidTransition`] when the tenant is closed.
    pub fn change_locale(
        &mut self,
        by: TenantControl<'_>,
        locale: Locale,
    ) -> Result<(), DomainError> {
        self.ensure_changeable(by, TenantArea::Profile)?;
        let old_locale = std::mem::replace(&mut self.locale, locale);
        self.touch();
        self.raise(TenantLocaleChanged {
            old_locale,
            new_locale: self.locale.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Labels the tenant as serving `environment`, such as staging. Raises
    /// `tenant.environment_changed` with both labels.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not change the
    ///   tenant's settings.
    /// - [`DomainError::InvalidTransition`] when the tenant is closed.
    pub fn change_environment(
        &mut self,
        by: TenantControl<'_>,
        environment: TenantEnvironment,
    ) -> Result<(), DomainError> {
        self.ensure_changeable(by, TenantArea::Profile)?;
        let old_environment = std::mem::replace(&mut self.environment, environment);
        self.touch();
        self.raise(TenantEnvironmentChanged {
            old_environment,
            new_environment: self.environment,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Makes a domain the tenant proved it owns its primary domain, or
    /// leaves it with none. Raises `tenant.primary_domain_changed` with the
    /// domain before and after.
    ///
    /// The data plane sends requests for the primary domain to this tenant.
    /// So it must be a name the tenant proved, never one it only typed in.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not change the
    ///   tenant's settings.
    /// - [`DomainError::Forbidden`] when another tenant proved the domain.
    /// - [`DomainError::InvalidTransition`] when the tenant is closed.
    pub fn change_primary_domain(
        &mut self,
        by: TenantControl<'_>,
        domain: Setting<OwnedDomain>,
    ) -> Result<(), DomainError> {
        self.ensure_changeable(by, TenantArea::Profile)?;
        let primary = self.primary_from(domain)?;
        let old = std::mem::replace(&mut self.primary_domain, primary);
        self.touch();
        self.raise_primary_domain_changed(&old);
        Ok(())
    }

    /// Raises the move of the primary domain away from `old` to the one the
    /// tenant has now.
    fn raise_primary_domain_changed(&mut self, old: &Setting<DomainName>) {
        self.raise(TenantPrimaryDomainChanged {
            old_domain: old.value().cloned(),
            new_domain: self.primary_domain.value().cloned(),
            occurred_at: self.updated_at,
        });
    }

    /// The primary domain `domain` stands for, refused when another tenant
    /// proved it.
    fn primary_from(
        &self,
        domain: Setting<OwnedDomain>,
    ) -> Result<Setting<DomainName>, DomainError> {
        let Setting::Set(owned) = domain else {
            return Ok(Setting::Unset);
        };
        if *owned.tenant() != self.id {
            return Err(DomainError::forbidden(message!(
                "tenant-the-domain-was-proved-by-another",
                "the domain was proved by another tenant"
            )));
        }
        Ok(Setting::Set(owned.into_domain()))
    }

    /// Lets go of `domain` as the primary domain, once it was removed,
    /// handed to another tenant or lost its proof. Gives the domain back
    /// when it was the primary one, and raises
    /// `tenant.primary_domain_changed` from it to none. Changes and raises
    /// nothing otherwise.
    ///
    /// Nobody chooses this, so it names nobody, and it works on a closed
    /// tenant too. A tenant must not keep routing a name it no longer
    /// holds.
    pub fn release_domain(&mut self, domain: &DomainName) -> Option<DomainName> {
        if self.primary_domain.value() != Some(domain) {
            return None;
        }
        let old = std::mem::replace(&mut self.primary_domain, Setting::Unset);
        self.touch();
        self.raise_primary_domain_changed(&old);
        Some(domain.clone())
    }

    /// Replaces the sign-in settings, such as the MFA and password policy.
    /// Raises `tenant.auth_config_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not change sign-in
    ///   settings, or did not prove who they are again just now.
    /// - [`DomainError::Validation`] when the settings would shut out the
    ///   tenant user saving them, by their way in or their address.
    /// - [`DomainError::InvalidTransition`] when the tenant is closed.
    pub fn update_auth_config(
        &mut self,
        by: TenantControl<'_>,
        proof: &impl RecentProof,
        change: SignInChange<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_changeable(by, TenantArea::SignIn)?;
        by.ensure_proved_recently(proof)?;
        change.ensure_keeps_in(by.by())?;
        self.auth_config = change.config;
        self.touch();
        self.raise(TenantAuthConfigUpdated {
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Replaces the mTLS trust anchor. Raises
    /// `tenant.mtls_config_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not change mutual
    ///   TLS, or did not prove who they are again just now.
    /// - [`DomainError::InvalidTransition`] when the tenant is closed.
    pub fn update_mtls(
        &mut self,
        by: TenantControl<'_>,
        proof: &impl RecentProof,
        config: MtlsConfig,
    ) -> Result<(), DomainError> {
        self.ensure_changeable(by, TenantArea::Mtls)?;
        by.ensure_proved_recently(proof)?;
        self.mtls = config;
        self.touch();
        self.raise(TenantMtlsConfigUpdated {
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Replaces the compliance posture: data residency, audit retention and
    /// whether operators may act as the tenant's users. Raises
    /// `tenant.compliance_changed` with the posture before and after.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not change the
    ///   compliance posture, or did not prove who they are again just now.
    /// - [`DomainError::Validation`] when the deployment does not allow the
    ///   posture. See [`ComplianceLimits::ensure_allows`].
    /// - [`DomainError::Validation`] when the tenant's data is placed
    ///   outside the residency the posture declares.
    /// - [`DomainError::InvalidTransition`] when the tenant is closed.
    pub fn change_compliance(
        &mut self,
        by: TenantControl<'_>,
        proof: &impl RecentProof,
        posture: CompliancePosture,
        limits: &ComplianceLimits,
    ) -> Result<(), DomainError> {
        self.ensure_changeable(by, TenantArea::Compliance)?;
        by.ensure_proved_recently(proof)?;
        limits.ensure_allows(&posture)?;
        self.residency
            .satisfies_declared_residency(posture.data_residency())?;
        let posture = posture.following(&self.compliance, crate::shared::clock::now());
        let before = std::mem::replace(&mut self.compliance, posture);
        self.touch();
        self.raise(TenantComplianceChanged {
            before,
            after: self.compliance.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Takes `source`'s sign-in settings, mutual TLS, timezone and locale,
    /// as a step of `clone`. Raises `tenant.auth_config_updated` and
    /// `tenant.mtls_config_updated`, so the copy is on record like any other
    /// change to how the tenant is protected.
    ///
    /// Whoever started the clone held the right to make tenants in the
    /// organization; the clone vouches for that. It vouches only for its own
    /// two tenants: a settings clone from production into staging copies
    /// nothing into a third tenant.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the clone has ended.
    /// - [`DomainError::Forbidden`] when the clone copies between other
    ///   tenants, or does not copy settings.
    /// - [`DomainError::InvalidTransition`] when this tenant is closed.
    pub fn copy_settings_from(
        &mut self,
        source: &Tenant,
        clone: &TenantClone,
    ) -> Result<(), DomainError> {
        clone.ensure_copies(ClonePart::Settings, source.id(), &self.id)?;
        self.ensure_open()?;
        self.auth_config = source.auth_config.clone();
        self.mtls = source.mtls.clone();
        self.timezone = source.timezone.clone();
        self.locale = source.locale.clone();
        self.touch();
        self.raise(TenantAuthConfigUpdated {
            occurred_at: self.updated_at,
        });
        self.raise(TenantMtlsConfigUpdated {
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Refuses a change to `area` unless the tenant is open and the person
    /// holds the right for it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the tenant is suspended,
    ///   archived or deleted.
    /// - [`DomainError::Forbidden`] when the person may not change `area`.
    pub(crate) fn ensure_changeable(
        &self,
        by: TenantControl<'_>,
        area: TenantArea,
    ) -> Result<(), DomainError> {
        self.ensure_open()?;
        by.ensure_may(&self.id, area)
    }

    /// Refuses a change to a suspended, archived or deleted tenant.
    fn ensure_open(&self) -> Result<(), DomainError> {
        if !self.status.is_open() {
            return Err(DomainError::invalid_transition(message!(
                "tenant-a-tenant-takes-no-changes",
                format!("a {} tenant takes no changes", self.status)
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::methods::AuthMethod;
    use crate::domains::authentication::sessions::session::Session;
    use crate::domains::authentication::sessions::session::tests::signed_in_session;
    use crate::domains::authorization::permission::{SystemPermission, TenantSettingsAction};
    use crate::domains::tenant::access::auth_config::{TenantAuthConfig, TenantAuthSettings};
    use crate::domains::tenant::access::network_security::MtlsMode;
    use crate::domains::tenant::access::sign_in_gate::SavedFrom;
    use crate::domains::tenant::compliance::{DataResidency, OperatorImpersonation, Residency};
    use crate::domains::tenant::compliance_limits::ComplianceLimitsParams;
    use crate::domains::tenant::fixtures::{
        ADMIN, ProvedJustNow, active, holder_of, holding, person, proved_domain,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::DisplayNameLimits;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEvent;
    use crate::shared::events::raised::RaisesComplete;
    use crate::test_support::events::raised_complete_names;
    use crate::types::{ActedBy, CertificatePem, Seconds};

    const VIEW_ONLY: &[SystemPermission] =
        &[SystemPermission::TenantSettings(TenantSettingsAction::View)];

    /// A new tenant keeps its names private; an admin opts in and out. Both
    /// changes are recorded while repeating a choice raises nothing.
    #[test]
    fn readable_addresses_need_consent_and_record_both_changes() {
        let ann = person("ann@acme.test");
        let mut tenant = fresh();
        let label = tenant.platform_label().clone();
        assert_eq!(tenant.readable_address(), ReadableAddress::Off);
        for choice in [
            ReadableAddress::On,
            ReadableAddress::On,
            ReadableAddress::Off,
        ] {
            tenant
                .change_readable_address(holding(&ann, &tenant, ADMIN), choice)
                .unwrap();
        }
        let events = tenant.take_events();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].event_type().as_str(),
            "tenant.readable_address_changed"
        );
        assert_eq!(
            change(&events[0], "readable_address"),
            (Some("off".into()), Some("on".into()))
        );
        assert_eq!(
            change(&events[1], "readable_address"),
            (Some("on".into()), Some("off".into()))
        );
        assert_eq!(tenant.platform_label(), &label);
    }

    /// A settings viewer cannot enable readable addresses. Consent stays off
    /// and no event is raised.
    #[test]
    fn a_viewer_cannot_publish_readable_addresses() {
        let sam = person("sam@acme.test");
        let mut tenant = fresh();
        let result =
            tenant.change_readable_address(holding(&sam, &tenant, VIEW_ONLY), ReadableAddress::On);
        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(tenant.readable_address(), ReadableAddress::Off);
        assert!(tenant.take_events().is_empty());
    }

    /// Even an administrator cannot enable readable addresses on an archived
    /// tenant. Consent stays off and no settings event is raised.
    #[test]
    fn a_closed_tenant_cannot_publish_readable_addresses() {
        let ann = person("ann@acme.test");
        let mut tenant = active();
        tenant.archive(ActedBy::Platform).unwrap();
        let _ = tenant.take_events();
        let result =
            tenant.change_readable_address(holding(&ann, &tenant, ADMIN), ReadableAddress::On);
        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert_eq!(tenant.readable_address(), ReadableAddress::Off);
        assert!(tenant.take_events().is_empty());
    }

    fn shorter_sessions() -> TenantAuthConfig {
        TenantAuthConfig::new(TenantAuthSettings {
            session_lifetime_secs: Seconds::new(7_200),
            ..TenantAuthSettings::default()
        })
        .unwrap()
    }

    fn saved_through(
        config: TenantAuthConfig,
        session: &Session<ResolvedTenant>,
    ) -> SignInChange<'_> {
        SignInChange {
            config,
            saved_from: SavedFrom::from_session(session),
        }
    }

    fn their_ca() -> MtlsConfig {
        let her_ca =
            CertificatePem::new("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
                .unwrap();
        MtlsConfig::new(MtlsMode::Optional, vec![her_ca]).unwrap()
    }

    fn allowing_impersonation(limits: &ComplianceLimits) -> CompliancePosture {
        CompliancePosture::new(
            Residency::Anywhere,
            365,
            OperatorImpersonation::Allowed,
            limits,
        )
        .unwrap()
    }

    /// Acme Corp is renamed to Acme Industries by an admin. The new name
    /// reads back and the last-changed time does not go backwards.
    #[test]
    fn an_admin_renames_the_tenant() {
        let ann = person("ann@acme.test");
        let mut tenant = active();
        let before = tenant.updated_at();
        let name = DisplayName::new("Acme Industries", &DisplayNameLimits::default()).unwrap();

        tenant.rename(holding(&ann, &tenant, ADMIN), name).unwrap();

        assert_eq!(tenant.display_name().as_str(), "Acme Industries");
        assert!(tenant.updated_at() >= before);
    }

    /// A settings viewer cannot redirect the tenant's notices to another
    /// mailbox; the existing contact address remains.
    #[test]
    fn someone_who_may_only_view_settings_cannot_redirect_security_notices() {
        let sam = person("sam@acme.test");
        let mut tenant = active();

        let refused = tenant.change_contact_email(
            holding(&sam, &tenant, VIEW_ONLY),
            Email::new("sam@evil.test").unwrap(),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(tenant.contact_email().as_str(), "admin@acme.com");
    }

    /// An admin moves the tenant to `America/New_York` and `de-DE`. Both read
    /// back.
    #[test]
    fn an_admin_changes_the_timezone_and_locale() {
        let ann = person("ann@acme.test");
        let mut tenant = active();

        tenant
            .change_timezone(
                holding(&ann, &tenant, ADMIN),
                Timezone::new("America/New_York").unwrap(),
            )
            .unwrap();
        tenant
            .change_locale(holding(&ann, &tenant, ADMIN), Locale::new("de-DE").unwrap())
            .unwrap();

        assert_eq!(tenant.timezone().as_str(), "America/New_York");
        assert_eq!(tenant.locale().as_str(), "de-DE");
    }

    /// An administrator cannot change an archived tenant's contact address.
    #[test]
    fn a_closed_tenant_takes_no_changes() {
        let ann = person("ann@acme.test");
        let mut tenant = active();
        tenant.archive(ActedBy::Platform).unwrap();

        let refused = tenant.change_contact_email(
            holding(&ann, &tenant, ADMIN),
            Email::new("ops@acme.com").unwrap(),
        );

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
    }

    /// Acme proves `auth.acme.com` and makes it the primary domain. It reads
    /// back, and is let go again once the domain leaves the tenant.
    #[test]
    fn a_proved_domain_becomes_primary_and_is_let_go_when_it_leaves() {
        let ann = person("ann@acme.test");
        let mut tenant = active();
        let owned = proved_domain(&tenant, "auth.acme.com");
        let name = owned.domain().clone();

        tenant
            .change_primary_domain(holding(&ann, &tenant, ADMIN), Setting::Set(owned))
            .unwrap();
        assert_eq!(tenant.primary_domain(), Some(&name));

        assert_eq!(tenant.release_domain(&name), Some(name));
        assert_eq!(tenant.primary_domain(), None);
    }

    /// A domain proved by another tenant cannot become the primary domain.
    /// The receiving tenant remains without a primary domain.
    #[test]
    fn a_domain_another_tenant_proved_cannot_become_primary() {
        let eve = person("eve@evil.test");
        let globex = active();
        let mut evil = active();

        let refused = evil.change_primary_domain(
            holding(&eve, &evil, ADMIN),
            Setting::Set(proved_domain(&globex, "globex.com")),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(evil.primary_domain(), None);
    }

    /// Five minutes after provisioning, an admin who just signed in again
    /// cuts sessions to two hours. The new lifetime applies and the
    /// last-changed time moves to that moment, which caches read to notice
    /// the edit.
    #[test]
    fn an_admin_who_proved_themselves_again_changes_the_sign_in_settings() {
        let session = signed_in_session();
        let ann = holder_of(&session, "ann@acme.test");
        let mut tenant = active();
        let later = tenant.updated_at() + time::Duration::minutes(5);

        let _frozen = crate::shared::clock::freeze(later);
        tenant
            .update_auth_config(
                holding(&ann, &tenant, ADMIN),
                &ProvedJustNow::by(&ann),
                saved_through(shorter_sessions(), &session),
            )
            .unwrap();

        assert_eq!(
            tenant.auth_config().session_lifetime_secs(),
            Seconds::new(7_200)
        );
        assert_eq!(tenant.updated_at(), later);
    }

    /// Fresh proof from another person cannot authorize a sign-in settings
    /// change, and the tenant keeps its default configuration.
    #[test]
    fn a_stolen_session_alone_cannot_change_the_sign_in_settings() {
        let session = signed_in_session();
        let ann = holder_of(&session, "ann@acme.test");
        let mallory = person("mallory@evil.test");
        let mut tenant = active();

        let refused = tenant.update_auth_config(
            holding(&ann, &tenant, ADMIN),
            &ProvedJustNow::by(&mallory),
            saved_through(shorter_sessions(), &session),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(tenant.auth_config(), &TenantAuthConfig::default());
    }

    /// A settings viewer's fresh proof does not grant permission to change
    /// the sign-in configuration.
    #[test]
    fn a_fresh_proof_does_not_replace_the_right() {
        let session = signed_in_session();
        let sam = holder_of(&session, "sam@acme.test");
        let mut tenant = active();

        let refused = tenant.update_auth_config(
            holding(&sam, &tenant, VIEW_ONLY),
            &ProvedJustNow::by(&sam),
            saved_through(shorter_sessions(), &session),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// An administrator signed in with a password cannot save passkey-only
    /// settings that would exclude their current sign-in method.
    #[test]
    fn an_admin_cannot_save_settings_that_shut_out_their_own_sign_in() {
        let session = signed_in_session();
        let ann = holder_of(&session, "ann@acme.test");
        let mut tenant = active();
        let passkeys_only = TenantAuthConfig::new(TenantAuthSettings {
            enabled_methods: vec![AuthMethod::Passkey],
            ..TenantAuthSettings::default()
        })
        .unwrap();

        let refused = tenant.update_auth_config(
            holding(&ann, &tenant, ADMIN),
            &ProvedJustNow::by(&ann),
            saved_through(passkeys_only, &session),
        );

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Mutual TLS rejects proof from another person, then accepts the
    /// administrator's own fresh proof and enables optional client certificates.
    #[test]
    fn a_stolen_session_alone_cannot_change_mutual_tls() {
        let ann = person("ann@acme.test");
        let mut tenant = active();

        let refused = tenant.update_mtls(
            holding(&ann, &tenant, ADMIN),
            &ProvedJustNow::by(&person("mallory@evil.test")),
            their_ca(),
        );
        let allowed = tenant.update_mtls(
            holding(&ann, &tenant, ADMIN),
            &ProvedJustNow::by(&ann),
            their_ca(),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(allowed.is_ok());
        assert_eq!(tenant.mtls().mode(), MtlsMode::Optional);
    }

    /// A settings viewer cannot enable mutual TLS even with fresh proof.
    /// Mutual TLS remains disabled.
    #[test]
    fn someone_who_may_only_view_settings_cannot_change_mutual_tls() {
        let sam = person("sam@acme.test");
        let mut tenant = active();

        let refused = tenant.update_mtls(
            holding(&sam, &tenant, VIEW_ONLY),
            &ProvedJustNow::by(&sam),
            their_ca(),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(tenant.mtls().mode(), MtlsMode::Disabled);
    }

    /// Proof from another person cannot authorize a compliance change that
    /// enables operator impersonation, which remains forbidden.
    #[test]
    fn a_stolen_session_alone_cannot_change_the_compliance_posture() {
        let ann = person("ann@acme.test");
        let mut tenant = active();
        let limits = ComplianceLimits::default();

        let refused = tenant.change_compliance(
            holding(&ann, &tenant, ADMIN),
            &ProvedJustNow::by(&person("mallory@evil.test")),
            allowing_impersonation(&limits),
            &limits,
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(
            tenant.compliance().operator_impersonation(),
            OperatorImpersonation::Forbidden
        );
    }

    /// A settings viewer cannot enable operator impersonation even with their
    /// own fresh proof.
    #[test]
    fn someone_who_may_only_view_settings_cannot_change_the_compliance_posture() {
        let sam = person("sam@acme.test");
        let mut tenant = active();
        let limits = ComplianceLimits::default();

        let refused = tenant.change_compliance(
            holding(&sam, &tenant, VIEW_ONLY),
            &ProvedJustNow::by(&sam),
            allowing_impersonation(&limits),
            &limits,
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Deployment limits requiring EU residency reject a posture allowing data
    /// anywhere. The tenant's existing unrestricted residency setting remains.
    #[test]
    fn a_posture_the_deployment_does_not_allow_is_refused() {
        let ann = person("ann@acme.test");
        let mut tenant = active();
        let eu_only = ComplianceLimits::new(ComplianceLimitsParams {
            default_data_residency: Residency::Within(DataResidency::Eu),
            ..ComplianceLimitsParams::default()
        })
        .unwrap();

        let refused = tenant.change_compliance(
            holding(&ann, &tenant, ADMIN),
            &ProvedJustNow::by(&ann),
            allowing_impersonation(&eu_only),
            &eu_only,
        );

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert_eq!(tenant.compliance().data_residency(), Residency::Anywhere);
    }

    /// Operators may not act as a new tenant's users. Acme's admin turns it
    /// on for a support case. The posture changes, and
    /// `tenant.compliance_changed` is raised with the setting before and
    /// after.
    #[test]
    fn an_admin_opts_in_to_operator_impersonation() {
        let ann = person("ann@acme.test");
        let mut tenant = fresh();
        let limits = ComplianceLimits::default();

        tenant
            .change_compliance(
                holding(&ann, &tenant, ADMIN),
                &ProvedJustNow::by(&ann),
                allowing_impersonation(&limits),
                &limits,
            )
            .unwrap();

        assert_eq!(
            tenant.compliance().operator_impersonation(),
            OperatorImpersonation::Allowed
        );
        let events = tenant.take_events();
        assert_eq!(
            events[0].event_type().to_string(),
            "tenant.compliance_changed"
        );
        assert_eq!(
            change(&events[0], "operator_impersonation"),
            (Some("forbidden".to_owned()), Some("allowed".to_owned()))
        );
    }

    /// Acme's tenant, active, with what it raised so far taken out.
    fn fresh() -> Tenant {
        let mut tenant = active();
        raised_complete_names(&mut tenant);
        tenant
    }

    fn change(event: &DomainEvent, key: &str) -> (Option<String>, Option<String>) {
        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value(key) else {
            panic!("{key} is not recorded as a change");
        };
        (
            change.from().map(str::to_owned),
            change.to().map(str::to_owned),
        )
    }

    /// Ann renames Acme Corp to Acme Industries and moves its notices to
    /// `security@acme.com`, its timezone to Berlin and its locale to
    /// German. Each change is raised in order, the rename with both names.
    #[test]
    fn each_profile_change_raises_its_record() {
        let ann = person("ann@acme.test");
        let mut tenant = fresh();
        let by = holding(&ann, &tenant, ADMIN);
        change_profile(&mut tenant, by);

        let events = tenant.take_events();
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type().to_string())
                .collect::<Vec<_>>(),
            [
                "tenant.renamed",
                "tenant.contact_email_changed",
                "tenant.timezone_changed",
                "tenant.locale_changed"
            ]
        );
        assert_eq!(
            change(&events[0], "name"),
            (
                Some("Acme Corp".to_owned()),
                Some("Acme Industries".to_owned())
            )
        );
        assert_eq!(events[0].tenant_id(), Some(tenant.id()));
    }

    /// Changes the name, notice address, timezone and locale in that order.
    fn change_profile(tenant: &mut Tenant, by: TenantControl<'_>) {
        let name = DisplayName::new("Acme Industries", &DisplayNameLimits::default()).unwrap();
        tenant.rename(by, name).unwrap();
        tenant
            .change_contact_email(by, Email::new("security@acme.com").unwrap())
            .unwrap();
        tenant
            .change_timezone(by, Timezone::new("Europe/Berlin").unwrap())
            .unwrap();
        tenant
            .change_locale(by, Locale::new("de-DE").unwrap())
            .unwrap();
    }

    /// Acme makes `auth.acme.com` its primary domain and later lets it go.
    /// Both moves are raised, from none to the domain and back.
    #[test]
    fn setting_and_releasing_the_primary_domain_raise_both_moves() {
        let ann = person("ann@acme.test");
        let mut tenant = fresh();
        let owned = proved_domain(&tenant, "auth.acme.com");
        let name = owned.domain().clone();

        tenant
            .change_primary_domain(holding(&ann, &tenant, ADMIN), Setting::Set(owned))
            .unwrap();
        tenant.release_domain(&name);

        let events = tenant.take_events();
        assert_eq!(
            change(&events[0], "domain"),
            (None, Some("auth.acme.com".to_owned()))
        );
        assert_eq!(
            change(&events[1], "domain"),
            (Some("auth.acme.com".to_owned()), None)
        );
    }

    /// A domain that was never Acme's primary one is let go. Nothing
    /// changes, so nothing is raised.
    #[test]
    fn releasing_a_domain_that_was_not_primary_raises_nothing() {
        let mut tenant = fresh();

        let released = tenant.release_domain(&DomainName::new("other.acme.com").unwrap());

        assert_eq!(released, None);
        assert!(raised_complete_names(&mut tenant).is_empty());
    }

    /// Ann, who just proved herself again, changes the sign-in settings and
    /// mutual TLS. Each is raised.
    #[test]
    fn protected_settings_changes_raise_their_records() {
        let session = signed_in_session();
        let ann = holder_of(&session, "ann@acme.test");
        let mut tenant = fresh();

        tenant
            .update_auth_config(
                holding(&ann, &tenant, ADMIN),
                &ProvedJustNow::by(&ann),
                saved_through(shorter_sessions(), &session),
            )
            .unwrap();
        tenant
            .update_mtls(
                holding(&ann, &tenant, ADMIN),
                &ProvedJustNow::by(&ann),
                their_ca(),
            )
            .unwrap();

        assert_eq!(
            raised_complete_names(&mut tenant),
            ["tenant.auth_config_updated", "tenant.mtls_config_updated"]
        );
    }

    /// A rename by a settings viewer and a mutual TLS change with another
    /// person's proof are refused without raising events.
    #[test]
    fn a_refused_settings_change_raises_nothing() {
        let sam = person("sam@acme.test");
        let ann = person("ann@acme.test");
        let mut tenant = fresh();
        let name = DisplayName::new("Sam Corp", &DisplayNameLimits::default()).unwrap();

        let renamed = tenant.rename(holding(&sam, &tenant, VIEW_ONLY), name);
        let mtls = tenant.update_mtls(
            holding(&ann, &tenant, ADMIN),
            &ProvedJustNow::by(&person("mallory@evil.test")),
            their_ca(),
        );

        assert!(renamed.is_err());
        assert!(mtls.is_err());
        assert!(raised_complete_names(&mut tenant).is_empty());
    }

    /// A tenant placed in Frankfurt cannot declare US data residency.
    #[test]
    fn a_residency_the_placement_breaks_is_refused() {
        let ann = person("ann@acme.test");
        let mut tenant = active();
        let limits = ComplianceLimits::default();
        let us = CompliancePosture::new(
            Residency::Within(DataResidency::Us),
            365,
            OperatorImpersonation::Allowed,
            &limits,
        )
        .unwrap();

        let refused = tenant.change_compliance(
            holding(&ann, &tenant, ADMIN),
            &ProvedJustNow::by(&ann),
            us,
            &limits,
        );

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Ann labels Acme's tenant as staging. The label reads back and
    /// `tenant.environment_changed` is raised.
    #[test]
    fn an_admin_labels_the_tenant_staging() {
        let ann = person("ann@acme.test");
        let mut tenant = active();
        let _ = tenant.take_events();

        tenant
            .change_environment(holding(&ann, &tenant, ADMIN), TenantEnvironment::Staging)
            .unwrap();

        assert_eq!(tenant.environment(), TenantEnvironment::Staging);
        assert_eq!(
            raised_complete_names(&mut tenant),
            vec!["tenant.environment_changed"]
        );
    }

    /// A settings viewer cannot relabel the tenant as development, and its
    /// production environment label remains.
    #[test]
    fn a_viewer_cannot_relabel_the_environment() {
        let sam = person("sam@acme.test");
        let mut tenant = active();

        let refused = tenant.change_environment(
            holding(&sam, &tenant, VIEW_ONLY),
            TenantEnvironment::Development,
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(tenant.environment(), TenantEnvironment::Production);
    }

    /// A tenant of Acme's organization in another timezone, just
    /// provisioned by the platform.
    fn staging_of(production: &Tenant) -> Tenant {
        Tenant::provision(
            crate::domains::tenant::lifecycle::ProvisionTenantParams {
                id: crate::types::TenantId::new(),
                organization_id: *production.organization_id(),
                timezone: Timezone::new("Asia/Tokyo").unwrap(),
                ..crate::domains::tenant::fixtures::acme_params()
            },
            &ComplianceLimits::default(),
            ActedBy::Platform,
        )
        .unwrap()
    }

    /// Ann's production tenant runs in New York time with mutual TLS. A
    /// settings clone into staging gives staging both.
    #[test]
    fn a_settings_clone_copies_the_settings() {
        let ann = person("ann@acme.test");
        let mut production = active();
        production
            .change_timezone(
                holding(&ann, &production, ADMIN),
                Timezone::new("America/New_York").unwrap(),
            )
            .unwrap();
        production
            .update_mtls(
                holding(&ann, &production, ADMIN),
                &ProvedJustNow::by(&ann),
                their_ca(),
            )
            .unwrap();
        let mut staging = staging_of(&production);
        let clone = TenantClone::start(
            vec![ClonePart::Settings],
            &production,
            &staging,
            ActedBy::Platform,
        )
        .unwrap();

        staging.copy_settings_from(&production, &clone).unwrap();

        assert_eq!(staging.timezone().as_str(), "America/New_York");
        assert_eq!(staging.mtls().mode(), MtlsMode::Optional);
        assert_eq!(staging.mtls().trusted_ca_certs().len(), 1);
    }

    /// A routes-only clone cannot copy settings, and a settings clone cannot
    /// copy into a third tenant. Both target timezones remain unchanged.
    #[test]
    fn a_clone_copies_settings_only_where_it_says() {
        let production = active();
        let mut staging = staging_of(&production);
        let mut third = staging_of(&production);
        let routes_only = TenantClone::start(
            vec![ClonePart::Routes],
            &production,
            &staging,
            ActedBy::Platform,
        )
        .unwrap();
        let settings = TenantClone::start(
            vec![ClonePart::Settings],
            &production,
            &staging,
            ActedBy::Platform,
        )
        .unwrap();

        let without_the_part = staging.copy_settings_from(&production, &routes_only);
        let elsewhere = third.copy_settings_from(&production, &settings);

        assert!(matches!(without_the_part, Err(DomainError::Forbidden(_))));
        assert!(matches!(elsewhere, Err(DomainError::Forbidden(_))));
        assert_eq!(staging.timezone().as_str(), "Asia/Tokyo");
        assert_eq!(third.timezone().as_str(), "Asia/Tokyo");
    }
}
