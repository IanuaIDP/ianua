//! Whether a tenant lets someone in at all, before any credential is looked
//! at.
//!
//! Every way of signing in asks the same questions. Is the workspace open?
//! Does it accept this method? Is the caller at an address it allows? They
//! are asked in one place, so a new sign-in method cannot skip one.
//!
//! The same questions keep an admin from saving settings that would turn
//! away their own sign-in, see [`SignInChange`].

use crate::domains::authentication::admission::{SignInAdmitted, allowlist_admits};
use crate::domains::authentication::methods::AuthMethod;
use crate::domains::authentication::sessions::session::Session;
use crate::domains::tenant::access::auth_config::TenantAuthConfig;
use crate::domains::tenant::lifecycle::Tenant;
use crate::domains::tenant::status::TenantStatus;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{Fact, Human, HumanAccount, IpAddress, UserId};

/// Why a tenant refused a sign-in before looking at who it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInRefusal {
    /// The workspace is suspended, archived or deleted.
    Unavailable(TenantStatus),
    /// The workspace has switched this way of signing in off.
    MethodOff(AuthMethod),
    /// The workspace admits only listed addresses. The caller's address is
    /// not on the list, or is not known.
    AddressNotAllowed,
    /// Every sign-in must reach an assurance level this method never can.
    ///
    /// At AAL3 only a passkey or a provider proving a hardware key gets in.
    /// At AAL2 with second factors off, only a passkey or single sign-on does.
    PasskeyOnly,
}

impl Tenant {
    /// Whether someone may sign in to this tenant with `method` from
    /// `client_ip`.
    ///
    /// The [`SignInAdmitted`] it gives is the proof every credential check
    /// then takes.
    ///
    /// # Errors
    ///
    /// - [`SignInRefusal::Unavailable`] when the tenant is suspended,
    ///   archived or deleted.
    /// - Otherwise the first refusal from [`TenantAuthConfig::admits`].
    pub fn admits_sign_in(
        &self,
        method: AuthMethod,
        client_ip: Fact<&IpAddress>,
    ) -> Result<SignInAdmitted, SignInRefusal> {
        if !self.status().is_open() {
            return Err(SignInRefusal::Unavailable(self.status()));
        }
        self.auth_config().admits(method, client_ip)
    }
}

impl TenantAuthConfig {
    /// Whether this configuration accepts `method` from `client_ip`.
    ///
    /// The address list is read as `allowlist_admits` reads every list.
    ///
    /// A method that can never reach the tenant's baseline assurance is
    /// refused here, see [`AuthMethod::can_reach`]. This happens before any
    /// user is looked up, so every email gets the same answer. Single sign-on
    /// passes at any baseline. Whether the provider proved enough is decided
    /// when the session is completed.
    ///
    /// # Errors
    ///
    /// - [`SignInRefusal::MethodOff`] when the tenant has switched `method`
    ///   off.
    /// - [`SignInRefusal::PasskeyOnly`] when `method` can never reach the
    ///   baseline assurance.
    /// - [`SignInRefusal::AddressNotAllowed`] when an address list is set and
    ///   `client_ip` is not on it or is unknown.
    pub fn admits(
        &self,
        method: AuthMethod,
        client_ip: Fact<&IpAddress>,
    ) -> Result<SignInAdmitted, SignInRefusal> {
        if !self.is_method_enabled(method) {
            return Err(SignInRefusal::MethodOff(method));
        }
        let baseline = self.step_up_policy().baseline_aal();
        if !method.can_reach(baseline, self.mfa_policy()) {
            return Err(SignInRefusal::PasskeyOnly);
        }
        if !allowlist_admits(self.ip_allowlist(), client_ip) {
            return Err(SignInRefusal::AddressNotAllowed);
        }
        Ok(SignInAdmitted::new(method, client_ip))
    }
}

/// Where the person saving new sign-in settings signed in.
#[derive(Debug, Clone, Copy)]
pub enum SavedFrom<'a> {
    /// A user of this tenant, signed in to it through this session. Built
    /// only by [`SavedFrom::from_session`].
    TenantSignIn(SessionSignIn<'a>),
    /// A member of the organization. They sign in to the organization, not
    /// to this tenant, so its settings cannot shut them out.
    Organization,
}

/// How and from where a tenant user's session signed in, as the session
/// records it.
///
/// Its fields are private, so the method and address are the ones the
/// session holds, never ones a caller wrote in.
#[derive(Debug, Clone, Copy)]
pub struct SessionSignIn<'a> {
    user: UserId,
    method: AuthMethod,
    client_ip: Fact<&'a IpAddress>,
}

impl<'a> SavedFrom<'a> {
    /// The sign-in `session` records: its account, method and address.
    #[must_use]
    pub fn from_session<T: TenantScope>(session: &'a Session<T>) -> Self {
        Self::TenantSignIn(SessionSignIn {
            user: *session.user_id(),
            method: session.auth_method(),
            client_ip: session.ip_address(),
        })
    }
}

/// New sign-in settings, with where the person saving them signed in.
#[derive(Debug, Clone)]
pub struct SignInChange<'a> {
    /// The settings to put in force.
    pub config: TenantAuthConfig,
    /// Where the person saving them signed in.
    pub saved_from: SavedFrom<'a>,
}

impl SignInChange<'_> {
    /// Refuses settings that would not let `by` sign in again the way they
    /// did just now.
    ///
    /// Ann is the only admin. Without this, she saves an address list
    /// without her own address, or turns off the one method she uses. Nobody
    /// could sign in to change it back. A member of the organization signs
    /// in elsewhere and can always mend the tenant, so only a tenant user is
    /// checked.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the sign-in named is not the kind
    ///   `by` acts through, or is another account's session.
    /// - [`DomainError::Validation`] when the settings would turn that
    ///   sign-in away.
    pub(crate) fn ensure_keeps_in(&self, by: &Human) -> Result<(), DomainError> {
        match (by.account(), self.saved_from) {
            (HumanAccount::OrgUser(_), SavedFrom::Organization) => Ok(()),
            (HumanAccount::User(user), SavedFrom::TenantSignIn(sign_in)) => {
                self.ensure_admits(user, sign_in)
            }
            (HumanAccount::User(_), SavedFrom::Organization)
            | (HumanAccount::OrgUser(_), SavedFrom::TenantSignIn(_)) => Err(not_theirs()),
        }
    }

    /// Refuses a session of another account, or settings that would turn
    /// the session's sign-in away.
    fn ensure_admits(&self, user: UserId, sign_in: SessionSignIn<'_>) -> Result<(), DomainError> {
        if sign_in.user != user {
            return Err(not_theirs());
        }
        self.config
            .admits(sign_in.method, sign_in.client_ip)
            .map(|_| ())
            .map_err(shut_out)
    }
}

/// The refusal for a sign-in that is not the one the person acts through.
fn not_theirs() -> DomainError {
    DomainError::forbidden(message!(
        "tenant-the-sign-in-named-is-not",
        "the sign-in named is not the one the person acts through"
    ))
}

/// The refusal for settings that would turn away the sign-in of the person
/// saving them.
fn shut_out(refusal: SignInRefusal) -> DomainError {
    let reason = match refusal {
        SignInRefusal::Unavailable(_) => "the tenant is closed",
        SignInRefusal::MethodOff(_) => "they turn off the way you signed in",
        SignInRefusal::AddressNotAllowed => "they do not allow the address you are at",
        SignInRefusal::PasskeyOnly => "they ask more than the way you signed in can give",
    };
    DomainError::invalid(message!(
        "tenant-these-settings-would-shut-you-out",
        format!("these settings would shut you out: {reason}")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::risk_engine::assessment::RiskLevel;
    use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use crate::domains::authentication::risk_engine::step_up::{
        MfaTrigger, StepUpPolicy, StepUpPolicyParams,
    };
    use crate::domains::authentication::sessions::session::tests::signed_in_session;
    use crate::domains::tenant::access::auth_config::TenantAuthSettings;
    use crate::domains::tenant::fixtures::holder_of;
    use crate::types::{CidrRange, OrgUserId, PersonKey};

    fn tenant_user() -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("ann@acme.test").unwrap(),
        )
    }

    fn org_member() -> Human {
        Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            PersonKey::new("olga@acme.test").unwrap(),
        )
    }

    fn saved_through<T: TenantScope>(
        config: TenantAuthConfig,
        session: &Session<T>,
    ) -> SignInChange<'_> {
        SignInChange {
            config,
            saved_from: SavedFrom::from_session(session),
        }
    }

    /// A settings change excluding the caller's session address is rejected,
    /// while a list containing that address passes the admission check.
    #[test]
    fn an_admin_cannot_save_an_address_list_without_their_own_address() {
        let session = signed_in_session();
        let ann = holder_of(&session, "ann@acme.test");

        let without_her = saved_through(
            config(vec![AuthMethod::Password], vec!["192.168.0.0/16"]),
            &session,
        );
        let with_her = saved_through(
            config(vec![AuthMethod::Password], vec!["10.0.0.0/8"]),
            &session,
        );

        assert!(matches!(
            without_her.ensure_keeps_in(&ann),
            Err(DomainError::Validation(_))
        ));
        assert!(with_her.ensure_keeps_in(&ann).is_ok());
    }

    /// A password-authenticated caller cannot save passkey-only settings
    /// because those settings exclude the method recorded in their session.
    #[test]
    fn the_saved_sign_in_is_the_one_the_session_records() {
        let session = signed_in_session();
        let ann = holder_of(&session, "ann@acme.test");

        let change = saved_through(config(vec![AuthMethod::Passkey], Vec::new()), &session);

        assert!(matches!(
            change.ensure_keeps_in(&ann),
            Err(DomainError::Validation(_))
        ));
    }

    /// Another user's session cannot satisfy the settings admission check,
    /// even when its address and method fit the proposed settings.
    #[test]
    fn a_tenant_user_cannot_name_another_accounts_session() {
        let bobs = signed_in_session();
        let mallory = tenant_user();

        let change = saved_through(
            config(vec![AuthMethod::Password], vec!["10.0.0.0/8"]),
            &bobs,
        );

        assert!(matches!(
            change.ensure_keeps_in(&mallory),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Olga, a member of the organization, saves the same narrow list. It is
    /// accepted, since she signs in to the organization and can always mend
    /// the tenant.
    #[test]
    fn an_organization_member_is_not_shut_out_by_tenant_settings() {
        let change = SignInChange {
            config: config(vec![AuthMethod::Passkey], vec!["10.0.0.0/8"]),
            saved_from: SavedFrom::Organization,
        };

        assert!(change.ensure_keeps_in(&org_member()).is_ok());
    }

    /// A tenant user cannot bypass the session admission check by claiming
    /// the settings change comes from an organization sign-in.
    #[test]
    fn a_tenant_user_cannot_claim_to_sign_in_through_the_organization() {
        let change = SignInChange {
            config: config(vec![AuthMethod::Passkey], vec!["10.0.0.0/8"]),
            saved_from: SavedFrom::Organization,
        };

        assert!(matches!(
            change.ensure_keeps_in(&tenant_user()),
            Err(DomainError::Forbidden(_))
        ));
    }

    fn config(methods: Vec<AuthMethod>, allowlist: Vec<&str>) -> TenantAuthConfig {
        TenantAuthConfig::new(TenantAuthSettings {
            enabled_methods: methods,
            ip_allowlist: allowlist
                .into_iter()
                .map(|range| CidrRange::new(range).unwrap())
                .collect(),
            ..TenantAuthSettings::default()
        })
        .unwrap()
    }

    fn ip(value: &str) -> IpAddress {
        IpAddress::new(value).unwrap()
    }

    /// A tenant turns on magic links and sets no address list. A magic link
    /// sign-in from an unknown address is let through.
    #[test]
    fn an_enabled_method_with_no_address_list_is_admitted() {
        let config = config(vec![AuthMethod::MagicLink], Vec::new());

        assert!(config.admits(AuthMethod::MagicLink, Fact::Unknown).is_ok());
    }

    /// Password-only settings reject magic-link admission and identify
    /// magic links as the disabled method.
    #[test]
    fn a_method_switched_off_is_refused() {
        let config = config(vec![AuthMethod::Password], Vec::new());

        assert_eq!(
            config.admits(AuthMethod::MagicLink, Fact::Known(&ip("10.0.0.1"))),
            Err(SignInRefusal::MethodOff(AuthMethod::MagicLink))
        );
    }

    /// An address list admits a passkey request from its listed network
    /// and rejects one from a different private network.
    #[test]
    fn an_address_list_admits_only_listed_addresses() {
        let config = config(vec![AuthMethod::Passkey], vec!["10.0.0.0/8"]);

        assert!(
            config
                .admits(AuthMethod::Passkey, Fact::Known(&ip("10.1.2.3")))
                .is_ok()
        );
        assert_eq!(
            config.admits(AuthMethod::Passkey, Fact::Known(&ip("192.168.1.1"))),
            Err(SignInRefusal::AddressNotAllowed)
        );
    }

    fn passkey_only(methods: Vec<AuthMethod>) -> TenantAuthConfig {
        TenantAuthConfig::new(TenantAuthSettings {
            step_up_policy: StepUpPolicy::new(StepUpPolicyParams {
                baseline_aal: AssuranceLevel::Aal3,
                sensitive_aal: AssuranceLevel::Aal3,
                new_device: MfaTrigger::Ignored,
                new_country: MfaTrigger::Ignored,
                mfa_risk_threshold: RiskLevel::Critical,
                deny_risk_threshold: RiskLevel::Critical,
            })
            .unwrap(),
            ..config(methods, Vec::new()).settings().clone()
        })
        .unwrap()
    }

    /// An AAL3 baseline rejects password and magic-link admission even when
    /// those methods are enabled in the tenant's settings.
    #[test]
    fn passwords_and_magic_links_are_refused_while_every_sign_in_must_be_a_passkey() {
        let config = passkey_only(vec![
            AuthMethod::Password,
            AuthMethod::MagicLink,
            AuthMethod::Passkey,
        ]);

        assert_eq!(
            config.admits(AuthMethod::Password, Fact::Unknown),
            Err(SignInRefusal::PasskeyOnly)
        );
        assert_eq!(
            config.admits(AuthMethod::MagicLink, Fact::Unknown),
            Err(SignInRefusal::PasskeyOnly)
        );
    }

    /// A tenant requires AAL3 for every sign-in. Passkeys and SAML are still
    /// let through here. Whether the provider proved enough is checked when
    /// the session is completed.
    #[test]
    fn passkeys_and_single_sign_on_still_get_in_while_every_sign_in_must_be_a_passkey() {
        let config = passkey_only(vec![AuthMethod::Passkey, AuthMethod::Saml]);

        assert!(config.admits(AuthMethod::Passkey, Fact::Unknown).is_ok());
        assert!(config.admits(AuthMethod::Saml, Fact::Unknown).is_ok());
    }

    /// An enabled passkey method still rejects an unknown client address
    /// when an address list is configured.
    #[test]
    fn an_unknown_address_is_refused_while_a_list_is_set() {
        let config = config(vec![AuthMethod::Passkey], vec!["10.0.0.0/8"]);

        assert_eq!(
            config.admits(AuthMethod::Passkey, Fact::Unknown),
            Err(SignInRefusal::AddressNotAllowed)
        );
    }
}
