//! A member's sign-in begun through a way in, before its session opens.

use crate::domains::authentication::mfa::owed::SecondFactor;
use crate::domains::authentication::sessions::sign_in_progress::{SignInProgress, SignInRefused};
use crate::domains::authentication::sessions::way_in::WayIn;
use crate::domains::organization::access::auth_config::OrganizationAuthConfig;
use crate::domains::organization::access::identity_provider::OrgProviderProof;
use crate::domains::organization::members::org_user::OrgUser;
use crate::types::{OrgUserId, PrincipalId};

/// A member's sign-in, begun through a way in proved for that member.
///
/// An org session opens only from one, for the member it names. So no way
/// in opens a session for a member it was not proved for. Mallory's own
/// password never opens a session for Ann, whatever address was typed. And
/// every sign-in is held to the organization's settings here, so none skips
/// the single sign-on it enforces.
#[derive(Debug)]
pub struct OrgSignInStart {
    member: OrgUserId,
    progress: SignInProgress,
}

impl OrgSignInStart {
    /// The sign-in `way_in` begins for `member`, owing `owed`, under the
    /// organization's `config`. The way in is spent on it, so one proof
    /// opens one session. Whether the member may sign in at all is asked
    /// when the session opens.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::ForAnotherAccount`] when `way_in` was proved for
    ///   someone else.
    /// - [`SignInRefused::WayInNotAllowed`] when the organization enforces
    ///   single sign-on and `member` is not an owner. See
    ///   [`OrganizationAuthConfig::ensure_may_skip_sso`].
    /// - [`SignInRefused::BelowBaseline`] when nothing more is owed and the
    ///   way in alone falls short of the organization's baseline.
    pub fn new(
        member: &OrgUser,
        way_in: WayIn,
        owed: SecondFactor,
        config: &OrganizationAuthConfig,
    ) -> Result<Self, SignInRefused> {
        if way_in.account() != PrincipalId::from(*member.id()) {
            return Err(SignInRefused::ForAnotherAccount);
        }
        config
            .ensure_may_skip_sso(member)
            .map_err(|_| SignInRefused::WayInNotAllowed)?;
        Ok(Self {
            member: *member.id(),
            progress: SignInProgress::start(way_in, owed, config.step_up_policy())?,
        })
    }

    /// The sign-in the organization's identity provider vouched for in
    /// `proof` (made only by
    /// [`OrgIdentityProvider::vouch`](crate::domains::organization::access::identity_provider::OrgIdentityProvider::vouch)),
    /// begun for `member`, owing `owed` unless the provider proved a factor.
    ///
    /// The provider names a person by the address it proved. Only the
    /// member holding that address is signed in. Mallory runs an identity
    /// provider of her own; without the address check, any sign-in it
    /// vouches for would open Ann's account. The connection is the
    /// organization's, and it reports a factor only when trusted to, and
    /// never for an owner.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::WayInNotAllowed`] when the organization has not
    ///   enabled the provider's protocol.
    /// - [`SignInRefused::ForAnotherAccount`] when the address the provider
    ///   proved is not `member`'s.
    /// - [`SignInRefused::BelowBaseline`] when nothing more is owed and the
    ///   sign-in falls short of the organization's baseline.
    pub fn through_provider(
        member: &OrgUser,
        proof: OrgProviderProof,
        owed: SecondFactor,
        config: &OrganizationAuthConfig,
    ) -> Result<Self, SignInRefused> {
        if !config.is_method_enabled(proof.sign_in().method()) {
            return Err(SignInRefused::WayInNotAllowed);
        }
        if proof.address().as_email() != member.email() {
            return Err(SignInRefused::ForAnotherAccount);
        }
        let (sign_in, _) = proof.into_parts();
        let progress =
            SignInProgress::begin_through_provider(sign_in, owed, config.step_up_policy())?;
        Ok(Self {
            member: *member.id(),
            progress,
        })
    }

    /// The member the sign-in was begun for.
    #[must_use]
    pub fn member(&self) -> &OrgUserId {
        &self.member
    }

    /// How far the sign-in has come.
    #[must_use]
    pub fn progress(&self) -> &SignInProgress {
        &self.progress
    }

    /// The member and the sign-in, taken apart by the session that opens
    /// from them.
    pub(crate) fn into_parts(self) -> (OrgUserId, SignInProgress) {
        (self.member, self.progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::methods::AuthMethod;
    use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use crate::domains::authentication::sessions::mfa_factor::FactorProved;
    use crate::domains::authentication::sessions::sign_in_progress::{
        FederatedMethod, ProviderSignIn,
    };
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::domains::organization::access::auth_config::{
        OrganizationAuthSettings, SsoEnforcement,
    };
    use crate::domains::organization::members::control::tests::{founder, member_of};
    use crate::types::Email;

    fn config(sso: SsoEnforcement) -> OrganizationAuthConfig {
        OrganizationAuthConfig::new(OrganizationAuthSettings {
            enabled_methods: vec![AuthMethod::Password, AuthMethod::Saml],
            step_up_policy: StepUpPolicy::relaxed(),
            sso,
            ..OrganizationAuthSettings::default()
        })
        .unwrap()
    }

    fn saml() -> ProviderSignIn {
        ProviderSignIn::new(FederatedMethod::Saml, FactorProved::NoneYet)
    }

    fn password_of(member: &OrgUser) -> WayIn {
        WayIn::by_password((*member.id()).into())
    }

    /// Enforced single sign-on prevents a plain member from starting password authentication.
    #[test]
    fn enforced_sso_begins_no_password_sign_in_for_a_member() {
        let bob = member_of(&founder());

        let refused = OrgSignInStart::new(
            &bob,
            password_of(&bob),
            SecondFactor::NotOwed,
            &config(SsoEnforcement::Enforced),
        );

        assert_eq!(refused.err(), Some(SignInRefused::WayInNotAllowed));
    }

    /// Acme enforces single sign-on and its provider is down. Ann, an
    /// owner, still begins a password sign-in.
    #[test]
    fn enforced_sso_still_begins_an_owners_password_sign_in() {
        let ann = founder();

        let started = OrgSignInStart::new(
            &ann,
            password_of(&ann),
            SecondFactor::NotOwed,
            &config(SsoEnforcement::Enforced),
        );

        assert!(started.is_ok());
    }

    /// Bob signs in through Acme's SAML provider, which proved his address.
    /// His sign-in begins, by SAML.
    #[test]
    fn a_provider_sign_in_for_the_members_address_begins() {
        let bob = member_of(&founder());
        let address = proof_of(bob.email());

        let started = OrgSignInStart::through_provider(
            &bob,
            OrgProviderProof::assumed(saml(), address),
            SecondFactor::NotOwed,
            &config(SsoEnforcement::Enforced),
        )
        .unwrap();

        assert_eq!(started.member(), bob.id());
        assert_eq!(started.progress().method(), AuthMethod::Saml);
    }

    /// A provider proof for another email address cannot start Bob's sign-in.
    #[test]
    fn a_provider_sign_in_for_another_address_begins_nothing() {
        let bob = member_of(&founder());
        let mallorys = proof_of(&Email::new("mallory@evil.test").unwrap());

        let refused = OrgSignInStart::through_provider(
            &bob,
            OrgProviderProof::assumed(saml(), mallorys),
            SecondFactor::NotOwed,
            &config(SsoEnforcement::Optional),
        );

        assert_eq!(refused.err(), Some(SignInRefused::ForAnotherAccount));
    }

    /// Acme enabled only passwords and SAML. An OIDC sign-in begins nothing.
    #[test]
    fn a_provider_sign_in_by_a_protocol_not_enabled_begins_nothing() {
        let bob = member_of(&founder());
        let address = proof_of(bob.email());

        let refused = OrgSignInStart::through_provider(
            &bob,
            OrgProviderProof::assumed(
                ProviderSignIn::new(FederatedMethod::Oidc, FactorProved::NoneYet),
                address,
            ),
            SecondFactor::NotOwed,
            &config(SsoEnforcement::Optional),
        );

        assert_eq!(refused.err(), Some(SignInRefused::WayInNotAllowed));
    }
}
