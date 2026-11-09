//! The claims of an OIDC ID token.
//!
//! Builds the standard JWT payload for an ID token, as
//! <https://openid.net/specs/openid-connect-core-1_0.html#IDToken> sets it
//! out. An adapter signs it through the `JwtSigner` port.

use time::OffsetDateTime;

use crate::domains::authentication::methods::AuthMethod;
use crate::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
use crate::domains::identity::account::user::User;
use crate::domains::oauth::clients::client::OAuthClient;
use crate::domains::oauth::grants::id_token_grant::{IdTokenGrant, StatedSignIn};
use crate::domains::oauth::grants::scoped_claims::{ScopedClaims, names};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{
    ClientId, DisplayName, Email, Issuer, Label, Locale, Nonce, Scope, TenantId, Timezone, UserId,
};

/// The scope that asks for an ID token at all.
pub(crate) const OPENID: &str = "openid";

/// Whether a grant for `scopes` hands out an ID token: only one asking for
/// `openid` does (OIDC Core 3.1.2.1). A plain OAuth grant gets access
/// tokens alone.
#[must_use]
pub fn asks_for_id_token(scopes: &[Scope]) -> bool {
    names(scopes, OPENID)
}

/// The standard claims of an OIDC ID token.
///
/// Only [`IdTokenClaims::build`] makes them, and nothing changes them after.
/// Without that, a caller could set `email_verified` or `aal` by hand before
/// the token is signed. Mallory's unproven address would then reach every
/// app as verified.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct IdTokenClaims {
    iss: Issuer,
    sub: UserId,
    aud: ClientId,
    #[cfg_attr(feature = "serde", serde(with = "time::serde::timestamp"))]
    exp: OffsetDateTime,
    #[cfg_attr(feature = "serde", serde(with = "time::serde::timestamp"))]
    iat: OffsetDateTime,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    nonce: Option<Nonce>,
    #[cfg_attr(feature = "serde", serde(flatten))]
    sign_in: StatedSignIn,
    at_hash: AccessTokenHash,
    tenant_id: TenantId,
    #[cfg_attr(feature = "serde", serde(flatten))]
    scoped: ScopedClaims,
}

/// What ID token claims are built from.
///
/// Who the token is for, how they signed in and the nonce are read from the
/// grant the client was just handed, and their address and name from their
/// account. None of it is written by the caller.
pub struct IdTokenParams<'a, T: TenantScope> {
    /// The tenant's issuer, from [`Issuer::of_tenant`] or the tenant's own
    /// configured one.
    pub issuer: Issuer,
    /// The client the grant went to. Its id is the audience.
    pub client: &'a OAuthClient<T>,
    /// The grant: a code just swapped, a refresh, or a device approval just
    /// collected.
    pub grant: IdTokenGrant<'a, T>,
    /// The account the grant is for, as it is now.
    ///
    /// The `email_verified` claim is read from its address, never set on its
    /// own. Relying parties link accounts by that claim.
    pub account: &'a User<T>,
    /// The tenant the token belongs to.
    pub tenant_id: TenantId,
    /// How long the token is good for.
    pub lifetime: crate::types::Lifetime,
    /// The `at_hash` of the access token issued beside it.
    pub at_hash: AccessTokenHash,
    /// The names of the roles the person holds, for the `roles` claim. Only
    /// a grant with the `roles` scope carries them.
    pub roles: &'a [Label],
}

impl IdTokenClaims {
    /// Builds the claims, issued now, from the grant `params.grant` the
    /// client was just handed.
    ///
    /// Mallory signed in with a password alone. Without the grant, a use
    /// case could write "a hardware key" into her token, and every app that
    /// asks for AAL3 would let her in.
    ///
    /// A refreshed token is about the same person, for the same client, and
    /// states the sign-in its session recorded, never the time of the
    /// refresh, with no nonce (OIDC Core 12.2). A token for a device states
    /// no sign-in and names no session.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a code was not swapped for tokens,
    ///   or a device approval not collected.
    /// - [`DomainError::Forbidden`] when the grant went to another client.
    /// - [`DomainError::Forbidden`] when the account is not the one the
    ///   grant is for.
    /// - [`DomainError::Forbidden`] when a refresh names a session other
    ///   than the one its grant was given in.
    /// - [`DomainError::Forbidden`] when the grant did not ask for `openid`.
    ///
    /// Claims follow the scopes the person granted (OIDC Core 5.4): the
    /// address and whether it is verified only with `email`; the name,
    /// locale and timezone only with `profile`; the roles only with `roles`.
    /// An app that asked for none of them learns who signed in and how,
    /// nothing more about them.
    pub fn build<T: TenantScope>(params: IdTokenParams<'_, T>) -> Result<Self, DomainError> {
        let account = params.account;
        let stated = params.grant.stated(params.client, account)?;
        if !asks_for_id_token(stated.scopes) {
            return Err(DomainError::forbidden(message!(
                "oauth-an-id-token-is-handed-out",
                "an ID token is handed out only for the openid scope"
            )));
        }
        let now = crate::shared::clock::now();
        Ok(Self {
            iss: params.issuer,
            sub: stated.subject,
            aud: params.client.client_id_value().clone(),
            exp: params.lifetime.ends_after(now),
            iat: now,
            nonce: stated.nonce.sent().cloned(),
            sign_in: stated.sign_in,
            at_hash: params.at_hash,
            tenant_id: params.tenant_id,
            scoped: ScopedClaims::for_scopes(stated.scopes, account, params.roles),
        })
    }

    /// The issuer, `iss`.
    #[must_use]
    pub fn iss(&self) -> &Issuer {
        &self.iss
    }

    /// The subject, `sub`: the user's id.
    #[must_use]
    pub fn sub(&self) -> UserId {
        self.sub
    }

    /// The audience, `aud`: the OAuth client id.
    #[must_use]
    pub fn aud(&self) -> &ClientId {
        &self.aud
    }

    /// When the token expires, `exp`. It is written as seconds since the
    /// epoch.
    #[must_use]
    pub fn exp(&self) -> OffsetDateTime {
        self.exp
    }

    /// When the token was issued, `iat`. It is written as seconds since the
    /// epoch.
    #[must_use]
    pub fn iat(&self) -> OffsetDateTime {
        self.iat
    }

    /// How the user signed in (`auth_time`, `acr`, `amr` and `aal`), when
    /// that is known, and the session the grant was given in (`sid`).
    #[must_use]
    pub fn sign_in(&self) -> &StatedSignIn {
        &self.sign_in
    }

    /// The nonce that ties the token to the authorization request.
    #[must_use]
    pub fn nonce(&self) -> Option<&Nonce> {
        self.nonce.as_ref()
    }

    /// What the grant's scopes let out about the user: their address,
    /// profile and roles.
    #[must_use]
    pub fn scoped(&self) -> &ScopedClaims {
        &self.scoped
    }

    /// The user's email address, when the grant has the `email` scope.
    #[must_use]
    pub fn email(&self) -> Option<&Email> {
        self.scoped.email()
    }

    /// Whether the user proved they hold the email address, when the grant
    /// has the `email` scope.
    #[must_use]
    pub fn email_verified(&self) -> Option<bool> {
        self.scoped.email_verified()
    }

    /// The user's display name, when the grant has the `profile` scope.
    #[must_use]
    pub fn name(&self) -> Option<&DisplayName> {
        self.scoped.name()
    }

    /// The user's own locale, when the grant has the `profile` scope and
    /// they set one.
    #[must_use]
    pub fn locale(&self) -> Option<&Locale> {
        self.scoped.locale()
    }

    /// The user's own timezone, `zoneinfo`, when the grant has the
    /// `profile` scope and they set one.
    #[must_use]
    pub fn zoneinfo(&self) -> Option<&Timezone> {
        self.scoped.zoneinfo()
    }

    /// The names of the roles the user holds, when the grant has the
    /// `roles` scope.
    #[must_use]
    pub fn roles(&self) -> Option<&[Label]> {
        self.scoped.roles()
    }

    /// The access token issued beside it, as `at_hash`.
    #[must_use]
    pub fn at_hash(&self) -> &AccessTokenHash {
        &self.at_hash
    }

    /// The tenant id. A custom claim, since one IdP serves many tenants.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

/// An Authentication Methods Reference (RFC 8176): one way the person
/// proved who they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AuthMethodReference {
    /// Knowledge of the account's reusable secret established identity.
    #[cfg_attr(feature = "serde", serde(rename = "pwd"))]
    Password,
    /// A changing code established possession of the enrolled factor.
    #[cfg_attr(feature = "serde", serde(rename = "otp"))]
    OneTimePassword,
    /// A code sent by text message.
    #[cfg_attr(feature = "serde", serde(rename = "sms"))]
    Sms,
    /// A hardware-backed key.
    #[cfg_attr(feature = "serde", serde(rename = "hwk"))]
    HardwareKey,
    /// A key held in software, such as a passkey that may be synced.
    #[cfg_attr(feature = "serde", serde(rename = "swk"))]
    SoftwareKey,
    /// More than one factor.
    #[cfg_attr(feature = "serde", serde(rename = "mfa"))]
    MultiFactor,
}

impl AuthMethodReference {
    /// The value RFC 8176 registers for it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "pwd",
            Self::OneTimePassword => "otp",
            Self::Sms => "sms",
            Self::HardwareKey => "hwk",
            Self::SoftwareKey => "swk",
            Self::MultiFactor => "mfa",
        }
    }
}

/// The RFC 8176 Authentication Methods References for how a session began
/// and the second factor it proved.
///
/// It names only what was recorded. A sign-in through an identity provider
/// names no first method, because how the provider checked the person is
/// its own business. A mailbox confirmation is no second factor.
pub(crate) fn amr_for(method: AuthMethod, second: FactorProved) -> Vec<AuthMethodReference> {
    let mut amr: Vec<AuthMethodReference> = first_factor(method).into_iter().collect();
    let FactorProved::Proved(factor) = second else {
        return amr;
    };
    let SecondFactor::Proved(references) = second_factor(factor) else {
        return amr;
    };
    for reference in references {
        if !amr.contains(reference) {
            amr.push(*reference);
        }
    }
    amr.push(AuthMethodReference::MultiFactor);
    amr
}

/// The reference for the way a session began, when it names one.
fn first_factor(method: AuthMethod) -> Option<AuthMethodReference> {
    match method {
        AuthMethod::Password => Some(AuthMethodReference::Password),
        AuthMethod::MagicLink => Some(AuthMethodReference::OneTimePassword),
        AuthMethod::Passkey => Some(AuthMethodReference::SoftwareKey),
        AuthMethod::Saml | AuthMethod::Oidc => None,
    }
}

/// What a recorded second factor says about the sign-in.
enum SecondFactor {
    /// A second factor, by these methods. None are named when a provider
    /// reported only that it asked for more than one.
    Proved(&'static [AuthMethodReference]),
    /// Not a second factor at all.
    NotAFactor,
}

/// What a recorded second factor counts as. A mailbox confirmation counts
/// as none, and so does a mailed code: it proves the mailbox again, which
/// NIST does not accept as a second factor, so no relying party is told
/// `mfa` on its strength.
fn second_factor(factor: MfaFactor) -> SecondFactor {
    match factor {
        MfaFactor::Totp | MfaFactor::RecoveryCode => {
            SecondFactor::Proved(&[AuthMethodReference::OneTimePassword])
        }
        MfaFactor::SmsCode => SecondFactor::Proved(&[AuthMethodReference::Sms]),
        MfaFactor::HardwareKey | MfaFactor::ProviderHardwareKey => {
            SecondFactor::Proved(&[AuthMethodReference::HardwareKey])
        }
        MfaFactor::Passkey => SecondFactor::Proved(&[AuthMethodReference::SoftwareKey]),
        MfaFactor::ProviderMultiFactor => SecondFactor::Proved(&[]),
        MfaFactor::EmailConfirmation | MfaFactor::EmailCode => SecondFactor::NotAFactor,
    }
}

text_value! {
    /// The `at_hash` claim: the left half of the access token's hash under
    /// the signing algorithm's hash function, base64url-encoded (OIDC Core
    /// 3.1.3.6). The signer works it out, since only it knows the
    /// algorithm. At most 86 characters, the length a SHA-512 half takes.
    pub struct AccessTokenHash;
}

impl TextValue for AccessTokenHash {
    const FIELD: &'static str = "at_hash";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=86,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE,
        )
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use crate::domains::authentication::sessions::session::Session;
    use crate::domains::authentication::sessions::session::tests::signed_in_session;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::domains::oauth::clients::client::{GrantType, NewOAuthClient};
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::domains::oauth::grants::authorization_code::{
        AuthCodeRow, AuthorizationCode, CodeChallenge, CodeChallengeMethod, NonceSent,
    };
    use crate::domains::oauth::grants::device_authorization::{
        DeviceAuthRow, DeviceAuthState, DeviceAuthorization, LastPoll, PollInterval,
    };
    use crate::domains::oauth::grants::id_token_grant::GrantSession;
    use crate::domains::oauth::grants::refresh_terms::{RefreshRequest, RefreshScopes};
    use crate::domains::oauth::grants::refresh_token::{
        GrantedIn, NextRefresh, OAuthRefreshToken, OAuthRefreshTokenRow, RefreshState,
    };
    use crate::domains::oauth::grants::token_binding::{PresentedProof, SenderBinding};
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::{label, user};
    use crate::types::{
        DeviceUserCode, Lifetime, OAuthClientId, RedirectUri, RefreshFamilyId, Scope, TokenHash,
        Usage,
    };

    /// The client every test's code is swapped by.
    fn client() -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("client_123").unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored(
                    "hashed_secret".to_owned(),
                )),
                name: label("Web app"),
                redirect_uris: vec![RedirectUri::new("https://app.acme.com/callback").unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                scopes: vec![Scope::new("openid").unwrap()],
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// The account at `address`, which its owner proved.
    fn proven(address: &str) -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), address);
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    /// The row of a code `client` swapped a moment ago for `account`, who
    /// signed in two minutes ago through `method` with `factor`.
    fn swapped_row(
        client: &OAuthClient<ResolvedTenant>,
        account: &User<ResolvedTenant>,
        method: AuthMethod,
        factor: FactorProved,
    ) -> AuthCodeRow {
        let now = crate::shared::clock::now();
        AuthCodeRow {
            code_hash: TokenHash::from_stored("hash_abc".to_owned()),
            client_id: *client.id(),
            user_id: *account.id(),
            redirect_uri: RedirectUri::new("https://app.acme.com/callback").unwrap(),
            scopes: ["openid", "email", "profile"]
                .map(|name| Scope::new(name).unwrap())
                .to_vec(),
            code_challenge: CodeChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .unwrap(),
            code_challenge_method: CodeChallengeMethod::S256,
            nonce: NonceSent::NotSent,
            session_id: crate::types::SessionId::new(),
            auth_method: method,
            second_factor: factor,
            authenticated_at: now - Duration::minutes(2),
            created_at: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            usage: Usage::Used { at: now },
        }
    }

    fn code(row: AuthCodeRow) -> AuthorizationCode<ResolvedTenant> {
        AuthorizationCode::reconstitute(row).unwrap()
    }

    /// The claims for `account`, from `code`, swapped by `client`, good for
    /// `seconds`.
    fn claims_for(
        client: &OAuthClient<ResolvedTenant>,
        code: &AuthorizationCode<ResolvedTenant>,
        account: &User<ResolvedTenant>,
        seconds: i64,
    ) -> Result<IdTokenClaims, DomainError> {
        claims_of(client, IdTokenGrant::Code(code), account, seconds)
    }

    /// The claims for `account`, from `grant`, handed to `client`, good for
    /// `seconds`.
    fn claims_of(
        client: &OAuthClient<ResolvedTenant>,
        grant: IdTokenGrant<'_, ResolvedTenant>,
        account: &User<ResolvedTenant>,
        seconds: i64,
    ) -> Result<IdTokenClaims, DomainError> {
        IdTokenClaims::build(IdTokenParams {
            issuer: Issuer::new("https://auth.acme.com").unwrap(),
            client,
            grant,
            account,
            tenant_id: TenantId::new(),
            lifetime: crate::types::Lifetime::seconds(seconds).unwrap(),
            at_hash: AccessTokenHash::new("77QmUPtjPfzWtF2AnpK9RQ").unwrap(),
            roles: &[],
        })
    }

    /// `account`'s claims from a code for `scopes`, swapped by `client`.
    fn claims_with_scopes(
        account: &User<ResolvedTenant>,
        scopes: &[&str],
        roles: &[Label],
    ) -> Result<IdTokenClaims, DomainError> {
        let client = client();
        let code = code(AuthCodeRow {
            scopes: scopes
                .iter()
                .map(|name| Scope::new(*name).unwrap())
                .collect(),
            ..swapped_row(
                &client,
                account,
                AuthMethod::Password,
                FactorProved::NoneYet,
            )
        });
        IdTokenClaims::build(IdTokenParams {
            issuer: Issuer::new("https://auth.acme.com").unwrap(),
            client: &client,
            grant: IdTokenGrant::Code(&code),
            account,
            tenant_id: TenantId::new(),
            lifetime: crate::types::Lifetime::seconds(300).unwrap(),
            at_hash: AccessTokenHash::new("77QmUPtjPfzWtF2AnpK9RQ").unwrap(),
            roles,
        })
    }

    /// An app asks only for `openid`. Its token says who signed in and how,
    /// and nothing about their address, name or roles.
    #[test]
    fn claims_follow_the_scopes_granted() {
        let ann = proven("ann@acme.com");

        let claims = claims_with_scopes(&ann, &["openid"], &[]).unwrap();

        assert_eq!(claims.sub(), *ann.id());
        assert_eq!(claims.email(), None);
        assert_eq!(claims.email_verified(), None);
        assert_eq!(claims.name(), None);
        assert_eq!(claims.roles(), None);
    }

    /// Building ID-token claims for a grant carrying `read` without `openid`
    /// is forbidden.
    #[test]
    fn no_id_token_without_openid() {
        let ann = proven("ann@acme.com");

        let result = claims_with_scopes(&ann, &["read"], &[]);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An app that asks for `roles` reads the roles Ann holds.
    #[test]
    fn the_roles_scope_carries_the_roles_held() {
        let ann = proven("ann@acme.com");
        let held = [label("Editor")];

        let claims = claims_with_scopes(&ann, &["openid", "roles"], &held).unwrap();

        assert_eq!(claims.roles(), Some(held.as_slice()));
    }

    /// The token names the session Ann consented in and its assurance level
    /// as `acr`.
    #[test]
    fn the_token_names_its_session_and_acr() {
        let ann = proven("ann@acme.com");
        let client = client();
        let code = code(swapped_row(
            &client,
            &ann,
            AuthMethod::Password,
            FactorProved::Proved(MfaFactor::Totp),
        ));

        let claims = claims_for(&client, &code, &ann, 300).unwrap();

        assert_eq!(claims.sign_in().session(), Some(code.session_id()));
        assert_eq!(
            claims.sign_in().assurance().map(AssuranceLevel::acr),
            Some("aal2")
        );
    }

    /// The claims for `account` after a sign-in through `method` with
    /// `factor`, good for five minutes.
    fn signed_in_with(
        account: &User<ResolvedTenant>,
        method: AuthMethod,
        factor: FactorProved,
    ) -> IdTokenClaims {
        let client = client();
        let code = code(swapped_row(&client, account, method, factor));
        claims_for(&client, &code, account, 300).unwrap()
    }

    /// A swapped password-and-TOTP code carrying the request's nonce.
    fn code_with_nonce(
        client: &OAuthClient<ResolvedTenant>,
        account: &User<ResolvedTenant>,
        nonce: &str,
    ) -> AuthorizationCode<ResolvedTenant> {
        code(AuthCodeRow {
            nonce: NonceSent::Sent(Nonce::new(nonce).unwrap()),
            ..swapped_row(
                client,
                account,
                AuthMethod::Password,
                FactorProved::Proved(MfaFactor::Totp),
            )
        })
    }

    /// Alice signs in with a password and a TOTP code. The claims carry the
    /// issuer, audience, email, her name, the nonce, a one-hour expiry, AAL2
    /// and the methods `pwd`, `otp` and `mfa`, all from her code and her
    /// account.
    #[test]
    fn builds_standard_claims() {
        let alice = proven("alice@acme.com");
        let client = client();
        let code = code_with_nonce(&client, &alice, "nonce_abc_1234567890");

        let claims = claims_for(&client, &code, &alice, 3600).unwrap();

        assert_eq!(claims.iss().as_str(), "https://auth.acme.com");
        assert_eq!(claims.aud().as_str(), "client_123");
        assert_eq!(claims.sub(), *alice.id());
        assert_eq!(claims.name(), Some(alice.display_name()));
        assert_eq!(claims.email().map(Email::as_str), Some("alice@acme.com"));
        assert_eq!(
            claims.nonce().map(Nonce::as_str),
            Some("nonce_abc_1234567890")
        );
        assert!(claims.exp() > claims.iat());
        assert_eq!(claims.exp() - claims.iat(), time::Duration::hours(1));
        assert_eq!(claims.sign_in().assurance(), Some(AssuranceLevel::Aal2));
        assert_eq!(
            claims.sign_in().amr(),
            [
                AuthMethodReference::Password,
                AuthMethodReference::OneTimePassword,
                AuthMethodReference::MultiFactor
            ]
        );
    }

    /// Bob signs in with only a password, and his request sent no nonce.
    /// The claims have no nonce and only `pwd` as the method.
    #[test]
    fn a_request_without_a_nonce_gets_a_token_without_one() {
        let bob = user(UserId::new(), "bob@acme.com");

        let claims = signed_in_with(&bob, AuthMethod::Password, FactorProved::NoneYet);

        assert!(claims.nonce().is_none());
        assert_eq!(claims.sign_in().amr(), [AuthMethodReference::Password]);
    }

    /// A passkey sign-in lists `swk`. A provider's own multi-factor sign-in
    /// lists only `mfa`. A password plus a mailbox confirmation lists only
    /// `pwd`, since the confirmation is no second factor.
    #[test]
    fn amr_names_what_the_session_recorded() {
        assert_eq!(
            amr_for(AuthMethod::Passkey, FactorProved::NoneYet),
            vec![AuthMethodReference::SoftwareKey]
        );
        assert_eq!(
            amr_for(
                AuthMethod::Oidc,
                FactorProved::Proved(MfaFactor::ProviderMultiFactor)
            ),
            vec![AuthMethodReference::MultiFactor]
        );
        assert_eq!(
            amr_for(
                AuthMethod::Password,
                FactorProved::Proved(MfaFactor::EmailConfirmation)
            ),
            vec![AuthMethodReference::Password]
        );
    }

    /// A password plus a texted code lists `pwd`, `sms` and `mfa`. A
    /// password plus a mailed code lists only `pwd`: the code proves the
    /// mailbox again, so no app is told the sign-in had two factors.
    #[test]
    fn amr_names_a_texted_code_and_not_a_mailed_one() {
        assert_eq!(
            amr_for(
                AuthMethod::Password,
                FactorProved::Proved(MfaFactor::SmsCode)
            ),
            vec![
                AuthMethodReference::Password,
                AuthMethodReference::Sms,
                AuthMethodReference::MultiFactor
            ]
        );
        assert_eq!(
            amr_for(
                AuthMethod::Password,
                FactorProved::Proved(MfaFactor::EmailCode)
            ),
            vec![AuthMethodReference::Password]
        );
    }

    /// Carol signs in with a password and a hardware key at AAL3. The claims
    /// list `pwd`, `hwk` and `mfa`, with AAL3.
    #[test]
    fn aal3_amr_is_hardware_key() {
        let carol = proven("carol@acme.com");

        let claims = signed_in_with(
            &carol,
            AuthMethod::Password,
            FactorProved::Proved(MfaFactor::HardwareKey),
        );

        assert_eq!(
            claims.sign_in().amr(),
            [
                AuthMethodReference::Password,
                AuthMethodReference::HardwareKey,
                AuthMethodReference::MultiFactor
            ]
        );
        assert_eq!(claims.sign_in().assurance(), Some(AssuranceLevel::Aal3));
    }

    /// Dave signed in three hours ago and gets a token now. `auth_time` is
    /// his sign-in, not the issue time, so an app can tell when to ask him to
    /// sign in again.
    #[test]
    fn auth_time_is_the_sign_in_not_the_issue() {
        let signed_in = crate::shared::clock::now() - Duration::hours(3);
        let dave = proven("dave@acme.com");
        let client = client();
        let code = code(AuthCodeRow {
            authenticated_at: signed_in,
            ..swapped_row(&client, &dave, AuthMethod::Password, FactorProved::NoneYet)
        });

        let claims = claims_for(&client, &code, &dave, 300).unwrap();

        assert_eq!(claims.sign_in().auth_time(), Some(signed_in));
        assert!(claims.iat() > signed_in);
    }

    /// Reads this flat claim object's keys in their serialized order.
    #[cfg(feature = "serde")]
    fn json_keys(json: &str) -> Vec<&str> {
        json.split('"')
            .collect::<Vec<_>>()
            .windows(2)
            .filter(|pair| pair[1].starts_with(':'))
            .map(|pair| pair[0])
            .collect()
    }

    /// The signed payload keeps the claim names and order relying parties
    /// read: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, then the
    /// address, the name, the tenant, `amr` and `aal`. A nonce the request
    /// did not send is not written.
    #[cfg(feature = "serde")]
    #[test]
    fn claims_serialize_with_their_registered_names_in_order() {
        let erin = user(UserId::new(), "erin@acme.com");

        let claims = signed_in_with(&erin, AuthMethod::Password, FactorProved::NoneYet);

        let json = serde_json::to_string(&claims).unwrap();
        let keys = json_keys(&json);

        assert_eq!(
            keys,
            [
                "iss",
                "sub",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "acr",
                "amr",
                "aal",
                "sid",
                "at_hash",
                "tenant_id",
                "email",
                "email_verified",
                "name"
            ]
        );
        assert!(json.contains(r#""iss":"https://auth.acme.com""#));
        assert!(json.contains(r#""email_verified":false"#));
    }

    /// Frank's token is written for an app to read. `exp`, `iat` and
    /// `auth_time` are whole seconds since the epoch, as JWT numeric dates
    /// are.
    #[cfg(feature = "serde")]
    #[test]
    fn times_are_written_as_seconds_since_the_epoch() {
        let signed_in = OffsetDateTime::from_unix_timestamp(1_792_400_000).unwrap()
            + Duration::milliseconds(500);
        let frank = user(UserId::new(), "frank@acme.com");
        let client = client();
        let code = code(AuthCodeRow {
            authenticated_at: signed_in,
            ..swapped_row(&client, &frank, AuthMethod::Password, FactorProved::NoneYet)
        });
        let claims = claims_for(&client, &code, &frank, 300).unwrap();

        let json = serde_json::to_value(&claims).unwrap();

        assert_eq!(json["auth_time"], 1_792_400_000);
        assert_eq!(json["exp"], claims.exp().unix_timestamp());
        assert_eq!(json["iat"], claims.iat().unix_timestamp());
    }

    /// A password sign-in for an account with an unproven address produces
    /// claims reporting an unverified email and AAL1 assurance.
    #[test]
    fn an_unproven_address_is_never_reported_verified() {
        let mallory = user(UserId::new(), "ceo@acme.com");

        let claims = signed_in_with(&mallory, AuthMethod::Password, FactorProved::NoneYet);

        assert_eq!(claims.email_verified(), Some(false));
        assert_eq!(claims.sign_in().assurance(), Some(AssuranceLevel::Aal1));
    }

    /// An unused authorization code cannot supply ID-token claims. Building
    /// them before the exchange is forbidden.
    #[test]
    fn an_unswapped_code_gives_no_token() {
        let ann = proven("ann@acme.com");
        let client = client();
        let unused = code(AuthCodeRow {
            usage: Usage::Unused,
            ..swapped_row(&client, &ann, AuthMethod::Password, FactorProved::NoneYet)
        });

        let claims = claims_for(&client, &unused, &ann, 300);

        assert!(matches!(claims, Err(DomainError::Forbidden(_))));
    }

    /// A code exchanged by the web app cannot supply ID-token claims for a
    /// different client. The build is forbidden.
    #[test]
    fn a_code_gives_a_token_only_to_its_own_client() {
        let ann = proven("ann@acme.com");
        let web_app = client();
        let code = code(swapped_row(
            &web_app,
            &ann,
            AuthMethod::Password,
            FactorProved::NoneYet,
        ));

        let claims = claims_for(&client(), &code, &ann, 300);

        assert!(matches!(claims, Err(DomainError::Forbidden(_))));
    }

    /// Supplying the CEO's account with Mallory's exchanged code is forbidden
    /// when building ID-token claims.
    #[test]
    fn a_code_gives_a_token_only_for_its_own_account() {
        let mallory = proven("mallory@acme.com");
        let ceo = proven("ceo@acme.com");
        let client = client();
        let code = code(swapped_row(
            &client,
            &mallory,
            AuthMethod::Password,
            FactorProved::NoneYet,
        ));

        let claims = claims_for(&client, &code, &ceo, 300);

        assert!(matches!(claims, Err(DomainError::Forbidden(_))));
    }

    /// What refreshing the token `client` holds for the person signed in to
    /// `session` hands on, for `openid` and `email`.
    fn refreshed(
        client: &OAuthClient<ResolvedTenant>,
        session: &Session<ResolvedTenant>,
    ) -> NextRefresh {
        let now = crate::shared::clock::now();
        let mut token = OAuthRefreshToken::<ResolvedTenant>::reconstitute(OAuthRefreshTokenRow {
            token_hash: TokenHash::from_stored("refresh_hash".to_owned()),
            family: RefreshFamilyId::new(),
            client_id: *client.id(),
            user_id: *session.user_id(),
            scopes: ["openid", "email"]
                .map(|name| Scope::new(name).unwrap())
                .to_vec(),
            granted_in: GrantedIn::Session(*session.id()),
            binding: SenderBinding::Bearer,
            issued_at: now - Duration::days(2),
            expires_at: now + Duration::days(1),
            family_expires_at: now + Duration::days(30),
            state: RefreshState::Active,
        })
        .unwrap();
        let request = RefreshRequest {
            scopes: RefreshScopes::AsGranted,
            idle: Lifetime::seconds(3600).unwrap(),
            proof: PresentedProof::nothing(),
        };
        token.rotate(client, request, now).unwrap()
    }

    /// A device approval for `openid`, started by `client`, standing as
    /// `state` says.
    fn device(
        client: &OAuthClient<ResolvedTenant>,
        state: DeviceAuthState,
    ) -> DeviceAuthorization<ResolvedTenant> {
        let now = crate::shared::clock::now();
        DeviceAuthorization::reconstitute(DeviceAuthRow {
            device_code_hash: TokenHash::from_stored("device_hash".to_owned()),
            user_code: DeviceUserCode::new("ABCD-1234").unwrap(),
            client_id: *client.id(),
            scopes: vec![Scope::new("openid").unwrap()],
            state,
            interval: PollInterval::DEFAULT,
            last_poll: LastPoll::Never,
            created_at: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(9),
        })
        .unwrap()
    }

    /// Ann's app refreshes her tokens two days after she signed in. The new
    /// ID token is about her, states the sign-in her session recorded, not
    /// the refresh, names that session, and carries no nonce.
    #[test]
    fn a_refreshed_token_states_the_sign_in_of_its_session() {
        let session = signed_in_session();
        let ann = user(*session.user_id(), "ann@acme.com");
        let client = client();
        let next = refreshed(&client, &session);
        let grant = IdTokenGrant::Refresh {
            next: &next,
            session: GrantSession::Kept(&session),
        };

        let claims = claims_of(&client, grant, &ann, 300).unwrap();

        assert_eq!(claims.sub(), *ann.id());
        assert_eq!(claims.sign_in().auth_time(), Some(session.signed_in_at()));
        assert_eq!(claims.sign_in().session(), Some(session.id()));
        assert_eq!(claims.sign_in().amr(), [AuthMethodReference::Password]);
        assert!(claims.nonce().is_none());
    }

    /// A refreshed grant cannot use another session to supply its sign-in
    /// claims. Building the ID token with that session is forbidden.
    #[test]
    fn a_refresh_states_only_the_session_its_grant_was_given_in() {
        let session = signed_in_session();
        let ann = user(*session.user_id(), "ann@acme.com");
        let client = client();
        let next = refreshed(&client, &session);
        let other = signed_in_session();
        let grant = IdTokenGrant::Refresh {
            next: &next,
            session: GrantSession::Kept(&other),
        };

        let claims = claims_of(&client, grant, &ann, 300);

        assert!(matches!(claims, Err(DomainError::Forbidden(_))));
    }

    /// Ann's session is no longer kept when her app refreshes. The token
    /// still names the session the grant was given in, but states no
    /// sign-in rather than one made up.
    #[test]
    fn a_refresh_without_its_session_states_no_sign_in() {
        let session = signed_in_session();
        let ann = user(*session.user_id(), "ann@acme.com");
        let client = client();
        let next = refreshed(&client, &session);
        let grant = IdTokenGrant::Refresh {
            next: &next,
            session: GrantSession::NotKept,
        };

        let claims = claims_of(&client, grant, &ann, 300).unwrap();

        assert_eq!(claims.sign_in().auth_time(), None);
        assert_eq!(claims.sign_in().assurance(), None);
        assert_eq!(claims.sign_in().session(), Some(session.id()));
    }

    /// Ann approves the TV, and the TV collects the approval. Its ID token
    /// is about her and names no session, since none was signed in on the
    /// TV.
    #[test]
    fn a_collected_device_approval_gets_an_id_token() {
        let ann = proven("ann@acme.com");
        let client = client();
        let tv = device(&client, DeviceAuthState::Redeemed { by: *ann.id() });

        let claims = claims_of(&client, IdTokenGrant::Device(&tv), &ann, 300).unwrap();

        assert_eq!(claims.sub(), *ann.id());
        assert_eq!(claims.sign_in().session(), None);
        assert_eq!(claims.sign_in().auth_time(), None);
    }

    /// Building ID-token claims before a device approval is collected is
    /// forbidden. A collected approval for Ann also cannot supply claims for
    /// the CEO's account.
    #[test]
    fn a_device_approval_gives_a_token_only_once_collected_for_its_person() {
        let ann = proven("ann@acme.com");
        let ceo = proven("ceo@acme.com");
        let client = client();
        let approved = device(&client, DeviceAuthState::Approved { by: *ann.id() });
        let collected = device(&client, DeviceAuthState::Redeemed { by: *ann.id() });

        let early = claims_of(&client, IdTokenGrant::Device(&approved), &ann, 300);
        let for_ceo = claims_of(&client, IdTokenGrant::Device(&collected), &ceo, 300);

        assert!(matches!(early, Err(DomainError::Forbidden(_))));
        assert!(matches!(for_ceo, Err(DomainError::Forbidden(_))));
    }

    /// A token for a device is written without `auth_time`, `acr`, `amr`,
    /// `aal` or `sid`: nothing is claimed that is not known.
    #[cfg(feature = "serde")]
    #[test]
    fn a_device_token_writes_no_sign_in() {
        let ann = proven("ann@acme.com");
        let client = client();
        let tv = device(&client, DeviceAuthState::Redeemed { by: *ann.id() });
        let claims = claims_of(&client, IdTokenGrant::Device(&tv), &ann, 300).unwrap();

        let json = serde_json::to_value(&claims).unwrap();

        for absent in ["auth_time", "acr", "amr", "aal", "sid", "nonce"] {
            assert!(json.get(absent).is_none(), "{absent}");
        }
        assert!(json.get("sub").is_some());
    }

    /// Password, one-time password and hardware key are written `pwd`, `otp`
    /// and `hwk`, as RFC 8176 registers them. Apps match on these strings.
    #[test]
    fn every_method_reference_has_its_registered_name() {
        assert_eq!(AuthMethodReference::Password.as_str(), "pwd");
        assert_eq!(AuthMethodReference::OneTimePassword.as_str(), "otp");
        assert_eq!(AuthMethodReference::Sms.as_str(), "sms");
        assert_eq!(AuthMethodReference::HardwareKey.as_str(), "hwk");
    }
}
