//! Rows of the organization context.

use ianua_app::ports::organization::{OrgSsoAwaiting, OrgSsoRequest};
use ianua_domain::domains::authentication::credentials::passkey::{
    AuthenticatorType, KeyAttestation, PasskeyCredentialRow,
};
use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
    CeremonyPurpose, CeremonySubject,
};
use ianua_domain::domains::authentication::device_status::DeviceStatus;
use ianua_domain::domains::authentication::device_trust::TrustedDeviceRow;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::enrollment::{
    EnrolledFactor, EnrollmentState, MfaEnrollmentRow, RecentFailures,
};
use ianua_domain::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::recovery::codes::{
    RecoveryCode, RecoveryCodeRow, RecoveryCodeSetRow,
};
use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::federation::connection::{
    AssertionDecryption, AssuranceTrust, AuthnRequestSigning, ConnectionConfig, EmailTrust,
    IdpCertificates, OidcConfig, SamlConfig, ScopeToken,
};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::identity::account::address::AddressStanding;
use ianua_domain::domains::identity::account::vouching::Vouching;
use ianua_domain::domains::identity::invitations::offer::OfferState;
use ianua_domain::domains::identity::privacy::consent::{ConsentDecision, ConsentType};
use ianua_domain::domains::identity::privacy::erasure::ErasureState;
use ianua_domain::domains::organization::access::api_key::{
    MintedThrough, OrgApiKeyRow, OrgApiKeyStatus,
};
use ianua_domain::domains::organization::access::auth_config::OrganizationAuthConfig;
use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProviderRow;
use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremonyRow;
use ianua_domain::domains::organization::access::session::{OrgSessionRow, SessionPlace};
use ianua_domain::domains::organization::access::token::OrgTokenRow;
use ianua_domain::domains::organization::billing::negotiated::PlanTerms;
use ianua_domain::domains::organization::billing::payment::{
    BillingCycle, PaymentMethod, SubscriptionState, TrialUse,
};
use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
use ianua_domain::domains::organization::billing::subscription::OrgSubscriptionRow;
use ianua_domain::domains::organization::branding::OrgBrandingRow;
use ianua_domain::domains::organization::lifecycle::OrganizationRow;
use ianua_domain::domains::organization::members::invitation::OrgInvitationRow;
use ianua_domain::domains::organization::members::linked_identity::{
    LinkedIdentityRow, TenantLink, TenantLinkRow,
};
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::domains::organization::members::org_user::{OrgPassword, OrgUserRow};
use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
use ianua_domain::domains::organization::members::privacy::consent::OrgConsentRecordRow;
use ianua_domain::domains::organization::members::privacy::erasure::OrgErasureRequestRow;
use ianua_domain::domains::organization::signup::{PendingSignupRow, SignupDetails};
use ianua_domain::domains::organization::status::{OrganizationStatus, Suspension};
use ianua_domain::shared::config::{DisplayNameLimits, SlugLimits};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CeremonyId, CertificatePem, ConnectionId, ConsentId, CredentialChange, DisplayName, Email,
    ErasureRequestId, Expiry, Fact, HttpsUrl, IpAddress, Joining, KeyPrefix, Label,
    LinkedIdentityId, Locale, Nonce, OrgApiKeyId, OrgInvitationId, OrgUserId, OrganizationId,
    PasskeyCredentialId, PasskeyId, PasswordHash, Preference, PrincipalId, SamlNameIdFormat, Scope,
    SealedSecret, SessionId, Setting, TenantId, TenantSlug, Text, Timezone, TokenHash,
    TrustedDeviceId, Usage, UserAgent, UserId,
};
use time::Duration;

use crate::test_support::rows::at;

/// An active organization on the free plan, under `slug` and called `name`.
///
/// # Panics
///
/// When `slug` or `name` is not a valid one, which is a mistake in the
/// test.
#[must_use]
pub fn organization_row(slug: &str, name: &str) -> OrganizationRow {
    OrganizationRow {
        id: OrganizationId::new(),
        slug: TenantSlug::new(slug, &SlugLimits::default()).expect("a valid slug"),
        name: Label::new("name", name).expect("a valid name"),
        contact_email: Email::new(format!("billing@{slug}.example")).expect("a valid address"),
        display_name: DisplayName::new(name, &DisplayNameLimits::default()).expect("a valid name"),
        plan: OrganizationPlan::Free,
        terms: PlanTerms::Standard,
        status: OrganizationStatus::Active,
        suspended_by: Suspension::NotSuspended,
        tenant_ids: Vec::new(),
        auth_config: OrganizationAuthConfig::default(),
        created_at: at(0),
        updated_at: at(0),
    }
}

/// An active, verified plain member of `organization` at `email`, with no
/// password, who joined when the account was made.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn org_user_row(organization: OrganizationId, email: &str) -> OrgUserRow {
    OrgUserRow {
        id: OrgUserId::new(),
        organization_id: organization,
        email: Email::new(email).expect("a valid address"),
        display_name: DisplayName::new(email, &DisplayNameLimits::default()).expect("a valid name"),
        password_hash: OrgPassword::NotSet,
        status: OrgUserStatus::Active,
        role: OrgRole::Member,
        email_standing: AddressStanding::Verified,
        locale: Preference::Inherited,
        timezone: Preference::Inherited,
        created_at: at(0),
        updated_at: at(0),
        joining: Joining::Joined { at: at(0) },
        credentials_changed_at: CredentialChange::Never,
        vouching: Vouching::Absent,
    }
}

/// The group of `organization` under `email`, linking a fresh account in
/// each of `tenants`, linked one second apart in that order.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn linked_identity_row(
    organization: OrganizationId,
    email: &str,
    tenants: &[TenantId],
) -> LinkedIdentityRow {
    let accounts: Vec<(TenantId, UserId)> = tenants
        .iter()
        .map(|tenant| (*tenant, UserId::new()))
        .collect();
    linked_identity_row_of(organization, email, &accounts)
}

/// The group of `organization` under `email`, linking each of `accounts`,
/// a tenant and the account in it, one second apart in that order.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn linked_identity_row_of(
    organization: OrganizationId,
    email: &str,
    accounts: &[(TenantId, UserId)],
) -> LinkedIdentityRow {
    let email = Email::new(email).expect("a valid address");
    let links = (0_i64..)
        .zip(accounts)
        .map(|(second, (tenant, user))| {
            TenantLink::reconstitute(TenantLinkRow {
                tenant_id: *tenant,
                user_id: *user,
                email: email.clone(),
                linked_at: at(second),
            })
            .expect("a link always reads back")
        })
        .collect();
    LinkedIdentityRow {
        id: LinkedIdentityId::new(),
        organization_id: organization,
        email,
        links,
        created_at: at(0),
    }
}

/// The organization, sender, recipient and link of an invitation fixture.
#[derive(Clone, Copy)]
pub struct OrgInvitationSeed<'a> {
    /// The company offering membership.
    pub organization: OrganizationId,
    /// The account invited to join.
    pub invitee: OrgUserId,
    /// The member sending the invitation.
    pub invited_by: OrgUserId,
    /// The recipient's mailbox.
    pub email: &'a str,
    /// The stored digest of the invitation link.
    pub token: &'a str,
}

/// A pending invitation `invited_by` sent the member `invitee` of
/// `organization` at `email`, whose link carries the token hashed as
/// `token`, sent at the fixed moment and working for years.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn org_invitation_row(seed: OrgInvitationSeed<'_>) -> OrgInvitationRow {
    let OrgInvitationSeed {
        organization,
        invitee,
        invited_by,
        email,
        token,
    } = seed;
    OrgInvitationRow {
        id: OrgInvitationId::new(),
        organization_id: organization,
        org_user_id: invitee,
        email: Email::new(email).expect("a valid address"),
        invited_by,
        token_hash: TokenHash::from_stored(token.to_owned()),
        state: OfferState::Pending,
        message: Some(Text::new("message", "Welcome aboard").expect("a valid message")),
        expires_at: at(400_000_000),
        created_at: at(0),
    }
}

/// A sign-up for `email`, founding Acme with its Production workspace,
/// whose link carries the token hashed as `token` and works for an hour
/// from the fixed moment.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn pending_signup_row(email: &str, token: &str) -> PendingSignupRow {
    PendingSignupRow {
        email: Email::new(email).expect("a valid address"),
        details: SignupDetails {
            company_name: Label::new("company_name", "Acme Corp").expect("a valid name"),
            tenant_name: Label::new("tenant_name", "Production").expect("a valid name"),
            admin_display_name: DisplayName::new("Ann", &DisplayNameLimits::default())
                .expect("a valid name"),
            password_hash: PasswordHash::from_stored("$argon2id$v=19$stub".to_owned()),
            timezone: Timezone::new("UTC").expect("a valid timezone"),
            locale: Locale::new("en-US").expect("a valid locale"),
        },
        token_hash: TokenHash::from_stored(token.to_owned()),
        requested_at: at(0),
        expires_at: at(3600),
    }
}

/// The platform's own look for `organization`, made at the fixed moment.
#[must_use]
pub fn org_branding_row(organization: OrganizationId) -> OrgBrandingRow {
    OrgBrandingRow {
        organization_id: organization,
        logo_url: Setting::Unset,
        primary_color: Setting::Unset,
        sender_name: Setting::Unset,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// An active API key of `organization` called `name`, made by `created_by`
/// through their session at the fixed moment, that views tenants and never
/// expires.
///
/// # Panics
///
/// When `name` is not a valid name and prefix, which is a mistake in the
/// test.
#[must_use]
pub fn org_api_key_row(
    organization: OrganizationId,
    created_by: OrgUserId,
    name: &str,
) -> OrgApiKeyRow {
    let id = OrgApiKeyId::new();
    OrgApiKeyRow {
        id,
        organization_id: organization,
        name: Label::new("api_key_name", name).expect("a valid name"),
        key_prefix: KeyPrefix::new(format!("oak_acme_{name}")).expect("a valid prefix"),
        key_hash: TokenHash::from_stored(format!("hash_{}", id.as_uuid())),
        scopes: vec![Scope::new("org:tenants:view").expect("a valid scope")],
        created_by,
        minted_through: MintedThrough::Session,
        expires_at: Expiry::Never,
        last_used_at: None,
        status: OrgApiKeyStatus::Active,
        created_at: at(0),
    }
}

/// An active session of `member` of `organization`, working at `place`,
/// signed in with a password and owing nothing, made at the fixed moment
/// and in force for decades, so it is in force whenever the test runs.
///
/// # Panics
///
/// Never: its address and user agent are valid ones.
#[must_use]
pub fn org_session_row(
    organization: OrganizationId,
    member: OrgUserId,
    place: SessionPlace,
) -> OrgSessionRow {
    let id = SessionId::new();
    OrgSessionRow {
        id,
        org_user_id: member,
        organization_id: organization,
        place,
        refresh_token_hash: TokenHash::from_stored(format!("refresh-{}", id.as_uuid())),
        progress: SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::NotOwed,
        },
        ip_address: Fact::Known(IpAddress::new("203.0.113.7").expect("a valid address")),
        user_agent: Fact::Known(UserAgent::new("curl/8.0").expect("a valid user agent")),
        status: SessionStatus::Active,
        created_at: at(0),
        last_active_at: at(0),
        expires_at: at(1_000_000_000),
        kept_through: CredentialChange::Never,
    }
}

/// The row of a session of `member` of `organization` on the organization
/// alone that expired long before any test runs.
#[must_use]
pub fn expired_org_session_row(organization: OrganizationId, member: OrgUserId) -> OrgSessionRow {
    OrgSessionRow {
        created_at: at(-1_000_000_000),
        last_active_at: at(-1_000_000_000),
        expires_at: at(-999_000_000),
        ..org_session_row(organization, member, SessionPlace::Organization)
    }
}

/// A device `member` trusts, last seen when it was trusted.
///
/// # Panics
///
/// Never: its name, address and user agent are valid ones.
#[must_use]
pub fn org_trusted_device_row(member: OrgUserId) -> TrustedDeviceRow {
    let id = TrustedDeviceId::new();
    TrustedDeviceRow {
        id,
        subject_id: PrincipalId::from(member),
        secret_hash: TokenHash::from_stored(format!("device-{}", id.as_uuid())),
        device_name: Label::new("device_name", "Ann's laptop").expect("a valid name"),
        last_user_agent: UserAgent::new("Mozilla/5.0").expect("a valid user agent"),
        last_ip: IpAddress::new("203.0.113.7").expect("a valid address"),
        status: DeviceStatus::Trusted,
        last_seen_at: at(0),
        created_at: at(0),
    }
}

/// `member`'s authenticator app, begun at the fixed moment and confirmed
/// ten seconds later, with no wrong answers.
///
/// # Panics
///
/// Never: the fixed seed and confirmation are valid ones.
#[must_use]
pub fn mfa_enrollment_row(member: OrgUserId) -> MfaEnrollmentRow {
    MfaEnrollmentRow {
        subject_id: PrincipalId::from(member),
        factor: EnrolledFactor::Totp(SealedSecret::new("v1.sealed-seed").expect("a valid seed")),
        state: EnrollmentState::from_stored(
            MfaEnrollmentStatus::Verified,
            Some(at(10)),
            Some(TokenHash::from_stored("recovery-codes".to_owned())),
            None,
        )
        .expect("a whole confirmation"),
        failures: RecentFailures::Clear,
        enrolled_at: at(0),
    }
}

/// A security key `member` registered at the fixed moment and never used,
/// under the credential id `credential`.
///
/// # Panics
///
/// When `credential` is empty, which is a mistake in the test.
#[must_use]
pub fn org_passkey_row(member: OrgUserId, credential: &[u8]) -> PasskeyCredentialRow<OrgUserId> {
    PasskeyCredentialRow {
        id: PasskeyId::new(),
        user_id: member,
        credential_id: PasskeyCredentialId::new(credential.to_vec())
            .expect("a valid credential id"),
        public_key: vec![5, 6, 7, 8],
        sign_count: 0,
        authenticator_type: AuthenticatorType::CrossPlatform,
        attestation: KeyAttestation::Unattested,
        name: Label::new("name", "YubiKey").expect("a valid name"),
        last_used_at: None,
        created_at: at(0),
    }
}

/// A sign-in ceremony opened for `member` at the fixed moment, open for
/// five minutes and not settled yet.
#[must_use]
pub fn org_passkey_ceremony_row(member: OrgUserId) -> OrgPasskeyCeremonyRow {
    OrgPasskeyCeremonyRow {
        id: CeremonyId::new(),
        subject: CeremonySubject::Claimed(member),
        purpose: CeremonyPurpose::Authentication,
        state: b"opaque-verifier-state".to_vec(),
        created_at: at(0),
        expires_at: at(300),
        usage: Usage::Unused,
    }
}

/// A set of `member`'s recovery codes made at the fixed moment, one per
/// hash in `hashes`, none used.
///
/// # Panics
///
/// Never: an unused code always rebuilds.
#[must_use]
pub fn org_recovery_code_set_row(member: OrgUserId, hashes: &[&str]) -> RecoveryCodeSetRow {
    RecoveryCodeSetRow {
        subject_id: PrincipalId::from(member),
        codes: hashes
            .iter()
            .map(|hash| {
                RecoveryCode::reconstitute(RecoveryCodeRow {
                    hash: TokenHash::from_stored((*hash).to_owned()),
                    usage: Usage::Unused,
                })
                .expect("an unused code rebuilds")
            })
            .collect(),
        generated_at: at(0),
    }
}

/// A link mailed to `member` at `email`, issued `issued` seconds after the
/// fixed moment for an hour, under the digest `hash`, not used yet.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn org_token_row(member: OrgUserId, email: &str, hash: &str, issued: i64) -> OrgTokenRow {
    OrgTokenRow {
        token_hash: TokenHash::from_stored(hash.to_owned()),
        org_user_id: member,
        sent_to: Email::new(email).expect("a valid address"),
        created_at: at(issued),
        expires_at: at(issued.saturating_add(3600)),
        usage: Usage::Unused,
    }
}

/// SAML settings for Acme's Okta: one signing certificate, unsigned
/// requests, readable assertions.
///
/// # Panics
///
/// Never: every value is a literal that is valid.
#[must_use]
pub fn org_saml_config() -> ConnectionConfig {
    ConnectionConfig::Saml(Box::new(SamlConfig {
        entity_id: HttpsUrl::new("https://acme.okta.com/saml").expect("a valid url"),
        sso_url: HttpsUrl::new("https://acme.okta.com/saml/sso").expect("a valid url"),
        slo_url: Setting::Unset,
        certificates: IdpCertificates::single(
            CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----")
                .expect("a valid certificate"),
        ),
        name_id_format: SamlNameIdFormat::new(SamlNameIdFormat::PERSISTENT)
            .expect("a valid format"),
        request_signing: AuthnRequestSigning::Unsigned,
        assertion_decryption: AssertionDecryption::NotExpected,
        metadata_url: Setting::Unset,
    }))
}

/// OIDC settings for Acme's Okta, its client secret already sealed.
///
/// # Panics
///
/// Never: every value is a literal that is valid.
#[must_use]
pub fn org_oidc_config() -> ConnectionConfig {
    ConnectionConfig::Oidc(OidcConfig {
        issuer: HttpsUrl::new("https://acme.okta.com").expect("a valid url"),
        client_id: Label::new("client_id", "ianua-dashboard").expect("a valid client id"),
        encrypted_client_secret: SealedSecret::new("v1.sealedclientsecret")
            .expect("a valid sealed secret"),
        scopes: vec![
            ScopeToken::new("openid").expect("a valid scope"),
            ScopeToken::new("email").expect("a valid scope"),
        ],
    })
}

/// The identity provider of `organization`, reached through `config`,
/// switched off and trusting nothing it says, added well before now.
///
/// # Panics
///
/// Never: the name is a literal that is valid.
#[must_use]
pub fn org_identity_provider_row(
    organization: OrganizationId,
    config: ConnectionConfig,
) -> OrgIdentityProviderRow {
    OrgIdentityProviderRow {
        id: ConnectionId::new(),
        organization_id: organization,
        name: Label::new("name", "Acme Okta").expect("a valid name"),
        config,
        email_trust: EmailTrust::Unverified,
        assurance_trust: AssuranceTrust::Untrusted,
        status: ConnectionStatus::Disabled,
        created_at: at(-100_000_000),
    }
}

/// A dashboard sign-in through `connection` of `organization`, sent over
/// OIDC, landing in its `sales` tenant.
///
/// # Panics
///
/// Never: every value is a literal that is valid.
#[must_use]
pub fn org_oidc_sso_request(
    organization: OrganizationId,
    connection: ConnectionId,
) -> OrgSsoRequest {
    OrgSsoRequest {
        organization_id: organization,
        connection_id: connection,
        binding_hash: TokenHash::from_stored("binding-digest".to_owned()),
        tenant_slug: Some(TenantSlug::new("sales", &SlugLimits::default()).expect("a valid slug")),
        awaiting: OrgSsoAwaiting::Oidc {
            nonce: Nonce::new("nonce-0123456789abcdef").expect("a valid nonce"),
            pkce_verifier: Secret::new("pkce-verifier-0123456789abcdef"),
            redirect_uri: HttpsUrl::new("https://app.ianua.example/org/sso/callback")
                .expect("a valid url"),
        },
    }
}

/// A dashboard sign-in through `connection` of `organization`, sent over
/// SAML, landing on the organization alone.
#[must_use]
pub fn org_saml_sso_request(
    organization: OrganizationId,
    connection: ConnectionId,
) -> OrgSsoRequest {
    OrgSsoRequest {
        organization_id: organization,
        connection_id: connection,
        binding_hash: TokenHash::from_stored("binding-digest".to_owned()),
        tenant_slug: None,
        awaiting: OrgSsoAwaiting::Saml,
    }
}

/// A pending request to erase `member` of `organization`, asked at the
/// fixed moment with a week's grace, its cancel link of its own, mailed to
/// `member@acme.example`.
///
/// # Panics
///
/// Never: every value is a literal that is valid.
#[must_use]
pub fn org_erasure_request_row(
    organization: OrganizationId,
    member: OrgUserId,
) -> OrgErasureRequestRow {
    let id = ErasureRequestId::new();
    let cancel_token_hash = TokenHash::from_stored(format!("cancel-{}", id.as_uuid()));
    OrgErasureRequestRow {
        id,
        organization_id: organization,
        org_user_id: member,
        reason: Some(Text::new("reason", "leaving the company").expect("a valid reason")),
        state: ErasureState::Pending,
        requested_at: at(0),
        scheduled_at: at(0).saturating_add(Duration::days(7)),
        cancel_token_hash,
        sent_to: Email::new("member@acme.example").expect("a valid address"),
    }
}

/// The member's consent choice and the time recorded by the fixture.
#[derive(Clone, Copy)]
pub struct OrgConsentSeed {
    /// The company whose member made the choice.
    pub organization: OrganizationId,
    /// The member whose consent is recorded.
    pub member: OrgUserId,
    /// The purpose being accepted or declined.
    pub consent_type: ConsentType,
    /// Whether the member grants consent.
    pub decision: ConsentDecision,
    /// The recording time relative to the fixed fixture moment.
    pub seconds: i64,
}

/// `member` of `organization` deciding `decision` on version `v1` of
/// `consent_type`, `seconds` after the fixed moment, from an address
/// nobody observed.
///
/// # Panics
///
/// Never: the version is a literal that is valid.
#[must_use]
pub fn org_consent_row(seed: OrgConsentSeed) -> OrgConsentRecordRow {
    let OrgConsentSeed {
        organization,
        member,
        consent_type,
        decision,
        seconds,
    } = seed;
    OrgConsentRecordRow {
        id: ConsentId::new(),
        organization_id: organization,
        org_user_id: member,
        consent_type,
        granted: decision,
        version: Label::new("version", "v1").expect("a valid version"),
        ip_address: Fact::Unknown,
        recorded_at: at(seconds),
    }
}

/// The subscription of `organization` as founding a Free organization
/// leaves it: on Free, paid up, billed monthly, with no payment method and
/// its trial unused.
#[must_use]
pub fn subscription_row(organization: OrganizationId) -> OrgSubscriptionRow {
    OrgSubscriptionRow {
        organization_id: organization,
        plan: OrganizationPlan::Free,
        cycle: BillingCycle::Monthly,
        state: SubscriptionState::Active,
        payment: PaymentMethod::Missing,
        trial: TrialUse::Unused,
        created_at: at(0),
        updated_at: at(0),
    }
}
