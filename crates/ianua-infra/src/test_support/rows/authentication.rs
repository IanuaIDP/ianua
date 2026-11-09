//! Rows of the authentication context.

use std::sync::Arc;

use ianua_app::ports::identity::UserStore;
use ianua_app::ports::shared::SessionStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::credentials::passkey::{
    AuthenticatorType, KeyAttestation, PasskeyCredentialRow,
};
use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
    CeremonyPurpose, CeremonySubject, PasskeyCeremonyRow,
};
use ianua_domain::domains::authentication::device_status::DeviceStatus;
use ianua_domain::domains::authentication::device_trust::TrustedDeviceRow;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::enrollment::{
    EnrolledFactor, EnrollmentState, MfaEnrollmentRow, MfaMethod, RecentFailures,
};
use ianua_domain::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;
use ianua_domain::domains::authentication::mfa::one_time_code::OneTimeCodeRow;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::recovery::codes::{
    RecoveryCode, RecoveryCodeRow, RecoveryCodeSetRow,
};
use ianua_domain::domains::authentication::recovery::reset::{
    PasswordResetRow, ResetInitiator, ResetState,
};
use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
use ianua_domain::domains::authentication::sessions::handoff::SessionHandoffRow;
use ianua_domain::domains::authentication::sessions::mfa_challenge::MfaChallengeRow;
use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
use ianua_domain::domains::authentication::sessions::session::{
    Session, SessionOrigin, SessionRow,
};
use ianua_domain::domains::authentication::sessions::sign_in_code::SignInCodeRow;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::authorization::break_glass::{
    BreakGlassAccess, BreakGlassGrantRow, BreakGlassPolicyRow, GrantApproval, SelfService,
};
use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{
    BreakGlassGrantId, CeremonyId, CredentialChange, DomainName, Email, Fact, IpAddress, Label,
    PasskeyCredentialId, PasskeyId, PasswordResetId, PersonKey, PrincipalId, Revocation,
    SealedSecret, ServiceId, SessionId, TenantId, Text, TokenHash, TrustedDeviceId, Usage,
    UserAgent, UserId,
};

use crate::postgres::Databases;
use crate::postgres::identity::PgUserStore;
use crate::postgres::shared::PgSessionStore;
use crate::test_support::rows::at;
use crate::test_support::rows::identity::{from_now, user_row};

/// `value` as a stored hash.
#[must_use]
pub fn hash(value: &str) -> TokenHash {
    TokenHash::from_stored(value.to_owned())
}

/// `user_id`'s finished dashboard session, signed in by password a minute
/// ago and good for an hour, holding the refresh token hashing to
/// `refresh`.
#[must_use]
pub fn session_row(user_id: UserId, refresh: &str) -> SessionRow {
    SessionRow {
        id: SessionId::new(),
        user_id,
        refresh_token_hash: hash(refresh),
        parent_id: SessionOrigin::SignIn,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        signed_in_from: Fact::Unknown,
        progress: SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::NotOwed,
        },
        status: SessionStatus::Active,
        channel: SessionChannel::Dashboard,
        signed_in_at: from_now(-60),
        created_at: from_now(-60),
        last_active_at: from_now(-60),
        expires_at: from_now(3600),
        kept_through: CredentialChange::Never,
        last_use: Fact::Unknown,
    }
}

/// `user_id`'s session opened through the app sign-in of `service_id`, as
/// [`session_row`] describes it otherwise.
#[must_use]
pub fn app_session_row(user_id: UserId, service_id: ServiceId, refresh: &str) -> SessionRow {
    SessionRow {
        channel: SessionChannel::App(service_id),
        ..session_row(user_id, refresh)
    }
}

/// A pending reset of `user_id`'s password, asked for by the holder at
/// `seconds` past the fixed moment, working for an hour, under the link
/// hashing to `link`.
///
/// # Panics
///
/// Never: the address is a valid one.
#[must_use]
pub fn reset_row(user_id: UserId, link: &str, seconds: i64) -> PasswordResetRow {
    PasswordResetRow {
        id: PasswordResetId::new(),
        user_id,
        email: Email::new("ann@acme.example").expect("a valid address"),
        initiator: ResetInitiator::User,
        state: ResetState::Pending,
        token_hash: hash(link),
        created_at: at(seconds),
        expires_at: at(seconds.saturating_add(3600)),
    }
}

/// `user_id`'s authenticator app, begun at the fixed moment and confirmed
/// ten seconds later, with no wrong answers.
///
/// # Panics
///
/// Never: the fixed seed and confirmation are valid ones.
#[must_use]
pub fn enrollment_row(user_id: UserId) -> MfaEnrollmentRow {
    MfaEnrollmentRow {
        subject_id: PrincipalId::from(user_id),
        factor: EnrolledFactor::Totp(SealedSecret::new("v1.sealed-seed").expect("a valid seed")),
        state: EnrollmentState::from_stored(
            MfaEnrollmentStatus::Verified,
            Some(at(10)),
            Some(hash("recovery-codes")),
            None,
        )
        .expect("a whole confirmation"),
        failures: RecentFailures::Clear,
        enrolled_at: at(0),
    }
}

/// A set of `user_id`'s recovery codes made at the fixed moment, one per
/// hash in `hashes`, none used.
///
/// # Panics
///
/// Never: an unused code always rebuilds.
#[must_use]
pub fn recovery_code_set_row(user_id: UserId, hashes: &[&str]) -> RecoveryCodeSetRow {
    RecoveryCodeSetRow {
        subject_id: PrincipalId::from(user_id),
        codes: hashes
            .iter()
            .map(|code| {
                RecoveryCode::reconstitute(RecoveryCodeRow {
                    hash: hash(code),
                    usage: Usage::Unused,
                })
                .expect("an unused code rebuilds")
            })
            .collect(),
        generated_at: at(0),
    }
}

/// A security key `user_id` registered at the fixed moment and never used,
/// under the credential id `credential`.
///
/// # Panics
///
/// When `credential` is empty, which is a mistake in the test.
#[must_use]
pub fn passkey_row(user_id: UserId, credential: &[u8]) -> PasskeyCredentialRow {
    PasskeyCredentialRow {
        id: PasskeyId::new(),
        user_id,
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

/// A sign-in ceremony of `tenant_id` opened for `user_id` a minute ago,
/// open for five minutes more and not settled yet.
#[must_use]
pub fn ceremony_row(tenant_id: TenantId, user_id: UserId) -> PasskeyCeremonyRow {
    PasskeyCeremonyRow {
        id: CeremonyId::new(),
        tenant_id,
        subject: CeremonySubject::Claimed(user_id),
        purpose: CeremonyPurpose::Authentication,
        state: b"opaque-verifier-state".to_vec(),
        created_at: from_now(-60),
        expires_at: from_now(300),
        usage: Usage::Unused,
    }
}

/// A device `user_id` trusts, last seen when it was trusted.
///
/// # Panics
///
/// Never: its name, address and user agent are valid ones.
#[must_use]
pub fn device_row(user_id: UserId) -> TrustedDeviceRow {
    let id = TrustedDeviceId::new();
    TrustedDeviceRow {
        id,
        subject_id: PrincipalId::from(user_id),
        secret_hash: hash(&format!("device-{}", id.as_uuid())),
        device_name: Label::new("device_name", "Ann's laptop").expect("a valid name"),
        last_user_agent: UserAgent::new("Mozilla/5.0").expect("a valid user agent"),
        last_ip: IpAddress::new("203.0.113.7").expect("a valid address"),
        status: DeviceStatus::Trusted,
        last_seen_at: at(0),
        created_at: at(0),
    }
}

/// A code mailed for `user_id`'s factor, set up at the fixed moment, sent
/// `seconds` later for five minutes under the hash `code`, not tried yet.
#[must_use]
pub fn sent_code_row(user_id: UserId, code: &str, seconds: i64) -> OneTimeCodeRow {
    OneTimeCodeRow {
        subject_id: PrincipalId::from(user_id),
        enrolled_at: at(0),
        method: MfaMethod::EmailCode,
        code_hash: hash(code),
        issued_at: at(seconds),
        expires_at: at(seconds.saturating_add(300)),
        wrong_tries: 0,
        usage: Usage::Unused,
    }
}

/// An unused sign-in code hashing to `code` for `session_id`, held by the
/// dashboard secret hashing to `dashboard`, working for a minute.
#[must_use]
pub fn sign_in_code_row(session_id: SessionId, code: &str, dashboard: &str) -> SignInCodeRow {
    SignInCodeRow {
        token_hash: hash(code),
        dashboard_hash: hash(dashboard),
        session_id,
        expires_at: at(60),
        usage: Usage::Unused,
    }
}

/// An open second-factor challenge hashing to `token` for `session_id`,
/// with no wrong code yet, working for five minutes.
#[must_use]
pub fn challenge_row(session_id: SessionId, token: &str) -> MfaChallengeRow {
    MfaChallengeRow {
        token_hash: hash(token),
        session_id,
        expires_at: at(300),
        failed_attempts: 0,
        usage: Usage::Unused,
    }
}

/// An unused pass hashing to `code` carrying `session_id` to the shop's
/// host for `service_id`, bound to the browser keeping `browser-of-{code}`,
/// working for a minute.
///
/// # Panics
///
/// Never: the host is a valid name.
#[must_use]
pub fn handoff_row(session_id: SessionId, service_id: ServiceId, code: &str) -> SessionHandoffRow {
    SessionHandoffRow {
        token_hash: hash(code),
        browser_hash: hash(&format!("browser-of-{code}")),
        session_id,
        service_id,
        host: DomainName::new("shop.example.com").expect("a valid host"),
        expires_at: at(60),
        usage: Usage::Unused,
    }
}

/// What a break-glass grant or policy hands out: viewing users.
///
/// # Panics
///
/// Never: it names one permission.
#[must_use]
pub fn viewing_users() -> BreakGlassAccess {
    BreakGlassAccess::new(vec![SystemPermission::Users(UserAction::View)], Vec::new())
        .expect("access naming one permission")
}

/// A self-approved grant of [`viewing_users`] in `tenant_id` to `user_id`,
/// the person at `ann@acme.example`, made `seconds` past the fixed moment
/// for an hour.
///
/// # Panics
///
/// Never: its person and reason are valid ones.
#[must_use]
pub fn grant_row(tenant_id: TenantId, user_id: UserId, seconds: i64) -> BreakGlassGrantRow {
    BreakGlassGrantRow {
        id: BreakGlassGrantId::new(),
        tenant_id,
        user_id,
        grantee_person: PersonKey::new("ann@acme.example").expect("a valid person"),
        access: viewing_users(),
        reason: Text::new("reason", "incident 42").expect("a valid reason"),
        approved_by: GrantApproval::SelfApproved,
        expires_at: at(seconds.saturating_add(3600)),
        revocation: Revocation::InForce,
        created_at: at(seconds),
    }
}

/// `tenant_id`'s policy letting its users give themselves
/// [`viewing_users`], set at the fixed moment.
#[must_use]
pub fn policy_row(tenant_id: TenantId) -> BreakGlassPolicyRow {
    BreakGlassPolicyRow {
        tenant_id,
        self_service: SelfService::UpTo(viewing_users()),
        updated_at: at(0),
    }
}

/// A session of `user`, already saved in `tenant`, saved through the
/// session store, as the rows that name a session point at one the tenant
/// keeps.
///
/// # Panics
///
/// When the session cannot be saved, which is a broken test database or a
/// user never saved.
pub async fn session_of(
    databases: &Arc<Databases>,
    tenant: &ScopedTenant,
    user: UserId,
) -> SessionId {
    let refresh = format!("refresh-{}", SessionId::new().as_uuid().simple());
    let session = Session::reconstitute(session_row(user, &refresh)).expect("a valid session");
    PgSessionStore::new(Arc::clone(databases))
        .save(tenant, &session)
        .await
        .expect("the session is saved");
    *session.id()
}

/// A session of a new user of `tenant`, the user and the session both
/// saved through their stores.
///
/// # Panics
///
/// When either cannot be saved, which is a broken test database.
pub async fn signed_in_session(databases: &Arc<Databases>, tenant: &ScopedTenant) -> SessionId {
    let address = format!("u{}@acme.example", UserId::new().as_uuid().simple());
    let user = User::reconstitute(user_row(&address)).expect("a valid user");
    PgUserStore::new(Arc::clone(databases), DomainLimits::default())
        .save(tenant, &user)
        .await
        .expect("the user is saved");
    session_of(databases, tenant, *user.id()).await
}
