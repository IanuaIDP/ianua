//! What the policy scenarios share: one point of the admission matrix and
//! the settings it makes, the settings compared whole, Ann saving them,
//! and Pat signed in as the policy asks, with an authenticator set up
//! when one is required.

use std::ops::Range;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{factors, people, sessions, tenants};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{ConfirmFactor, FactorSetup};
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::{
    ConfirmTenantSignIn, TenantPasswordSignIn, TenantSession, TenantSignedIn,
};
use ianua_scenarios::wire::tenants::{
    MfaPolicy, PasswordAgain, ReplaceSignInSettings, SignInSettings,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::mail_linking_to;

/// The ways in a tenant may offer, in the order of their bits in a mask.
const METHODS: [&str; 5] = ["Password", "MagicLink", "Passkey", "Saml", "Oidc"];

/// The password's bit in a mask: the only way in the public form takes.
const PASSWORD: u8 = 1;

/// The mailed link's bit in a mask: a way in no deployment without a mail
/// server can offer.
const MAGIC_LINK: u8 = 1 << 1;

/// The bits of the passkey, SAML and OIDC: the ways in that alone reach
/// the stronger assurances.
const STRONG: u8 = (1 << 2) | (1 << 3) | (1 << 4);

/// Every nonempty subset of the five ways in, as masks.
pub(super) const SUBSETS: Range<u8> = 1..32;

/// One point of the admission matrix: which ways in are offered, whether
/// the public may register, and the second-factor policy.
pub(super) struct Admission {
    /// The ways in, one bit each in the order of `METHODS`.
    pub(super) mask: u8,
    /// Whether the public may register.
    pub(super) registration: Registration,
    /// What a new account must do after proving its mailbox.
    pub(super) mfa: MfaPolicy,
}

/// Whether the tenant takes accounts from its public form.
#[derive(Clone, Copy, Debug)]
pub(super) enum Registration {
    /// Anyone may register.
    Open,
    /// Only administrators make accounts.
    Closed,
}

impl Admission {
    /// Every point with `mfa`: each subset of the ways in, closed and
    /// open, 62 in all.
    pub(super) fn cases(mfa: MfaPolicy) -> Vec<Self> {
        [Registration::Closed, Registration::Open]
            .into_iter()
            .flat_map(|registration| {
                SUBSETS.map(move |mask| Self {
                    mask,
                    registration,
                    mfa,
                })
            })
            .collect()
    }

    /// Whether the policy admits a password registration: open to the
    /// public, with the password a way in. The deployment may still
    /// refuse it, for want of a mail server.
    pub(super) fn advertised(&self) -> bool {
        matches!(self.registration, Registration::Open) && self.mask & PASSWORD != 0
    }

    /// Whether the mailed link is among the ways in.
    pub(super) fn offers_magic_link(&self) -> bool {
        self.mask & MAGIC_LINK != 0
    }

    /// Whether a passkey, SAML or OIDC is among the ways in.
    pub(super) fn offers_a_strong_method(&self) -> bool {
        self.mask & STRONG != 0
    }

    /// A name for this point, to tell it apart in a failure and in the
    /// addresses it registers.
    pub(super) fn name(&self) -> String {
        format!("case-{:?}-{:?}-{}", self.mfa, self.registration, self.mask).to_lowercase()
    }

    /// `settings` with this point's ways in, registration and
    /// second-factor policy, and everything else as it was.
    pub(super) fn settings(&self, mut settings: SignInSettings) -> SignInSettings {
        settings.mfa_policy = self.mfa;
        settings.enabled_methods = METHODS
            .iter()
            .enumerate()
            .filter(|(bit, _)| self.mask & (1 << bit) != 0)
            .map(|(_, name)| (*name).to_owned())
            .collect();
        settings.rest.insert(
            "self_registration".to_owned(),
            json!(matches!(self.registration, Registration::Open)),
        );
        settings
    }
}

/// `settings` as JSON, to compare whole with what the API answers after
/// a save.
pub(super) fn as_json(settings: &SignInSettings) -> serde_json::Value {
    serde_json::to_value(settings).expect("sign-in settings serialize")
}

/// Ann saves `settings` on the tenant, her password typed again.
///
/// # Panics
///
/// When the save is refused.
pub(super) async fn saved(world: &World<'_>, settings: SignInSettings) {
    tenants::replace_sign_in_settings(
        world.tenant(),
        &ReplaceSignInSettings {
            settings,
            proof: PasswordAgain {
                password: world.owner().password().to_owned(),
                code: None,
            },
        },
    )
    .send(world.owner().client())
    .await
    .ok();
}

/// `person`, whose mailbox is proved, signs in on a device of their own:
/// the mailed confirmation a new device owes is answered, an authenticator
/// is set up exactly when `mfa` requires one, and then they read their
/// own verified record and nothing of the users or the twin tenant.
///
/// # Panics
///
/// When the sign-in owes other than `mfa` says, or any step is refused.
pub(super) async fn signed_in_under(world: &World<'_>, person: &Person, mfa: MfaPolicy) {
    let mut device = Client::new(world.stack(), person.email()).expect("a client");
    let session = sign_in_password(world, person, &device).await;
    device.authorize(&session.refresh_token);
    let owed = confirm_new_device(world, person, &device, &session).await;
    let expected = match mfa {
        MfaPolicy::Required => Owed::FactorEnrolment,
        MfaPolicy::Disabled | MfaPolicy::Optional => Owed::Nothing,
    };
    assert_eq!(
        owed,
        expected,
        "{} owes what the policy {mfa:?} asks",
        person.email()
    );
    if owed == Owed::FactorEnrolment {
        authenticator_confirmed(world, &device, &session.session_id).await;
    }
    assert_user_access(world, person, &device).await;
}

/// The password chosen at signup opens a session without another password change.
async fn sign_in_password(world: &World<'_>, person: &Person, device: &Client) -> TenantSession {
    let answer = sessions::sign_in(
        world.tenant(),
        &TenantPasswordSignIn {
            email: person.email().to_owned(),
            password: person.password().to_owned(),
            fingerprint_hash: None,
        },
    )
    .send(device)
    .await
    .ok();
    let TenantSignedIn::Session(session) = answer else {
        panic!(
            "{} chose their own password, so none is owed",
            person.email()
        );
    };
    session
}

/// A new device proves the mailbox before the remaining factor requirement is read.
async fn confirm_new_device(
    world: &World<'_>,
    person: &Person,
    device: &Client,
    session: &TenantSession,
) -> Owed {
    match session.owed() {
        Owed::MailedConfirmation => {
            people::me(world.tenant())
                .send(device)
                .await
                .refused(Status::UNAUTHORIZED, "unauthenticated");
            let mail = mail_linking_to(world.stack(), person.email(), "/confirm-sign-in").await;
            sessions::confirm_sign_in(
                world.tenant(),
                &ConfirmTenantSignIn {
                    link: mail.token_in("/confirm-sign-in"),
                    session_token: session.refresh_token.clone(),
                },
            )
            .send(device)
            .await
            .ok()
            .owed()
        }
        owed => owed,
    }
}

/// The completed session reads its verified account but neither user listings nor the twin tenant.
async fn assert_user_access(world: &World<'_>, person: &Person, device: &Client) {
    let own = people::me(world.tenant()).send(device).await.ok();
    assert_eq!(own.id, person.id(), "the record read is their own");
    assert!(own.email_verified, "with the address proved");
    people::list(world.tenant(), None)
        .send(device)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::me(world.twin())
        .send(device)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// The session `session_id` on `device` reads nothing until an
/// authenticator is set up and its first code confirmed.
///
/// # Panics
///
/// When the setup or its confirmation is refused.
async fn authenticator_confirmed(world: &World<'_>, device: &Client, session_id: &str) {
    people::me(world.tenant())
        .send(device)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let begun = factors::enroll_totp(world.tenant(), &FactorSetup::default())
        .send(device)
        .await
        .ok();
    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    factors::confirm_totp(
        world.tenant(),
        &ConfirmFactor {
            code: phone.code().await,
            session_id: Some(session_id.to_owned()),
        },
    )
    .send(device)
    .await
    .ok();
}
