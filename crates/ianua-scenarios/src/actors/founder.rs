//! Someone who signs a company up: the first actor of all, before there is
//! a world to stand in. Used by the scenarios about signing up and signing
//! in, which need a company and nothing more.

use crate::api::{OrgPath, member_factors, sessions};
use crate::authenticators::TotpApp;
use crate::mail::Mail;
use crate::net::Client;
use crate::stack::{Stack, secrets};
use crate::wire::Answer;
use crate::wire::factors::{ConfirmFactor, FactorCode};
use crate::wire::onboarding::{ConfirmSignup, Founded, Signup, SignupAccepted};
use crate::wire::sign_in::{
    ConfirmSignIn, ConfirmedSignIn, DeviceRemembered, MemberFactorSetup, MemberProof, Owed,
    PasswordSignIn, RememberDevice, Session, SignedIn,
};

/// The password a founder chooses: a sentence, so no scanner takes it for
/// a key.
pub const FOUNDER_PASSWORD: &str = "Scenario lantern harbour meadow 4821";

/// The bytes of a device secret: 64 hex digits, as a browser makes it.
const DEVICE_SECRET_BYTES: usize = 32;

/// Someone signing a company up, with an address under the stack's domain,
/// a client of their own, and the device secret their browser keeps, sent
/// with every sign-in as the dashboard sends it.
pub struct Founder {
    email: String,
    client: Client,
    device_secret: String,
}

impl std::fmt::Debug for Founder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Founder")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

impl Founder {
    /// `name`, at an address of their own under the stack's domain.
    ///
    /// # Panics
    ///
    /// When the client cannot be built.
    /// A founder needs a usable browser before the scenario can begin.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn named(stack: &Stack, name: &str) -> Self {
        Self {
            email: format!("{}@{}", name.to_lowercase(), stack.base_domain()),
            client: Client::new(stack, &format!("{name}, a founder")).expect("a client"),
            device_secret: secrets::hex(DEVICE_SECRET_BYTES),
        }
    }

    /// They set up an authenticator app on `org_slug` from the `session`
    /// they hold, as an owner does in the dashboard: the password typed
    /// again opens the setup, the app scans its link, and its first code
    /// confirms it. Answers the app.
    ///
    /// # Panics
    ///
    /// When the setup or its confirmation is refused.
    pub async fn set_up_authenticator(&self, org_slug: &str, session: &Session) -> TotpApp {
        let org = OrgPath::new(org_slug);
        let bearer = format!("Bearer {}", session.refresh_token);
        let setup = MemberFactorSetup {
            proof: MemberProof {
                password: FOUNDER_PASSWORD.to_owned(),
                code: None,
            },
        };
        let begun = member_factors::begin_totp(&org, &setup)
            .header("authorization", &bearer)
            .send(&self.client)
            .await
            .ok();
        let mut phone = TotpApp::scanning(&begun.otpauth_uri);
        let confirm = ConfirmFactor {
            code: phone.code().await,
            session_id: None,
        };
        member_factors::confirm_totp(&org, &confirm)
            .header("authorization", &bearer)
            .send(&self.client)
            .await
            .ok();
        phone
    }

    /// They sign in with [`FOUNDER_PASSWORD`] and answer with a code from
    /// `phone` when the sign-in asks for one, as the dashboard leads them.
    ///
    /// # Panics
    ///
    /// When the sign-in or the code is refused, or the sign-in offers a
    /// choice.
    pub async fn signed_in_with(&self, stack: &Stack, phone: &mut TotpApp) -> Session {
        let session = self.password_sign_in().await;
        if session.owed() != Owed::FactorCode {
            return self.settled(stack, session).await;
        }
        let org = OrgPath::new(&session.org_slug);
        let verify = FactorCode {
            code: phone.code().await,
        };
        member_factors::verify(&org, &verify)
            .header(
                "authorization",
                &format!("Bearer {}", session.refresh_token),
            )
            .send(&self.client)
            .await
            .ok();
        session
    }

    /// They remember the device they signed in from, as the dashboard
    /// offers after a sign-in: their browser's secret is kept under a name,
    /// so later sign-ins from it are known. `org_slug` is their
    /// organization, `session` the session they hold.
    pub async fn remember_device(
        &self,
        org_slug: &str,
        session: &Session,
    ) -> Answer<DeviceRemembered> {
        let remember = RememberDevice {
            fingerprint_hash: self.device_secret.clone(),
            device_name: "Founder's laptop".to_owned(),
        };
        let bearer = format!("Bearer {}", session.refresh_token);
        sessions::remember_device(&OrgPath::new(org_slug), &remember)
            .header("authorization", &bearer)
            .send(&self.client)
            .await
    }

    /// Their address.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Browser state used for this founder's API requests.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Their client, to hand it a session's token.
    pub fn client_mut(&mut self) -> &mut Client {
        &mut self.client
    }

    /// The sign-up they send for `company`, with `password`.
    #[must_use]
    pub fn sign_up_of(&self, company: &str, password: &str) -> Signup {
        Signup {
            company_name: company.to_owned(),
            tenant_name: "Production".to_owned(),
            admin_email: self.email.clone(),
            admin_display_name: format!("{company} Owner"),
            admin_password: password.to_owned(),
        }
    }

    /// They ask for `company` with [`FOUNDER_PASSWORD`], are answered
    /// "check your inbox", and found it from the mailed link.
    ///
    /// # Panics
    ///
    /// When the sign-up or the founding is refused, or no link comes.
    pub async fn founded(&self, stack: &Stack, company: &str) -> Founded {
        let accepted = self
            .client
            .post::<SignupAccepted>(
                "/api/v1/signup",
                &self.sign_up_of(company, FOUNDER_PASSWORD),
            )
            .await
            .ok();
        assert_eq!(accepted.status, "check_inbox");
        let link = stack.mailbox().next_for(&self.email).await;
        self.confirmed_sign_up(&link).await.ok()
    }

    /// They follow the sign-up link in `mail`.
    pub async fn confirmed_sign_up(&self, mail: &Mail) -> Answer<Founded> {
        let confirm = ConfirmSignup {
            token: mail.token_in("/signup/confirm"),
        };
        self.client
            .post::<Founded>("/api/v1/signup/confirm", &confirm)
            .await
    }

    /// They sign in with [`FOUNDER_PASSWORD`], confirming the sign-in from
    /// their mailbox when the platform asks them to, as the dashboard leads
    /// them.
    ///
    /// # Panics
    ///
    /// When the sign-in is refused, offers a choice, or owes a second
    /// factor a fresh founder does not have.
    pub async fn signed_in(&self, stack: &Stack) -> Session {
        let session = self.password_sign_in().await;
        self.settled(stack, session).await
    }

    /// The session their password opens, from their browser's device, owing
    /// whatever the platform asks for still: to see what a sign-in from
    /// this device is asked for, before answering it.
    ///
    /// # Panics
    ///
    /// When the sign-in is refused or offers a choice.
    pub async fn password_sign_in(&self) -> Session {
        let sign_in =
            PasswordSignIn::of(&self.email, FOUNDER_PASSWORD).from_device(&self.device_secret);
        let answer = self
            .client
            .post::<SignedIn>("/api/v1/login", &sign_in)
            .await
            .ok();
        let SignedIn::Authenticated(session) = answer else {
            panic!("a founder of one organization signs in without a choice");
        };
        tracing::debug!(founder = %self.email, owed = ?session.owed(), "signed in");
        session
    }

    /// `session` once nothing is owed: confirmed from the mailbox when the
    /// platform asks for that.
    ///
    /// # Panics
    ///
    /// When it owes a second factor, which [`Founder::signed_in_with`]
    /// answers.
    async fn settled(&self, stack: &Stack, session: Session) -> Session {
        match session.owed() {
            Owed::Nothing => session,
            Owed::MailedConfirmation => {
                let mail = stack.mailbox().next_for(&self.email).await;
                self.confirmed_sign_in(session, &mail).await
            }
            Owed::FactorEnrolment | Owed::FactorCode => {
                panic!(
                    "the sign-in owes {:?}; sign in with the authenticator instead",
                    session.owed()
                )
            }
        }
    }

    /// Their waiting `session`, confirmed with the link in `mail`.
    async fn confirmed_sign_in(&self, session: Session, mail: &Mail) -> Session {
        let confirm = ConfirmSignIn {
            token: mail.token_in("/confirm-sign-in"),
            refresh_token: session.refresh_token.clone(),
        };
        let confirmed = self
            .client
            .post::<ConfirmedSignIn>("/api/v1/login/confirm", &confirm)
            .await
            .ok();
        assert_eq!(confirmed.session_id, session.session_id);
        session
    }
}
