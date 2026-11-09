//! A tenant user with their own devices: their password, an authenticator
//! app on their phone, a passkey, and the recovery codes printed at setup.
//! They join from a mailed invitation, sign in every way the tenant lets
//! them, confirm a new device from their mailbox when asked, and reset a
//! forgotten password by mail.
//!
//! The API keeps a tenant user's session in the bearer token its sign-in
//! answered with; this person's client sends it, and keeps whatever
//! cookies the platform sets in its own jar.

use std::fmt;

use serde::de::DeserializeOwned;

use super::mailed::mail_linking;
use crate::api::{Request, TenantPath, factors, people, sessions};
use crate::authenticators::{PasskeyAnswer, RecoveryCodes, SoftPasskey, TotpApp};
use crate::net::Client;
use crate::stack::Stack;
use crate::wire::factors::{
    ConfirmFactor, ConfirmPasskey, FactorSetup, PasskeyAnswerBody, PasskeySignInFor, Proof,
    SessionCode,
};
use crate::wire::people::{AcceptInvitation, UserJoined};
use crate::wire::sign_in::Owed;
use crate::wire::tenant_sign_in::{
    ConfirmPasswordReset, ConfirmTenantSignIn, PasswordResetFor, PasswordSet, TenantPasswordSignIn,
    TenantSession, TenantSignedIn,
};
use crate::wire::{Answer, Exchange, Status};

/// Who a person is and the tenant they belong to.
#[derive(Debug, Clone)]
pub struct PersonAccount {
    /// Their address.
    pub email: String,
    /// Human-readable label attached to the tenant account.
    pub display_name: String,
    /// API scope in which the actor's account and sessions live.
    pub tenant: TenantPath,
}

/// How a sign-in proved the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedInWith {
    /// The password alone.
    Password,
    /// The password and a code from the authenticator app.
    PasswordAndCode,
    /// A printed single-use proof substituted for the unavailable authenticator.
    PasswordAndRecoveryCode,
    /// A WebAuthn assertion satisfied authentication without a password.
    Passkey,
}

/// What answers a sign-in that owes a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeFrom {
    /// The authenticator app.
    Phone,
    /// A recovery code.
    Printout,
}

/// A tenant user with their own client, password and devices. `Debug`
/// shows no secret.
pub struct Person {
    client: Client,
    account: PersonAccount,
    password: String,
    id: Option<String>,
    session: Option<HeldSession>,
    phone: Option<TotpApp>,
    passkey: Option<SoftPasskey>,
    recovery: Option<RecoveryCodes>,
    secrets: Vec<String>,
    exchanges: Vec<Exchange>,
}

/// The session a person holds, named by its id; its token is the one the
/// person's client sends.
#[derive(Clone)]
struct HeldSession {
    id: String,
}

impl fmt::Debug for Person {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Person")
            .field("account", &self.account)
            .field("id", &self.id)
            .field("signed_in", &self.session.is_some())
            .field("phone", &self.phone)
            .field("passkey", &self.passkey)
            .field("recovery", &self.recovery)
            .finish_non_exhaustive()
    }
}

impl Person {
    /// `account` with `password`, acting through `client`, not yet a user
    /// of the tenant.
    #[must_use]
    pub fn new(client: Client, account: PersonAccount, password: &str) -> Self {
        Self {
            client,
            account,
            password: password.to_owned(),
            id: None,
            session: None,
            phone: None,
            passkey: None,
            recovery: None,
            secrets: vec![password.to_owned()],
            exchanges: Vec::new(),
        }
    }

    /// The client they act through.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Takes the session `refresh_token` names as theirs from now on, as
    /// when single sign-on hands one back, keeping it among the secrets
    /// nothing may echo.
    pub fn hold_session(&mut self, refresh_token: &str) {
        self.secrets.push(refresh_token.to_owned());
        self.client.authorize(refresh_token);
    }

    /// Who they are.
    #[must_use]
    pub fn account(&self) -> &PersonAccount {
        &self.account
    }

    /// Their address.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.account.email
    }

    /// API scope used by requests concerning this actor's account.
    #[must_use]
    pub fn tenant(&self) -> &TenantPath {
        &self.account.tenant
    }

    /// Their password now.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Their user id.
    ///
    /// # Panics
    ///
    /// Before they were invited.
    #[must_use]
    pub fn id(&self) -> &str {
        let Some(id) = &self.id else {
            panic!("{} has no account yet", self.account.email);
        };
        id
    }

    /// The session they hold now.
    ///
    /// # Panics
    ///
    /// When they are not signed in.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.held_session().id
    }

    /// Their authenticator app, while they have their phone.
    #[must_use]
    pub fn phone(&self) -> Option<&TotpApp> {
        self.phone.as_ref()
    }

    /// Their passkey, once they added one.
    #[must_use]
    pub fn passkey(&self) -> Option<&SoftPasskey> {
        self.passkey.as_ref()
    }

    /// Their recovery codes, once a factor was set up.
    #[must_use]
    pub fn recovery_codes(&self) -> Option<&RecoveryCodes> {
        self.recovery.as_ref()
    }

    /// Records the account an invitation made for them.
    pub fn record_invitation(&mut self, user_id: &str) {
        self.id = Some(user_id.to_owned());
    }

    /// Sends `request` as them and keeps the exchange.
    pub async fn send<T: DeserializeOwned>(&mut self, request: Request<T>) -> Answer<T> {
        let answer = request.send(&self.client).await;
        self.exchanges.push(answer.exchange().clone());
        answer
    }

    /// Accepts the invitation mailed to them, choosing their password.
    ///
    /// # Panics
    ///
    /// When no invitation comes, or accepting it is refused.
    pub async fn accept_invitation(&mut self, stack: &Stack) {
        let token = self.invitation_token(stack).await;
        let password = self.password.clone();
        self.accept_with(&token, &password).await.ok();
    }

    /// The token of the invitation mailed to them.
    ///
    /// # Panics
    ///
    /// When no invitation comes.
    pub async fn invitation_token(&mut self, stack: &Stack) -> String {
        let mail = mail_linking(stack.mailbox(), &self.account.email, "/accept-invite").await;
        let token = mail.token_in("/accept-invite");
        self.secrets.push(token.clone());
        token
    }

    /// Accepts the invitation `token` names choosing `password`, and
    /// answers what the API said. Once accepted, `password` is theirs.
    pub async fn accept_with(&mut self, token: &str, password: &str) -> Answer<UserJoined> {
        let accept = AcceptInvitation {
            token: token.to_owned(),
            password: password.to_owned(),
        };
        let tenant = self.account.tenant.clone();
        let answer = self.send(people::accept_invitation(&tenant, &accept)).await;
        let Some(joined) = answer.value() else {
            return answer;
        };
        self.id = Some(joined.id.clone());
        self.password = password.to_owned();
        self.secrets.push(password.to_owned());
        answer
    }

    /// Signs in with their password, answering whatever the sign-in owes:
    /// the link mailed for a new device, and a code from their phone.
    ///
    /// # Panics
    ///
    /// When the sign-in is refused, or owes a code and their phone is
    /// gone.
    pub async fn sign_in(&mut self, stack: &Stack) -> SignedInWith {
        self.signed_in_by_password(stack, CodeFrom::Phone).await
    }

    /// Signs in with their password and, for the code it owes, one of
    /// their recovery codes, as when the phone is lost.
    ///
    /// # Panics
    ///
    /// When the sign-in is refused or owes no code, or no code is left.
    pub async fn sign_in_with_recovery_code(&mut self, stack: &Stack) -> SignedInWith {
        self.signed_in_by_password(stack, CodeFrom::Printout).await
    }

    /// Signs in with their passkey, on a challenge listing their passkeys.
    ///
    /// # Panics
    ///
    /// When they have no passkey, or the sign-in is refused or still owes
    /// something.
    pub async fn sign_in_with_passkey(&mut self) -> SignedInWith {
        self.client.forget_authorization();
        let challenge = self.passkey_challenge().await;
        let answer = self.passkey_mut().sign_in(&challenge.1);
        let tenant = self.account.tenant.clone();
        let body = answer_body(&challenge.0, &answer);
        let session = self
            .send(factors::confirm_passkey_sign_in(&tenant, &body))
            .await
            .ok();
        assert_eq!(
            session.owed(),
            Owed::Nothing,
            "a passkey proves the person on its own"
        );
        self.hold(&session);
        SignedInWith::Passkey
    }

    /// A passkey sign-in challenge for them: the ceremony's id and its
    /// options.
    ///
    /// # Panics
    ///
    /// When it is refused.
    pub async fn passkey_challenge(&mut self) -> (String, String) {
        let whose = PasskeySignInFor {
            email: self.account.email.clone(),
        };
        let tenant = self.account.tenant.clone();
        let challenge = self
            .send(factors::begin_passkey_sign_in(&tenant, &whose))
            .await
            .ok();
        (challenge.ceremony_id, challenge.challenge)
    }

    /// Sets up the authenticator app on their phone, proving who they are
    /// with their password, and keeps the recovery codes it comes with.
    ///
    /// # Panics
    ///
    /// When they are not signed in, or the setup is refused.
    pub async fn set_up_authenticator(&mut self) {
        let tenant = self.account.tenant.clone();
        let setup = FactorSetup {
            proof: Some(self.password_proof(None)),
        };
        let link = self.send(factors::enroll_totp(&tenant, &setup)).await.ok();
        let mut phone = TotpApp::scanning(&link.otpauth_uri);
        self.secrets.push(phone.secret().to_owned());
        let confirm = ConfirmFactor {
            code: phone.code().await,
            session_id: None,
        };
        let shown = self
            .send(factors::confirm_totp(&tenant, &confirm))
            .await
            .ok();
        self.secrets.extend(shown.recovery_codes.iter().cloned());
        self.recovery = Some(RecoveryCodes::printed(shown.recovery_codes));
        self.phone = Some(phone);
    }

    /// Adds a passkey on this device, named `name`, proving who they are
    /// with their password and a code from their phone when they have one.
    /// Every other session of theirs ends; this one stays.
    ///
    /// # Panics
    ///
    /// When they are not signed in, or adding it is refused.
    pub async fn add_passkey(&mut self, stack: &Stack, name: &str) {
        let passkey = SoftPasskey::new(&stack.app_url());
        let answer = self.registration_answer(&passkey).await;
        self.confirm_registration(&answer, name).await.ok();
        self.passkey = Some(passkey);
    }

    /// Begins adding a passkey and answers the challenge with `passkey`:
    /// the ceremony's id and the answer.
    ///
    /// # Panics
    ///
    /// When beginning is refused.
    pub async fn registration_answer(&mut self, passkey: &SoftPasskey) -> (String, PasskeyAnswer) {
        let tenant = self.account.tenant.clone();
        let challenge = self.send(factors::begin_passkey(&tenant)).await.ok();
        (
            challenge.ceremony_id,
            passkey.register(&challenge.challenge),
        )
    }

    /// Confirms the registration `answer` names, as the passkey `name`,
    /// with their proof, and answers what the API said.
    pub async fn confirm_registration(
        &mut self,
        answer: &(String, PasskeyAnswer),
        name: &str,
    ) -> Answer<()> {
        let code = self.phone_code().await;
        let confirm = ConfirmPasskey {
            ceremony_id: answer.0.clone(),
            response: answer.1.response.clone(),
            passkey_name: name.to_owned(),
            proof: Some(self.password_proof(code)),
        };
        let tenant = self.account.tenant.clone();
        self.send(factors::confirm_passkey(&tenant, &confirm)).await
    }

    /// Their phone, which they no longer have; codes must come from
    /// elsewhere until it is found.
    ///
    /// # Panics
    ///
    /// When they have no phone.
    pub fn lose_phone(&mut self) -> TotpApp {
        let Some(phone) = self.phone.take() else {
            panic!("{} has no phone to lose", self.account.email);
        };
        phone
    }

    /// Their phone, found again.
    pub fn find_phone(&mut self, phone: TotpApp) {
        self.phone = Some(phone);
    }

    /// Asks for a reset link for a forgotten password and answers the
    /// token mailed to them.
    ///
    /// # Panics
    ///
    /// When asking is refused or no link comes.
    pub async fn reset_link(&mut self, stack: &Stack) -> String {
        let whose = PasswordResetFor {
            email: self.account.email.clone(),
        };
        let tenant = self.account.tenant.clone();
        self.send(sessions::request_password_reset(&tenant, &whose))
            .await
            .ok();
        let mail = mail_linking(stack.mailbox(), &self.account.email, "/reset-password").await;
        let token = mail.token_in("/reset-password");
        self.secrets.push(token.clone());
        token
    }

    /// Sets `new_password` with the reset `token`, with a code from their
    /// phone when they have one, and answers what the API said. On success
    /// the password is theirs and every session of theirs has ended.
    pub async fn confirm_reset(&mut self, token: &str, new_password: &str) -> Answer<PasswordSet> {
        let confirm = ConfirmPasswordReset {
            token: token.to_owned(),
            new_password: new_password.to_owned(),
            mfa_code: self.phone_code().await,
        };
        self.secrets.push(new_password.to_owned());
        let tenant = self.account.tenant.clone();
        let answer = self
            .send(sessions::confirm_password_reset(&tenant, &confirm))
            .await;
        if answer.status() == Status::OK {
            self.password = new_password.to_owned();
            self.session = None;
            self.client.forget_authorization();
        }
        answer
    }

    /// A client of their own on another device, signed in and then signed
    /// out again: it still sends the token of a session that ended.
    ///
    /// # Panics
    ///
    /// When the sign-in or the sign-out is refused.
    pub async fn signed_out(&mut self, stack: &Stack) -> Client {
        let (device, _) = self.on_another_device(stack, "signed out").await;
        let tenant = self.account.tenant.clone();
        let answer = sessions::sign_out(&tenant).send(&device).await;
        self.exchanges.push(answer.exchange().clone());
        answer.ok();
        device
    }

    /// A client of their own on another device, signed in with their
    /// password, and the id of its session, for an administrator to end.
    /// Their own client keeps its session.
    ///
    /// # Panics
    ///
    /// When the sign-in is refused.
    /// This scenario action requires a separate browser before signing in.
    #[allow(clippy::expect_used)]
    pub async fn on_another_device(&mut self, stack: &Stack, why: &str) -> (Client, String) {
        let actor = format!("{}, {why}", self.client.actor());
        let device = Client::new(stack, &actor).expect("a client for another device");
        let own_client = std::mem::replace(&mut self.client, device);
        let own_session = self.session.clone();
        self.signed_in_by_password(stack, CodeFrom::Phone).await;
        let device = std::mem::replace(&mut self.client, own_client);
        let device_session = std::mem::replace(&mut self.session, own_session);
        let Some(device_session) = device_session else {
            unreachable!("a finished sign-in holds a session");
        };
        (device, device_session.id)
    }

    /// The secrets they hold or held, to make sure none appears where it
    /// should not: passwords, tokens, mailed links, the authenticator's
    /// secret and the recovery codes.
    #[must_use]
    pub fn secrets(&self) -> Vec<String> {
        self.secrets.clone()
    }

    /// Every exchange they made since this was last asked.
    pub fn take_exchanges(&mut self) -> Vec<Exchange> {
        std::mem::take(&mut self.exchanges)
    }

    /// Signs in with their password and answers what it owes, a code
    /// coming `from` the phone or the printout.
    async fn signed_in_by_password(&mut self, stack: &Stack, from: CodeFrom) -> SignedInWith {
        self.client.forget_authorization();
        let sign_in = TenantPasswordSignIn {
            email: self.account.email.clone(),
            password: self.password.clone(),
            fingerprint_hash: None,
        };
        let tenant = self.account.tenant.clone();
        let answer = self.send(sessions::sign_in(&tenant, &sign_in)).await.ok();
        let TenantSignedIn::Session(session) = answer else {
            panic!("{}'s own password owes no change", self.account.email);
        };
        self.hold(&session);
        let owed = self.confirmed_by_mail(stack, &session).await;
        self.answer_owed(owed, from).await
    }

    /// What `session` owes once a link mailed for it is followed, when it
    /// waited for one.
    async fn confirmed_by_mail(&mut self, stack: &Stack, session: &TenantSession) -> Owed {
        if session.owed() != Owed::MailedConfirmation {
            return session.owed();
        }
        let mail = mail_linking(stack.mailbox(), &self.account.email, "/confirm-sign-in").await;
        let confirm = ConfirmTenantSignIn {
            link: mail.token_in("/confirm-sign-in"),
            session_token: session.refresh_token.clone(),
        };
        let tenant = self.account.tenant.clone();
        let confirmed = self
            .send(sessions::confirm_sign_in(&tenant, &confirm))
            .await
            .ok();
        confirmed.owed()
    }

    /// Answers what the held session owes, a code coming `from` the phone
    /// or the printout.
    ///
    /// # Panics
    ///
    /// When it owes a factor to set up, or a code they cannot give.
    async fn answer_owed(&mut self, owed: Owed, from: CodeFrom) -> SignedInWith {
        match (owed, from) {
            (Owed::Nothing, CodeFrom::Phone) => SignedInWith::Password,
            (Owed::FactorCode, CodeFrom::Phone) => self.answered_from_phone().await,
            (Owed::FactorCode, CodeFrom::Printout) => self.answered_from_printout().await,
            (other, _) => panic!(
                "{}'s sign-in owes {other:?}, which they cannot answer that way",
                self.account.email
            ),
        }
    }

    /// The held sign-in, answered with a code from the phone.
    async fn answered_from_phone(&mut self) -> SignedInWith {
        let Some(code) = self.phone_code().await else {
            panic!(
                "{}'s sign-in owes a code and their phone is gone",
                self.account.email
            );
        };
        let answer = SessionCode {
            session_id: self.session_id().to_owned(),
            code,
        };
        let tenant = self.account.tenant.clone();
        self.send(factors::verify(&tenant, &answer)).await.ok();
        SignedInWith::PasswordAndCode
    }

    /// The held sign-in, answered with the next recovery code.
    async fn answered_from_printout(&mut self) -> SignedInWith {
        let session_id = self.held_session().id.clone();
        let Some(codes) = self.recovery.as_mut() else {
            panic!("{} was never shown recovery codes", self.account.email);
        };
        let answer = SessionCode {
            session_id,
            code: codes.take(),
        };
        let tenant = self.account.tenant.clone();
        self.send(factors::redeem_recovery_code(&tenant, &answer))
            .await
            .ok();
        SignedInWith::PasswordAndRecoveryCode
    }

    /// Holds `session` and sends its token from now on.
    fn hold(&mut self, session: &TenantSession) {
        self.secrets.push(session.refresh_token.clone());
        self.client.authorize(&session.refresh_token);
        self.session = Some(HeldSession {
            id: session.session_id.clone(),
        });
    }

    /// The session held.
    ///
    /// # Panics
    ///
    /// When there is none.
    fn held_session(&self) -> &HeldSession {
        let Some(session) = &self.session else {
            panic!("{} is not signed in", self.account.email);
        };
        session
    }

    /// Their password typed again, with `code`.
    fn password_proof(&self, code: Option<String>) -> Proof {
        Proof::Password {
            password: self.password.clone(),
            code,
        }
    }

    /// A fresh code from their phone, when they have it.
    async fn phone_code(&mut self) -> Option<String> {
        let phone = self.phone.as_mut()?;
        Some(phone.code().await)
    }

    /// Their passkey.
    ///
    /// # Panics
    ///
    /// When they have none.
    fn passkey_mut(&mut self) -> &mut SoftPasskey {
        let Some(passkey) = self.passkey.as_mut() else {
            panic!("{} has no passkey", self.account.email);
        };
        passkey
    }
}

/// The body that sends `answer` for the ceremony `ceremony_id`.
fn answer_body(ceremony_id: &str, answer: &PasskeyAnswer) -> PasskeyAnswerBody {
    PasskeyAnswerBody {
        ceremony_id: ceremony_id.to_owned(),
        response: answer.response.clone(),
        credential_id: answer.credential_id.clone(),
    }
}
