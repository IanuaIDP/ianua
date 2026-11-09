//! A member of an organization at the dashboard: the owner who founded it,
//! a tenant administrator, a member without rights, or a stranger from
//! another organization. Each signs in with their password through the
//! real sign-in, landing in the tenant they work in, and confirms a new
//! device from their mailbox when asked.

use std::fmt;

use serde::de::DeserializeOwned;

use super::mailed::mail_linking;
use crate::api::{OrgPath, Request, sessions};
use crate::mail::Mailbox;
use crate::net::Client;
use crate::stack::Stack;
use crate::wire::organization::OrgRole;
use crate::wire::sign_in::{ConfirmSignIn, Owed, PasswordSignIn, Session, SignOut, SignedIn};
use crate::wire::{Answer, Exchange};

/// Who a member is: their account and where it lives.
#[derive(Debug, Clone)]
pub struct MemberAccount {
    /// Their account's id.
    pub id: String,
    /// Their address.
    pub email: String,
    /// Human-readable label shown to colleagues in the organization.
    pub display_name: String,
    /// Their organization.
    pub org: OrgPath,
    /// Organization authority exercised by this actor's requests.
    pub role: OrgRole,
    /// The tenant their sessions land in, by slug; none for a session on
    /// the organization alone. A member acts in a tenant only from a
    /// session opened there.
    pub landing: Option<String>,
}

/// An organization member with their own client and password. `Debug`
/// shows no password or token.
pub struct Member {
    client: Client,
    account: MemberAccount,
    password: String,
    session: Option<SessionHeld>,
    tokens: Vec<String>,
    exchanges: Vec<Exchange>,
}

/// The session a member holds: its id and its token.
#[derive(Clone)]
struct SessionHeld {
    id: String,
    token: String,
}

impl fmt::Debug for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Member")
            .field("account", &self.account)
            .field("signed_in", &self.session.is_some())
            .finish_non_exhaustive()
    }
}

impl Member {
    /// `account` with `password`, acting through `client`, not yet signed
    /// in.
    #[must_use]
    pub fn new(client: Client, account: MemberAccount, password: &str) -> Self {
        Self {
            client,
            account,
            password: password.to_owned(),
            session: None,
            tokens: Vec::new(),
            exchanges: Vec::new(),
        }
    }

    /// The client they act through.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Who they are.
    #[must_use]
    pub fn account(&self) -> &MemberAccount {
        &self.account
    }

    /// Their account's id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.account.id
    }

    /// Their address.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.account.email
    }

    /// Account secret supplied by scenarios that prove the member's identity again.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Their organization.
    #[must_use]
    pub fn org(&self) -> &OrgPath {
        &self.account.org
    }

    /// Their sessions land in `tenant_slug` from the next sign-in on.
    pub fn land_in(&mut self, tenant_slug: &str) {
        self.account.landing = Some(tenant_slug.to_owned());
    }

    /// The session they hold now.
    ///
    /// # Panics
    ///
    /// When they are not signed in.
    #[must_use]
    pub fn session_id(&self) -> &str {
        let Some(session) = &self.session else {
            panic!("{} is not signed in", self.account.email);
        };
        &session.id
    }

    /// Sends `request` as them and keeps the exchange.
    pub async fn send<T: DeserializeOwned>(&mut self, request: Request<T>) -> Answer<T> {
        let answer = request.send(&self.client).await;
        self.exchanges.push(answer.exchange().clone());
        answer
    }

    /// Signs in with their password, landing in their tenant, confirming
    /// from their mailbox when the platform asks, and sends the session's
    /// token from then on.
    ///
    /// # Panics
    ///
    /// When the sign-in is refused, owes a second factor they never set
    /// up, or offers a choice of organizations.
    pub async fn sign_in(&mut self, stack: &Stack) {
        self.client.forget_authorization();
        let session = self.signed_in_on(None, stack.mailbox()).await;
        self.client.authorize(&session.token);
        self.session = Some(session);
    }

    /// A client of their own on another device, signed in and then signed
    /// out again: it still sends the token of a session that ended.
    ///
    /// # Panics
    ///
    /// When the sign-in or the sign-out is refused.
    pub async fn signed_out(&mut self, stack: &Stack) -> Client {
        let mut device = self.another_device(stack, "signed out");
        let session = self.signed_in_on(Some(&device), stack.mailbox()).await;
        device.authorize(&session.token);
        let sign_out = SignOut {
            session_id: session.id.clone(),
        };
        let answer = sessions::member_sign_out(&self.account.org, &sign_out)
            .send(&device)
            .await;
        self.exchanges.push(answer.exchange().clone());
        answer.ok();
        device
    }

    /// A client of their own on another device whose session `steward`
    /// ended for them.
    ///
    /// # Panics
    ///
    /// When the sign-in or the ending is refused.
    pub async fn revoked_by(&mut self, steward: &Member, stack: &Stack) -> Client {
        let mut device = self.another_device(stack, "session revoked");
        let session = self.signed_in_on(Some(&device), stack.mailbox()).await;
        device.authorize(&session.token);
        let answer = sessions::end_member_session(&self.account.org, &session.id)
            .send(steward.client())
            .await;
        self.exchanges.push(answer.exchange().clone());
        answer.ok();
        device
    }

    /// The secrets they hold, to make sure none appears where it should
    /// not: their password and every session token they were given.
    #[must_use]
    pub fn secrets(&self) -> Vec<String> {
        let mut secrets = vec![self.password.clone()];
        secrets.extend(self.tokens.iter().cloned());
        secrets
    }

    /// Every exchange they made since this was last asked.
    pub fn take_exchanges(&mut self) -> Vec<Exchange> {
        std::mem::take(&mut self.exchanges)
    }

    /// A fresh client for them, named for `why`.
    ///
    /// # Panics
    ///
    /// When the client cannot be built.
    /// A second-device scenario cannot proceed without its independent client.
    #[allow(clippy::expect_used)]
    fn another_device(&self, stack: &Stack, why: &str) -> Client {
        let actor = format!("{}, {why}", self.client.actor());
        Client::new(stack, &actor).expect("a client for another device")
    }

    /// The session their password opens through `device`, or their own
    /// client when none is named, confirmed from `mailbox` when asked.
    ///
    /// # Panics
    ///
    /// When the sign-in is refused, owes a second factor, or offers a
    /// choice.
    async fn signed_in_on(&mut self, device: Option<&Client>, mailbox: &Mailbox) -> SessionHeld {
        let client = device.unwrap_or(&self.client);
        let sign_in = PasswordSignIn {
            organization: Some(self.account.org.slug().to_owned()),
            tenant_slug: self.account.landing.clone(),
            ..PasswordSignIn::of(&self.account.email, &self.password)
        };
        let answer = sessions::member_sign_in(&sign_in).send(client).await;
        let mut exchanges = vec![answer.exchange().clone()];
        let SignedIn::Authenticated(session) = answer.ok() else {
            panic!(
                "{} named their organization, so no choice is offered",
                self.account.email
            );
        };
        let (held, confirmation) = settle_session(client, mailbox, &self.account, &session).await;
        exchanges.extend(confirmation);
        self.exchanges.extend(exchanges);
        self.tokens.push(held.token.clone());
        held
    }
}

/// Settles the password session, preserving any mailed-confirmation exchange.
async fn settle_session(
    client: &Client,
    mailbox: &Mailbox,
    account: &MemberAccount,
    session: &Session,
) -> (SessionHeld, Option<Exchange>) {
    match session.owed() {
        Owed::Nothing => (held(session), None),
        Owed::MailedConfirmation => {
            let (held, exchange) = confirmed(client, mailbox, account, session).await;
            (held, Some(exchange))
        }
        Owed::FactorEnrolment | Owed::FactorCode => panic!(
            "{} set up no second factor, yet their sign-in owes {:?}",
            account.email,
            session.owed()
        ),
    }
}

/// `session`, confirmed with the link mailed to `account`, and the
/// exchange that confirmed it.
async fn confirmed(
    client: &Client,
    mailbox: &Mailbox,
    account: &MemberAccount,
    session: &Session,
) -> (SessionHeld, Exchange) {
    let mail = mail_linking(mailbox, &account.email, "/confirm-sign-in").await;
    let confirm = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: session.refresh_token.clone(),
    };
    let answer = sessions::confirm_member_sign_in(&confirm)
        .send(client)
        .await;
    let exchange = answer.exchange().clone();
    let confirmed = answer.ok();
    assert_eq!(
        confirmed.session_id, session.session_id,
        "the mailed link confirms the sign-in it was sent for"
    );
    (held(session), exchange)
}

/// The id and token of `session`.
fn held(session: &Session) -> SessionHeld {
    SessionHeld {
        id: session.session_id.clone(),
        token: session.refresh_token.clone(),
    }
}
