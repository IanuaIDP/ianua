//! The platform's texts, received by a stand-in of Twilio's messages API
//! and read per number: the code in each.
//!
//! The platform texts through its real Twilio adapter, pointed at
//! [`Texts`] by `TWILIO_API_URL`. The stand-in answers the one call the
//! adapter makes, `POST /2010-04-01/Accounts/{AccountSid}/Messages.json`,
//! form encoded, signed in with HTTP Basic authentication, as Twilio
//! does: a created message is `Status::CREATED`, a call with the wrong account or
//! credentials `Status::UNAUTHORIZED`, a call missing its fields `Status::BAD_REQUEST`.

mod twilio;

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use ianua_boot::shutdown::Shutdown;
use tokio::net::TcpListener;

use crate::inbox::Inbox;
use crate::mail::code_in;
use crate::stack::secrets;

/// How long [`Texts::next_for`] waits for a text to come.
const TEXT_WAIT: Duration = Duration::from_secs(30);

/// The number the platform's texts come from, one Twilio keeps for tests.
const SENDER: &str = "+15005550006";

/// The Twilio account the stand-in takes calls for. `Debug` shows no
/// token.
#[derive(Clone)]
pub struct TwilioAccount {
    sid: String,
    auth_token: String,
}

impl fmt::Debug for TwilioAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TwilioAccount")
            .field("sid", &self.sid)
            .finish_non_exhaustive()
    }
}

impl TwilioAccount {
    /// An account of its own: an Account SID and an Auth Token made at
    /// random.
    fn made() -> Self {
        Self {
            sid: format!("AC{}", secrets::hex(16)),
            auth_token: secrets::hex(16),
        }
    }

    /// The Account SID, for `TWILIO_ACCOUNT_SID`.
    #[must_use]
    pub fn sid(&self) -> &str {
        &self.sid
    }

    /// The Auth Token, for `TWILIO_AUTH_TOKEN`.
    #[must_use]
    pub fn auth_token(&self) -> &str {
        &self.auth_token
    }

    /// The number texts come from, for `TWILIO_FROM`.
    #[must_use]
    pub fn sender(&self) -> &str {
        SENDER
    }
}

/// The stand-in of Twilio's messages API, holding every text it took.
pub struct Texts {
    address: SocketAddr,
    account: TwilioAccount,
    inbox: Inbox<Text>,
}

impl fmt::Debug for Texts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Texts")
            .field("address", &self.address)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl Texts {
    /// A stand-in listening on a port of loopback for an account of its
    /// own, until `shutdown` stops it.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub async fn open(shutdown: &Shutdown) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let account = TwilioAccount::made();
        let inbox = Inbox::open();
        twilio::serve(
            listener,
            twilio::Desk::new(&account, inbox.clone()),
            shutdown,
        );
        Ok(Self {
            address,
            account,
            inbox,
        })
    }

    /// The API's address, for `TWILIO_API_URL`.
    #[must_use]
    pub fn api_url(&self) -> String {
        format!("http://{}/", self.address)
    }

    /// The account the stand-in takes calls for.
    #[must_use]
    pub fn account(&self) -> &TwilioAccount {
        &self.account
    }

    /// The next text to `number`, waiting up to thirty seconds for one.
    ///
    /// # Panics
    ///
    /// When no text to `number` comes in that time, naming the number.
    pub async fn next_for(&self, number: &str) -> Text {
        let next = self.inbox.next_for(number, TEXT_WAIT).await;
        let Some(text) = next else {
            panic!("no text reached {number} within {TEXT_WAIT:?}");
        };
        text
    }
}

/// One text as the stand-in took it.
#[derive(Clone)]
pub struct Text {
    to: String,
    sender: String,
    body: String,
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Text")
            .field("to", &self.to)
            .field("sender", &self.sender)
            .finish_non_exhaustive()
    }
}

impl Text {
    /// The number it went to.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    /// The number or Messaging Service it came from.
    #[must_use]
    pub fn sender(&self) -> &str {
        &self.sender
    }

    /// Its words.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// The code it carries: the first word of six to eight digits.
    ///
    /// # Panics
    ///
    /// When it carries none.
    #[must_use]
    pub fn code(&self) -> String {
        let Some(code) = code_in(&self.body) else {
            panic!("the text to {} carries no code", self.to);
        };
        code
    }
}
