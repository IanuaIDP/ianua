//! Text messages: second-factor codes texted to the number a factor was set
//! up with, through the platform's own provider account.
//!
//! The provider is the platform's, named in configuration; the domain lets
//! no tenant choose one of its own. Every call is held to a few seconds and
//! goes to an address the platform chose. No code, number or credential is
//! ever logged or written into an error, and a provider's answer is never
//! read back into either.
//!
//! [`RoutedFactorCodeSender`] is the sender the sign-in holds: it hands a
//! mailed code to the mail sender and a texted one to the text sender, and
//! refuses a texted code when no provider is set up.

mod routed;
mod twilio;

pub use routed::{ConfiguredTextMessaging, RoutedFactorCodeSender};
pub use twilio::{
    TwilioAccount, TwilioEndpoint, TwilioFactorCodeSender, TwilioLogin, TwilioSender, TwilioSid,
};
