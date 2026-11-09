//! The platform's text message provider, for second-factor codes sent by
//! text: a Twilio account, or none, which refuses texted codes.

use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
use ianua_infra::sms::{TwilioAccount, TwilioEndpoint, TwilioLogin, TwilioSender, TwilioSid};

/// The setting naming where Twilio's API answers.
const API_URL: &str = "TWILIO_API_URL";

/// Every Twilio setting, for telling none set from some.
const TWILIO_SETTINGS: [&str; 9] = [
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "TWILIO_AUTH_TOKEN_FILE",
    "TWILIO_API_KEY_SID",
    "TWILIO_API_KEY_SECRET",
    "TWILIO_API_KEY_SECRET_FILE",
    "TWILIO_FROM",
    "TWILIO_MESSAGING_SERVICE_SID",
    API_URL,
];

/// The text message provider.
#[derive(Debug, Clone)]
pub(crate) struct SmsConfig {
    /// `TWILIO_ACCOUNT_SID`; `TWILIO_AUTH_TOKEN`, or `TWILIO_API_KEY_SID`
    /// with `TWILIO_API_KEY_SECRET`; and `TWILIO_FROM` or
    /// `TWILIO_MESSAGING_SERVICE_SID`. None set leaves texted codes
    /// refused.
    pub twilio: Option<TwilioAccount>,
    /// `TWILIO_API_URL` (`https://api.twilio.com/`): where Twilio's API
    /// answers, another address only for a stand-in of it; `https` in
    /// production.
    pub endpoint: TwilioEndpoint,
    /// `TEXT_SEND_TIMEOUT_SECONDS` (5): one text, never more than five
    /// seconds.
    pub send_timeout: Duration,
}

impl SmsConfig {
    /// The text provider `vars` sets up, in `environment`.
    ///
    /// # Errors
    ///
    /// Some Twilio settings set but not a whole account: no account, no
    /// way to sign in or two, no sender or two. And an API address that
    /// is no URL, or is not `https` in production.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        let mut any = false;
        for name in TWILIO_SETTINGS {
            any |= vars.optional(name)?.is_some();
        }
        Ok(Self {
            twilio: if any { Some(twilio(vars)?) } else { None },
            endpoint: endpoint(vars, environment)?,
            send_timeout: vars.seconds("TEXT_SEND_TIMEOUT_SECONDS", Duration::from_secs(5))?,
        })
    }
}

/// Twilio's public API, or the stand-in `TWILIO_API_URL` names. A plain
/// `http` address is refused in production: the call carries the
/// account's credentials and the code.
fn endpoint(vars: &Env, environment: Environment) -> Read<TwilioEndpoint> {
    let Some(url) = vars.url(API_URL)? else {
        return TwilioEndpoint::public().map_err(|cause| ConfigError::rejected(API_URL, cause));
    };
    if url.scheme() != "https" && environment.is_production() {
        return Err(ConfigError::contradicts(
            API_URL,
            "is not https in production, which sends the Twilio credentials and the codes unencrypted",
        ));
    }
    TwilioEndpoint::at(url.as_str()).map_err(|cause| ConfigError::rejected(API_URL, cause))
}

/// The whole Twilio account.
fn twilio(vars: &Env) -> Read<TwilioAccount> {
    Ok(TwilioAccount {
        account_sid: vars.required_parsed("TWILIO_ACCOUNT_SID", |sid| TwilioSid::account(&sid))?,
        login: login(vars)?,
        sender: sender(vars)?,
    })
}

/// The Auth Token, or an API key with its secret: exactly one.
fn login(vars: &Env) -> Read<TwilioLogin> {
    let token = vars.secret("TWILIO_AUTH_TOKEN")?;
    let key_sid = vars.parsed("TWILIO_API_KEY_SID", |sid| TwilioSid::api_key(&sid))?;
    let key_secret = vars.secret("TWILIO_API_KEY_SECRET")?;
    match (token, key_sid, key_secret) {
        (Some(token), None, None) => Ok(TwilioLogin::AuthToken(token)),
        (None, Some(key_sid), Some(secret)) => Ok(TwilioLogin::ApiKey { key_sid, secret }),
        (None, None, None) => Err(ConfigError::missing(
            "TWILIO_AUTH_TOKEN, or TWILIO_API_KEY_SID with TWILIO_API_KEY_SECRET,",
        )),
        (None, Some(_), None) => Err(ConfigError::contradicts(
            "TWILIO_API_KEY_SID",
            "is set without TWILIO_API_KEY_SECRET",
        )),
        (None, None, Some(_)) => Err(ConfigError::contradicts(
            "TWILIO_API_KEY_SECRET",
            "is set without TWILIO_API_KEY_SID",
        )),
        (Some(_), _, _) => Err(ConfigError::contradicts(
            "TWILIO_AUTH_TOKEN",
            "is set beside an API key; sign in one way",
        )),
    }
}

/// The number or the Messaging Service texts come from: exactly one.
fn sender(vars: &Env) -> Read<TwilioSender> {
    let number = vars.parsed("TWILIO_FROM", PhoneNumber::new)?;
    let service = vars.parsed("TWILIO_MESSAGING_SERVICE_SID", |sid| {
        TwilioSid::messaging_service(&sid)
    })?;
    match (number, service) {
        (Some(number), None) => Ok(TwilioSender::Number(number)),
        (None, Some(service)) => Ok(TwilioSender::MessagingService(service)),
        (None, None) => Err(ConfigError::missing(
            "TWILIO_FROM or TWILIO_MESSAGING_SERVICE_SID",
        )),
        (Some(_), Some(_)) => Err(ConfigError::contradicts(
            "TWILIO_FROM",
            "and TWILIO_MESSAGING_SERVICE_SID are both set; texts come from one",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "AC0123456789abcdef0123456789abcdef";
    /// A made-up API key SID, put together at run time so no key-shaped
    /// string sits in the source.
    fn key_sid() -> String {
        format!("SK{}", "0123456789abcdef".repeat(2))
    }
    const SERVICE: &str = "MG0123456789abcdef0123456789abcdef";

    /// The text provider `vars` sets up in production.
    fn read(vars: &Env) -> Read<SmsConfig> {
        SmsConfig::read(vars, Environment::Production)
    }

    /// A whole account with an Auth Token and a number, texting through
    /// the API at `url`.
    fn account_at(url: &str) -> Env {
        Env::of([
            ("TWILIO_ACCOUNT_SID", ACCOUNT),
            ("TWILIO_AUTH_TOKEN", "tw-token"),
            ("TWILIO_FROM", "+15005550006"),
            ("TWILIO_API_URL", url),
        ])
    }

    /// A stand-in of Twilio's API on a plain address is taken outside
    /// production, for a test platform texting a local receiver.
    #[test]
    fn a_plain_api_address_is_taken_outside_production() {
        let vars = account_at("http://127.0.0.1:8080/");

        let config = SmsConfig::read(&vars, Environment::Development);

        assert!(config.is_ok());
    }

    /// Production SMS configuration refuses an HTTP Twilio endpoint,
    /// naming its URL setting.
    #[test]
    fn a_plain_api_address_is_refused_in_production() {
        let vars = account_at("http://127.0.0.1:8080/");

        assert!(
            matches!(read(&vars), Err(ConfigError::Contradicts { name, .. }) if name == "TWILIO_API_URL")
        );
    }

    /// A Twilio endpoint without account settings is refused.
    #[test]
    fn an_api_address_without_an_account_is_refused() {
        let vars = Env::of([("TWILIO_API_URL", "https://twilio.internal/")]);

        assert!(read(&vars).is_err());
    }

    /// With no Twilio setting, texted codes stay refused.
    #[test]
    fn with_no_twilio_setting_there_is_no_provider() {
        let config = read(&Env::of([])).unwrap();

        assert!(config.twilio.is_none());
    }

    /// A whole account with an Auth Token and a number is read, the token
    /// never printed.
    #[test]
    fn a_whole_account_is_read_and_never_prints_its_token() {
        let vars = Env::of([
            ("TWILIO_ACCOUNT_SID", ACCOUNT),
            ("TWILIO_AUTH_TOKEN", "tw-token"),
            ("TWILIO_FROM", "+15005550006"),
        ]);

        let config = read(&vars).unwrap();

        assert!(config.twilio.is_some());
        assert!(!format!("{config:?}").contains("tw-token"));
    }

    /// An API key and a Messaging Service are taken in place of the token
    /// and the number.
    #[test]
    fn an_api_key_and_a_messaging_service_are_taken() {
        let key = key_sid();
        let vars = Env::of([
            ("TWILIO_ACCOUNT_SID", ACCOUNT),
            ("TWILIO_API_KEY_SID", key.as_str()),
            ("TWILIO_API_KEY_SECRET", "key-secret"),
            ("TWILIO_MESSAGING_SERVICE_SID", SERVICE),
        ]);

        let account = read(&vars).unwrap().twilio.unwrap();

        assert!(matches!(account.login, TwilioLogin::ApiKey { .. }));
        assert!(matches!(account.sender, TwilioSender::MessagingService(_)));
    }

    /// Twilio configuration refuses a missing sender, login or account SID.
    #[test]
    fn a_partial_twilio_set_is_refused() {
        let no_sender = Env::of([
            ("TWILIO_ACCOUNT_SID", ACCOUNT),
            ("TWILIO_AUTH_TOKEN", "tw-token"),
        ]);
        let no_login = Env::of([
            ("TWILIO_ACCOUNT_SID", ACCOUNT),
            ("TWILIO_FROM", "+15005550006"),
        ]);
        let no_account = Env::of([
            ("TWILIO_AUTH_TOKEN", "tw-token"),
            ("TWILIO_FROM", "+15005550006"),
        ]);

        assert!(read(&no_sender).is_err());
        assert!(read(&no_login).is_err());
        assert!(read(&no_account).is_err());
    }

    /// Providing both a Twilio Auth Token and API key is refused as
    /// contradictory configuration.
    #[test]
    fn two_ways_to_sign_in_are_refused() {
        let key = key_sid();
        let vars = Env::of([
            ("TWILIO_ACCOUNT_SID", ACCOUNT),
            ("TWILIO_AUTH_TOKEN", "tw-token"),
            ("TWILIO_API_KEY_SID", key.as_str()),
            ("TWILIO_API_KEY_SECRET", "key-secret"),
            ("TWILIO_FROM", "+15005550006"),
        ]);

        assert!(matches!(read(&vars), Err(ConfigError::Contradicts { .. })));
    }

    /// A SID of the wrong kind is refused, naming the setting.
    #[test]
    fn a_sid_of_the_wrong_kind_is_refused() {
        let key = key_sid();
        let vars = Env::of([
            ("TWILIO_ACCOUNT_SID", key.as_str()),
            ("TWILIO_AUTH_TOKEN", "tw-token"),
            ("TWILIO_FROM", "+15005550006"),
        ]);

        assert!(
            matches!(read(&vars), Err(ConfigError::Rejected { name, .. }) if name == "TWILIO_ACCOUNT_SID")
        );
    }
}
