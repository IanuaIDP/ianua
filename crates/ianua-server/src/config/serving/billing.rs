//! The payment provider organizations are billed through: a Stripe
//! account, or none, which refuses every checkout and every notice.

use std::fmt;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::HttpsUrl;

/// Every Stripe setting, for telling none set from some.
const STRIPE_SETTINGS: [&str; 8] = [
    "STRIPE_SECRET_KEY",
    "STRIPE_SECRET_KEY_FILE",
    "STRIPE_WEBHOOK_SECRET",
    "STRIPE_WEBHOOK_SECRET_FILE",
    "STRIPE_CURRENCY",
    "STRIPE_SUCCESS_URL",
    "STRIPE_CANCEL_URL",
    "STRIPE_TIMEOUT_SECONDS",
];

/// The platform's Stripe account. `Debug` shows no secret.
#[derive(Clone)]
pub(crate) struct StripeConfig {
    /// `STRIPE_SECRET_KEY` or `STRIPE_SECRET_KEY_FILE`: the account's
    /// secret API key.
    pub api_key: Secret,
    /// `STRIPE_WEBHOOK_SECRET` or `STRIPE_WEBHOOK_SECRET_FILE`: the signing
    /// secret of the endpoint Stripe posts events to.
    pub webhook_secret: Secret,
    /// `STRIPE_CURRENCY` (`eur`): the currency organizations are charged
    /// in, three lower case letters.
    pub currency: String,
    /// `STRIPE_SUCCESS_URL`: where a member lands after saving a payment
    /// method; `APP_BASE_URL` by default.
    pub success_url: HttpsUrl,
    /// `STRIPE_CANCEL_URL`: where a member lands after leaving the
    /// checkout; `APP_BASE_URL` by default.
    pub cancel_url: HttpsUrl,
    /// `STRIPE_TIMEOUT_SECONDS` (10): one call to Stripe.
    pub timeout: Duration,
}

impl fmt::Debug for StripeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StripeConfig")
            .field("currency", &self.currency)
            .field("success_url", &self.success_url.as_str())
            .field("cancel_url", &self.cancel_url.as_str())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// The payment provider.
#[derive(Debug, Clone)]
pub(crate) struct BillingConfig {
    /// The Stripe account; none set leaves billing off, every checkout and
    /// every notice refused.
    pub stripe: Option<StripeConfig>,
}

impl BillingConfig {
    /// The payment provider `vars` sets up, members sent back to
    /// `app_base_url` unless a setting says otherwise.
    ///
    /// # Errors
    ///
    /// Some Stripe settings set but not the key and the signing secret, a
    /// currency that is not three lower case letters, or a return address
    /// that is no `https` URL.
    pub(crate) fn read(vars: &Env, app_base_url: &HttpsUrl) -> Read<Self> {
        let mut any = false;
        for name in STRIPE_SETTINGS {
            any |= vars.optional(name)?.is_some();
        }
        if !any {
            return Ok(Self { stripe: None });
        }
        Ok(Self {
            stripe: Some(stripe(vars, app_base_url)?),
        })
    }
}

/// The whole Stripe account.
fn stripe(vars: &Env, app_base_url: &HttpsUrl) -> Read<StripeConfig> {
    Ok(StripeConfig {
        api_key: vars.required_secret("STRIPE_SECRET_KEY")?,
        webhook_secret: vars.required_secret("STRIPE_WEBHOOK_SECRET")?,
        currency: currency(vars)?,
        success_url: return_url(vars, "STRIPE_SUCCESS_URL", app_base_url)?,
        cancel_url: return_url(vars, "STRIPE_CANCEL_URL", app_base_url)?,
        timeout: vars.seconds("STRIPE_TIMEOUT_SECONDS", Duration::from_secs(10))?,
    })
}

/// `STRIPE_CURRENCY`, three lower case letters as Stripe writes them.
fn currency(vars: &Env) -> Read<String> {
    let name = "STRIPE_CURRENCY";
    let currency = vars.text(name, "eur")?;
    let well_formed = currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_lowercase());
    if !well_formed {
        return Err(ConfigError::invalid(
            name,
            format!("must be three lower case letters, such as eur, got {currency:?}"),
        ));
    }
    Ok(currency)
}

/// The address `name` holds, or `app_base_url`.
fn return_url(vars: &Env, name: &str, app_base_url: &HttpsUrl) -> Read<HttpsUrl> {
    Ok(vars
        .parsed(name, HttpsUrl::new)?
        .unwrap_or_else(|| app_base_url.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> HttpsUrl {
        HttpsUrl::new("https://app.example.com").unwrap()
    }

    /// No Stripe setting leaves billing off.
    #[test]
    fn no_stripe_setting_leaves_billing_off() {
        let config = BillingConfig::read(&Env::of([]), &base()).unwrap();

        assert!(config.stripe.is_none());
    }

    /// A Stripe API key without a webhook signing secret is refused,
    /// naming the missing secret setting.
    #[test]
    fn a_key_without_the_signing_secret_is_refused() {
        let vars = Env::of([("STRIPE_SECRET_KEY", "sk_test_1")]);

        let read = BillingConfig::read(&vars, &base());

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("STRIPE_WEBHOOK_SECRET"))
        );
    }

    /// A whole account reads, members sent back to the dashboard.
    #[test]
    fn a_whole_account_reads_with_the_dashboard_as_its_return() {
        let vars = Env::of([
            ("STRIPE_SECRET_KEY", "sk_test_1"),
            ("STRIPE_WEBHOOK_SECRET", "whsec_1"),
        ]);

        let stripe = BillingConfig::read(&vars, &base()).unwrap().stripe.unwrap();

        assert_eq!(stripe.currency, "eur");
        assert_eq!(stripe.success_url, base());
    }

    /// A four-letter uppercase currency is refused as an invalid currency
    /// setting.
    #[test]
    fn a_currency_that_is_not_three_letters_is_refused() {
        let vars = Env::of([
            ("STRIPE_SECRET_KEY", "sk_test_1"),
            ("STRIPE_WEBHOOK_SECRET", "whsec_1"),
            ("STRIPE_CURRENCY", "EURO"),
        ]);

        let read = BillingConfig::read(&vars, &base());

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "STRIPE_CURRENCY")
        );
    }
}
