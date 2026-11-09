//! Customers' own cloud accounts: the platform's AWS keys that assume
//! their roles, and the link that opens their console with the onboarding
//! template.

use std::fmt;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_domain::shared::security::secret::Secret;

/// The platform's own AWS keys. `Debug` shows only the key's id.
#[derive(Clone)]
pub(crate) struct AwsKeys {
    /// `CLOUD_AWS_ACCESS_KEY_ID`.
    pub access_key_id: String,
    /// `CLOUD_AWS_SECRET_ACCESS_KEY` or `_FILE`.
    pub secret_access_key: Secret,
    /// `CLOUD_AWS_SESSION_TOKEN` or `_FILE`, when the keys are temporary.
    pub session_token: Option<Secret>,
}

impl fmt::Debug for AwsKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsKeys")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// Customers' own cloud accounts.
#[derive(Debug, Clone)]
pub(crate) struct CloudConfig {
    /// The platform's AWS keys; none leaves customers' AWS accounts
    /// unreachable, every other cloud working with the customer's own
    /// credential alone.
    pub aws: Option<AwsKeys>,
    /// `CLOUD_CONSOLE_TEMPLATE`: a link opening a customer's console with
    /// the onboarding template loaded, `{external_id}` filled in; none
    /// offers written steps only.
    pub console_template: Option<String>,
}

impl CloudConfig {
    /// The cloud settings `vars` holds.
    ///
    /// # Errors
    ///
    /// Half the AWS keys, a session token without them, or a console
    /// template with no `{external_id}`.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        let console_template = vars.optional("CLOUD_CONSOLE_TEMPLATE")?;
        if console_template
            .as_deref()
            .is_some_and(|template| !template.contains("{external_id}"))
        {
            return Err(ConfigError::invalid(
                "CLOUD_CONSOLE_TEMPLATE",
                "must hold {external_id}, where the customer's external id goes",
            ));
        }
        Ok(Self {
            aws: aws(vars)?,
            console_template,
        })
    }
}

/// The platform's AWS keys: the id with its secret, or neither.
fn aws(vars: &Env) -> Read<Option<AwsKeys>> {
    let id = vars.optional("CLOUD_AWS_ACCESS_KEY_ID")?;
    let secret = vars.secret("CLOUD_AWS_SECRET_ACCESS_KEY")?;
    let session_token = vars.secret("CLOUD_AWS_SESSION_TOKEN")?;
    match (id, secret) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(Some(AwsKeys {
            access_key_id,
            secret_access_key,
            session_token,
        })),
        (None, None) if session_token.is_some() => Err(ConfigError::contradicts(
            "CLOUD_AWS_SESSION_TOKEN",
            "is set without CLOUD_AWS_ACCESS_KEY_ID",
        )),
        (None, None) => Ok(None),
        (Some(_), None) => Err(ConfigError::missing("CLOUD_AWS_SECRET_ACCESS_KEY")),
        (None, Some(_)) => Err(ConfigError::missing("CLOUD_AWS_ACCESS_KEY_ID")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With nothing set, no AWS keys are held and no console link is
    /// offered.
    #[test]
    fn with_nothing_set_no_keys_are_held() {
        let config = CloudConfig::read(&Env::of([])).unwrap();

        assert!(config.aws.is_none());
        assert!(config.console_template.is_none());
    }

    /// AWS credentials containing only the access key ID or only the
    /// secret are refused.
    #[test]
    fn half_the_aws_keys_are_refused() {
        assert!(
            CloudConfig::read(&Env::of([(
                "CLOUD_AWS_ACCESS_KEY_ID",
                "AKIAIOSFODNN7EXAMPLE"
            )]))
            .is_err()
        );
        assert!(CloudConfig::read(&Env::of([("CLOUD_AWS_SECRET_ACCESS_KEY", "s3cret")])).is_err());
    }

    /// Cloud configuration debug output omits the AWS secret.
    #[test]
    fn the_aws_secret_never_prints() {
        let vars = Env::of([
            ("CLOUD_AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            ("CLOUD_AWS_SECRET_ACCESS_KEY", "s3cret-aws"),
        ]);

        let config = CloudConfig::read(&vars).unwrap();

        assert!(!format!("{config:?}").contains("s3cret-aws"));
    }

    /// A console template with nowhere to put the external id is refused.
    #[test]
    fn a_console_template_without_the_external_id_is_refused() {
        let read = CloudConfig::read(&Env::of([(
            "CLOUD_CONSOLE_TEMPLATE",
            "https://console.aws.amazon.com/",
        )]));

        assert!(read.is_err());
    }
}
