//! How a customer grants us access to their cloud account.
//!
//! No type here that carries a secret derives [`std::fmt::Debug`]. The
//! derived form would print the secret, and a credential that reaches a log
//! or a span attribute has to be rotated. Each implements `Debug` by hand and
//! redacts. The identifiers beside them, [`RoleArn`] and [`CloudIdentifier`],
//! are not secret and print as they are.

use crate::domains::tenant::provisioning::infrastructure::CloudProvider;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::security::ssrf::is_never_public;
use crate::shared::validation::rules::url::UrlHost;
use crate::shared::validation::{Charset, Rule, TextValue, ValidationError, Validator, text_value};
use crate::types::{CertificatePem, HttpsUrl};

/// Bounds on the free-form parts of a credential.
///
/// These are not security limits, because the cloud decides what it accepts.
/// They stop a huge pasted value from reaching a CLI argument.
const MAX_CREDENTIAL_FIELD: usize = 4096;

text_value! {
    redacted
    /// The shared secret proving an `AssumeRole` call is one we were asked for.
    ///
    /// We generate one per organization, and the customer puts it in their
    /// role's trust policy. Without it, Mallory learns Acme's role ARN, names
    /// it in *her* settings, and has us assume Acme's role for her. That is
    /// the confused-deputy attack, and it is easy, because a role ARN is not
    /// a secret.
    ///
    /// Wiped on drop. It is half of what makes an `AssumeRole` succeed, so it
    /// is treated as secret even though it grants nothing alone.
    #[derive(zeroize::ZeroizeOnDrop)]
    pub struct ExternalId;
}

impl TextValue for ExternalId {
    const FIELD: &'static str = "external_id";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            Self::MIN_LEN..=Self::MAX_LEN,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE,
        )
    }
}

impl ExternalId {
    /// Minimum length that keeps the value unguessable.
    const MIN_LEN: usize = 24;
    /// AWS allows external ids up to 1224 characters. We stay well inside that.
    const MAX_LEN: usize = 128;
}

text_value! {
    /// An IAM role ARN in the customer's AWS account.
    ///
    /// Not a secret on its own, which is why [`ExternalId`] exists. It is
    /// still checked, so a malformed value fails here and not as an unclear
    /// CLI error three steps into provisioning.
    pub struct RoleArn;
}

impl TextValue for RoleArn {
    const FIELD: &'static str = "role_arn";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=2048).rule(&AwsRoleArn)
    }
}

impl RoleArn {
    /// The twelve-digit AWS account id this role lives in.
    ///
    /// Shown back to the customer so they can confirm we connected to the
    /// account they meant.
    #[must_use]
    pub fn account_id(&self) -> &str {
        self.0.split(':').nth(4).unwrap_or_default()
    }
}

/// An opaque secret handed to us by a cloud provider or its customer.
///
/// One type for every provider's secret, such as an Azure client secret, a
/// DigitalOcean token or a Kubernetes token. They differ only in format. The
/// domain holds each one, never shows it, and hands it to exactly one adapter.
///
/// Wiped on drop. Unlike the sealed form in the database, this is the
/// *plaintext*, and it stays in memory for any request that touches a cloud.
/// Without the wipe it would stay in freed heap until the page was reused.
/// That is long enough to reach a core dump or a swapped page.
#[derive(Clone, Eq, zeroize::ZeroizeOnDrop)]
pub struct CloudSecret(String);

impl PartialEq for CloudSecret {
    fn eq(&self, other: &Self) -> bool {
        crate::shared::security::constant_time::same_secret(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl TextValue for CloudSecret {
    const FIELD: &'static str = "secret";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_empty().max_bytes(MAX_CREDENTIAL_FIELD)
    }
}

impl CloudSecret {
    /// Wraps a provider secret.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if empty or longer than 4096 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        Self::checked(value.into()).map(Self)
    }

    /// Exposes the secret. Every call site is a place to check for leaks.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for CloudSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CloudSecret(<redacted>)")
    }
}

text_value! {
    /// A non-secret identifier naming something inside a customer's cloud.
    ///
    /// Azure needs a directory id and a client id next to its secret. Both are
    /// public. Kept apart from [`CloudSecret`] so the compiler stops a secret
    /// from being stored where an identifier was meant.
    pub struct CloudIdentifier;
}

impl TextValue for CloudIdentifier {
    const FIELD: &'static str = "identifier";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=MAX_CREDENTIAL_FIELD)
    }
}

/// A customer's grant of access to their cloud account.
///
/// An enum, not opaque bytes plus a provider tag, so an AWS connection
/// cannot hold an Azure service principal. [`Self::provider`] comes from the
/// variant, so the two can never disagree.
#[derive(Clone, PartialEq, Eq)]
pub enum CloudCredential {
    /// A role in the customer's account that trusts ours, assumed under an
    /// external id.
    ///
    /// Preferred over access keys wherever a cloud offers it. There is no
    /// long-lived secret for us to lose, and the customer revokes it by
    /// deleting the role.
    AwsAssumeRole {
        /// The role we assume.
        role_arn: RoleArn,
        /// The shared secret in its trust policy.
        external_id: ExternalId,
    },

    /// A GCP service account key, as downloaded from their console.
    GcpServiceAccount {
        /// The service account's email address.
        client_email: CloudIdentifier,
        /// The key file, checked to be a service-account key for that
        /// address that signs in at Google's own token endpoint.
        key: GcpServiceAccountKey,
    },

    /// Authenticates an application in the customer's Entra directory with a client secret.
    AzureServicePrincipal {
        /// The Entra directory, which Azure calls a tenant, the principal
        /// lives in.
        directory_id: CloudIdentifier,
        /// The application id.
        client_id: CloudIdentifier,
        /// The client secret.
        secret: CloudSecret,
    },

    /// A DigitalOcean personal access token.
    DigitalOceanToken {
        /// The bearer credential authorizing calls to the customer's cloud account.
        token: CloudSecret,
    },

    /// A service account in the customer's own Kubernetes cluster.
    ///
    /// By far the smallest grant of the five. The others let us create
    /// databases anywhere in an account. This one is limited to one namespace
    /// by a role the customer writes, and they revoke it by deleting the
    /// service account. For a customer who already runs Kubernetes it is less
    /// to give away and less to explain.
    ///
    /// Three fields, not a kubeconfig, because a kubeconfig can carry an exec
    /// plugin. That is a command we would run for them, against a binary we
    /// do not have, with arguments we did not choose. A server, a CA and a
    /// token are all we need, and none of them runs anything.
    KubernetesServiceAccount {
        /// The API server, as `https://host:port`.
        server: KubernetesApiServer,
        /// The cluster's CA certificate, PEM-encoded.
        ///
        /// Not a secret, and not optional. Without it, the only way to reach a
        /// cluster with a private CA is to stop verifying the server. That
        /// would hand every token we hold to whoever answers that address.
        ca_certificate: CertificatePem,
        /// The service account's bearer token.
        token: CloudSecret,
    },
}

impl CloudCredential {
    /// The cloud this credential opens.
    ///
    /// Taken from the variant, not stored beside it, so a connection cannot
    /// claim one provider and carry another's secret.
    #[must_use]
    pub fn provider(&self) -> CloudProvider {
        match self {
            Self::AwsAssumeRole { .. } => CloudProvider::Aws,
            Self::GcpServiceAccount { .. } => CloudProvider::Gcp,
            Self::AzureServicePrincipal { .. } => CloudProvider::Azure,
            Self::DigitalOceanToken { .. } => CloudProvider::DigitalOcean,
            Self::KubernetesServiceAccount { .. } => CloudProvider::Kubernetes,
        }
    }

    /// Whether the customer can revoke this without our help.
    ///
    /// True for grants they can withdraw at their end, such as by deleting a
    /// role or a service account. False for a DigitalOcean token, which stays
    /// valid until *we* delete our copy. The customer is told, because the
    /// two promise very different things about offboarding.
    #[must_use]
    pub fn is_revocable_by_customer(&self) -> bool {
        matches!(
            self,
            Self::AwsAssumeRole { .. }
                | Self::GcpServiceAccount { .. }
                | Self::AzureServicePrincipal { .. }
                | Self::KubernetesServiceAccount { .. }
        )
    }
}

impl std::fmt::Debug for CloudCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CloudCredential::{:?}(<redacted>)", self.provider())
    }
}

/// A Kubernetes API server we will send a service-account token to.
///
/// An `https://` URL that passes the shared rules. It has no credentials in
/// it and no private, loopback or link-local address as its host. It also
/// has no query or fragment, and no host name that can only be internal.
/// Such a name is a single label like `localhost` or `redis`, or one under
/// `.internal`, `.local`, `.localhost`, `.svc` or `.cluster.local`.
///
/// The worker connects to it holding the customer's token. An address in our
/// own network or a cloud metadata service would hand the token, and the
/// worker's reach, to whoever chose it.
///
/// A public-looking name can still resolve to an internal address, and the
/// name cannot show that. The adapter that connects must resolve it through
/// the screened resolver, refuse a blocked address, and connect to the
/// address it screened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesApiServer(HttpsUrl);

impl KubernetesApiServer {
    /// The API server at `url`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if `url` is not an acceptable HTTPS URL.
    /// - [`ValidationError`] if it carries a query or a fragment.
    /// - [`ValidationError`] if it names a host that can never be public.
    pub fn new(url: impl Into<String>) -> Result<Self, ValidationError> {
        let url = HttpsUrl::new(url)?;
        if url.has_query_or_fragment() {
            return Err(ValidationError::Rule {
                message: message!(
                    "organization-a-kubernetes-api-server-is-written",
                    "a Kubernetes API server is written as https://host:port, \
                          with no query or fragment"
                ),
            });
        }
        if let UrlHost::Name(name) = url.host()
            && is_never_public(name)
        {
            return Err(ValidationError::Rule {
                message: message!(
                    "organization-a-kubernetes-api-server-must-have",
                    "a Kubernetes API server must have a public host name"
                ),
            });
        }
        Ok(Self(url))
    }

    /// The URL, as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// What a GCP key file says about itself, as the adapter that parsed it read
/// it. The domain holds no JSON parser. It decides on what was read.
pub struct GcpKeyFacts<'a> {
    /// The file's `type`.
    pub key_type: &'a str,
    /// The file's `client_email`.
    pub client_email: &'a str,
    /// The file's `token_uri`, where the CLI exchanges the key for tokens.
    pub token_uri: &'a str,
    /// The file's `universe_domain`, if it names one. The CLI moves every API
    /// endpoint it calls onto this domain.
    pub universe_domain: Option<&'a str>,
}

/// The parts of a GCP key file that are the key itself, as the adapter that
/// parsed the file read them.
pub struct GcpKeyParts {
    /// The project the service account belongs to.
    pub project_id: CloudIdentifier,
    /// The service account's numeric id.
    pub client_id: CloudIdentifier,
    /// Which of the account's keys this is.
    pub private_key_id: CloudIdentifier,
    /// The private key, PEM-encoded.
    pub private_key: CloudSecret,
}

/// A GCP service account key, held as its parts rather than the file the
/// customer uploaded.
///
/// The CLI trusts a key file completely. It signs in at whatever `token_uri`
/// it names, moves every API endpoint onto its `universe_domain`, and treats
/// an `external_account` file as a recipe for fetching credentials. So only
/// a `service_account` key for the named account is accepted, and only its
/// parts are kept. The adapter that runs the CLI writes a fresh file from
/// them with [`Self::TOKEN_URI`] and [`Self::UNIVERSE_DOMAIN`]. Nothing else
/// the customer wrote, known field or unknown, ever reaches the CLI.
#[derive(Clone, PartialEq, Eq)]
pub struct GcpServiceAccountKey {
    project_id: CloudIdentifier,
    client_id: CloudIdentifier,
    private_key_id: CloudIdentifier,
    private_key: CloudSecret,
}

impl GcpServiceAccountKey {
    /// Google's token endpoint, the only one a key file may name.
    pub const TOKEN_URI: &'static str = "https://oauth2.googleapis.com/token";

    /// Google's own universe, the only one a key file may name.
    pub const UNIVERSE_DOMAIN: &'static str = "googleapis.com";

    /// The key read from a file that says `facts` about itself.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if the file is not a `service_account`
    ///   key.
    /// - [`DomainError::Validation`] if it belongs to another account than
    ///   `client_email`.
    /// - [`DomainError::Validation`] if it names another token endpoint or
    ///   universe than Google's.
    pub fn new(
        parts: GcpKeyParts,
        facts: &GcpKeyFacts<'_>,
        client_email: &CloudIdentifier,
    ) -> Result<Self, DomainError> {
        if facts.key_type != "service_account" {
            return Err(DomainError::invalid(message!(
                "organization-only-a-google-service-account-key",
                "only a Google service account key can be used"
            )));
        }
        if facts.client_email != client_email.as_str() {
            return Err(DomainError::invalid(message!(
                "organization-the-key-belongs-to-a-different",
                "the key belongs to a different service account than the one named"
            )));
        }
        let googles_universe = facts
            .universe_domain
            .is_none_or(|universe| universe == Self::UNIVERSE_DOMAIN);
        if facts.token_uri != Self::TOKEN_URI || !googles_universe {
            return Err(DomainError::invalid(message!(
                "organization-the-key-must-sign-in-at",
                "the key must sign in at Google's own endpoints"
            )));
        }
        Ok(Self {
            project_id: parts.project_id,
            client_id: parts.client_id,
            private_key_id: parts.private_key_id,
            private_key: parts.private_key,
        })
    }

    /// The project the service account belongs to.
    #[must_use]
    pub fn project_id(&self) -> &CloudIdentifier {
        &self.project_id
    }

    /// The service account's numeric id.
    #[must_use]
    pub fn client_id(&self) -> &CloudIdentifier {
        &self.client_id
    }

    /// Which of the account's keys this is.
    #[must_use]
    pub fn private_key_id(&self) -> &CloudIdentifier {
        &self.private_key_id
    }

    /// The private key, for the one adapter that writes the CLI's key file.
    #[must_use]
    pub fn private_key(&self) -> &CloudSecret {
        &self.private_key
    }
}

impl std::fmt::Debug for GcpServiceAccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GcpServiceAccountKey(<redacted>)")
    }
}

/// `arn:<partition>:iam::<12-digit account>:role/<path and name>`, in one of
/// AWS's partitions, with the characters IAM allows in a role's path and name.
struct AwsRoleArn;

impl AwsRoleArn {
    const PARTITIONS: [&'static str; 3] = ["aws", "aws-cn", "aws-us-gov"];
}

impl Rule for AwsRoleArn {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let parts: Vec<&str> = value.split(':').collect();
        let shaped = match parts.as_slice() {
            ["arn", partition, "iam", "", account, resource] => {
                Self::PARTITIONS.contains(partition)
                    && account.len() == 12
                    && account.bytes().all(|b| b.is_ascii_digit())
                    && names_a_role(resource)
            }
            _ => false,
        };
        if shaped {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_role_arn".to_owned(),
            message: message!(
                "organization-role-arn-must-look-like-arn",
                "role_arn must look like arn:aws:iam::<account-id>:role/<name>"
            ),
        })
    }
}

fn names_a_role(resource: &str) -> bool {
    resource.strip_prefix("role/").is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-/".contains(&b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn external_id() -> ExternalId {
        ExternalId::new("abcdefghijklmnopqrstuvwxyz012345").unwrap()
    }

    fn role_arn() -> RoleArn {
        RoleArn::new("arn:aws:iam::123456789012:role/IanuaProvisioning").unwrap()
    }

    /// The external ID constructor refuses a five-character value below
    /// its minimum length.
    #[test]
    fn external_id_rejects_a_guessable_length() {
        assert!(ExternalId::new("short").is_err());
    }

    /// An external id holding `/../` is refused. Only letters, digits,
    /// hyphens and underscores are allowed.
    #[test]
    fn external_id_rejects_characters_outside_the_safe_alphabet() {
        assert!(ExternalId::new("abcdefghijklmnopqrstuvwx/../etc").is_err());
    }

    /// A long external id with a hyphen and an underscore in it is accepted.
    #[test]
    fn external_id_accepts_hyphens_and_underscores() {
        assert!(ExternalId::new("abcdefghijkl-mnopqrstuv_wxyz0123").is_ok());
    }

    /// An external id is printed with `{:?}`, as a log line would. It shows
    /// as redacted, without its value.
    #[test]
    fn external_id_debug_does_not_leak_the_value() {
        let rendered = format!("{:?}", external_id());
        assert!(!rendered.contains("abcdefghij"));
        assert!(rendered.contains("redacted"));
    }

    /// A role ARN in account `123456789012` is accepted, and reports that
    /// account id for the customer to confirm.
    #[test]
    fn role_arn_accepts_a_well_formed_arn() {
        assert_eq!(role_arn().account_id(), "123456789012");
    }

    /// A role ARN in the `aws-us-gov` partition is accepted.
    #[test]
    fn role_arn_accepts_the_govcloud_partition() {
        assert!(RoleArn::new("arn:aws-us-gov:iam::123456789012:role/Ianua").is_ok());
    }

    /// A customer pastes the ARN of an IAM user instead of a role. It is
    /// refused.
    #[test]
    fn role_arn_rejects_a_user_arn() {
        assert!(RoleArn::new("arn:aws:iam::123456789012:user/someone").is_err());
    }

    /// An ARN that names S3 instead of IAM is refused.
    #[test]
    fn role_arn_rejects_a_non_iam_service() {
        assert!(RoleArn::new("arn:aws:s3::123456789012:role/Ianua").is_err());
    }

    /// An ARN with a five-digit account id is refused. AWS account ids have
    /// twelve digits.
    #[test]
    fn role_arn_rejects_a_short_account_id() {
        assert!(RoleArn::new("arn:aws:iam::12345:role/Ianua").is_err());
    }

    /// An ARN ending in `role/` with no name is refused.
    #[test]
    fn role_arn_rejects_an_empty_role_name() {
        assert!(RoleArn::new("arn:aws:iam::123456789012:role/").is_err());
    }

    /// An IAM role ARN that names `eu-central-1` is refused. IAM is global,
    /// so its ARNs carry no region.
    #[test]
    fn role_arn_rejects_a_region_it_should_not_carry() {
        assert!(RoleArn::new("arn:aws:iam:eu-central-1:123456789012:role/Ianua").is_err());
    }

    /// An ARN in a made-up `awsx` partition is refused.
    #[test]
    fn role_arn_rejects_a_partition_aws_does_not_have() {
        assert!(RoleArn::new("arn:awsx:iam::123456789012:role/Ianua").is_err());
    }

    /// A role name with a space or a quote in it is refused, as IAM would
    /// refuse it, before it reaches a CLI argument.
    #[test]
    fn role_arn_rejects_a_role_name_with_characters_iam_refuses() {
        assert!(RoleArn::new("arn:aws:iam::123456789012:role/Ianua admin").is_err());
        assert!(RoleArn::new("arn:aws:iam::123456789012:role/Ia\"nua").is_err());
    }

    /// A role under the path `service-role/` with a `+` in its name is
    /// accepted, as IAM allows both.
    #[test]
    fn role_arn_accepts_a_role_under_a_path() {
        assert!(RoleArn::new("arn:aws:iam::123456789012:role/service-role/Ianua+Ops").is_ok());
    }

    /// An ARN cut off after the account id is refused.
    #[test]
    fn role_arn_rejects_a_truncated_arn() {
        assert!(RoleArn::new("arn:aws:iam::123456789012").is_err());
    }

    /// A customer submits an empty token. It is refused.
    #[test]
    fn cloud_secret_rejects_empty() {
        assert!(CloudSecret::new("").is_err());
    }

    /// A DigitalOcean token is printed with `{:?}`, as a log line would. It
    /// shows as redacted, without its value.
    #[test]
    fn cloud_secret_debug_does_not_leak_the_value() {
        let secret = CloudSecret::new("do_v1_supersecrettoken").unwrap();
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("supersecret"));
        assert!(rendered.contains("redacted"));
    }

    /// An assumed role reports AWS and a DigitalOcean token reports
    /// DigitalOcean, read from the kind of credential alone.
    #[test]
    fn provider_is_derived_from_the_credential_shape() {
        let aws = CloudCredential::AwsAssumeRole {
            role_arn: role_arn(),
            external_id: external_id(),
        };
        assert_eq!(aws.provider(), CloudProvider::Aws);

        let r#do = CloudCredential::DigitalOceanToken {
            token: CloudSecret::new("dop_v1_x").unwrap(),
        };
        assert_eq!(r#do.provider(), CloudProvider::DigitalOcean);
    }

    /// A DigitalOcean token stays valid until the platform deletes its copy.
    /// It reads as not revocable by the customer, so they are told so.
    #[test]
    fn a_bearer_token_cannot_be_revoked_from_the_customer_side() {
        let token = CloudCredential::DigitalOceanToken {
            token: CloudSecret::new("dop_v1_x").unwrap(),
        };
        assert!(!token.is_revocable_by_customer());
    }

    /// An AWS role can be cut off by the customer deleting it. It reads as
    /// revocable by the customer.
    #[test]
    fn an_assumed_role_can_be_revoked_from_the_customer_side() {
        let role = CloudCredential::AwsAssumeRole {
            role_arn: role_arn(),
            external_id: external_id(),
        };
        assert!(role.is_revocable_by_customer());
    }

    /// An Azure service principal is printed with `{:?}`. Its client secret
    /// shows as redacted.
    #[test]
    fn credential_debug_leaks_neither_secret_nor_external_id() {
        let azure = CloudCredential::AzureServicePrincipal {
            directory_id: CloudIdentifier::new("dir-1").unwrap(),
            client_id: CloudIdentifier::new("client-1").unwrap(),
            secret: CloudSecret::new("azure-client-secret-value").unwrap(),
        };
        let rendered = format!("{azure:?}");
        assert!(!rendered.contains("azure-client-secret-value"));
        assert!(rendered.contains("redacted"));
    }

    /// A role ARN, an external id, a token and a directory id each give back
    /// the exact value they were made from, since a cloud SDK gets them as
    /// written.
    #[test]
    fn every_credential_field_hands_back_the_value_it_holds() {
        assert_eq!(
            role_arn().as_str(),
            "arn:aws:iam::123456789012:role/IanuaProvisioning"
        );
        assert_eq!(external_id().as_str(), "abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(
            CloudSecret::new("dop_v1_token").unwrap().expose(),
            "dop_v1_token"
        );
        assert_eq!(CloudIdentifier::new("dir-1").unwrap().as_str(), "dir-1");
    }

    /// A role ARN is printed with `{:?}`. It shows in full, since it is not a
    /// secret and an operator reads it to see which role a call tried.
    #[test]
    fn a_role_arn_shows_itself_in_debug_output() {
        let rendered = format!("{:?}", role_arn());

        assert!(rendered.contains("arn:aws:iam::123456789012:role/Ianua"));
        assert!(rendered.contains("RoleArn"));
    }

    /// A public HTTPS Kubernetes endpoint is accepted; private, loopback
    /// and link-local addresses, HTTP, credentials, queries and fragments
    /// are refused.
    #[test]
    fn a_kubernetes_api_server_must_be_a_public_https_address() {
        assert!(KubernetesApiServer::new("https://k8s.corp.example:6443").is_ok());
        for bad in [
            "http://k8s.corp.example:6443",
            "https://169.254.169.254/",
            "https://10.0.0.5:6443",
            "https://127.0.0.1:6443",
            "https://[::1]:6443",
            "https://user:pass@k8s.corp.example",
            "https://k8s.corp.example:6443/?x=y",
            "https://k8s.corp.example:6443/#x",
        ] {
            assert!(KubernetesApiServer::new(bad).is_err(), "{bad} was accepted");
        }
    }

    /// Kubernetes endpoints with internal-only names are refused,
    /// including uppercase metadata names with a trailing dot.
    #[test]
    fn a_name_that_can_only_be_internal_is_refused() {
        for bad in [
            "https://localhost:6443",
            "https://metadata.google.internal/",
            "https://kubernetes.default.svc",
            "https://kubernetes.default.svc.cluster.local",
            "https://printer.local",
            "https://app.localhost",
            "https://redis:6379",
            "https://METADATA.GOOGLE.INTERNAL./",
        ] {
            assert!(KubernetesApiServer::new(bad).is_err(), "{bad} was accepted");
        }
    }

    fn key_facts<'a>(
        key_type: &'a str,
        client_email: &'a str,
        token_uri: &'a str,
    ) -> GcpKeyFacts<'a> {
        GcpKeyFacts {
            key_type,
            client_email,
            token_uri,
            universe_domain: None,
        }
    }

    fn parts() -> GcpKeyParts {
        GcpKeyParts {
            project_id: CloudIdentifier::new("proj").unwrap(),
            client_id: CloudIdentifier::new("1234567890").unwrap(),
            private_key_id: CloudIdentifier::new("abc123").unwrap(),
            private_key: CloudSecret::new("test-private-key-material").unwrap(),
        }
    }

    fn gcp_key(facts: &GcpKeyFacts<'_>) -> Result<GcpServiceAccountKey, DomainError> {
        GcpServiceAccountKey::new(
            parts(),
            facts,
            &CloudIdentifier::new("svc@proj.iam.gserviceaccount.com").unwrap(),
        )
    }

    /// A service-account key naming an outside universe is refused, while
    /// the same facts naming Google's universe are accepted.
    #[test]
    fn a_key_naming_another_universe_is_refused() {
        let email = "svc@proj.iam.gserviceaccount.com";
        let elsewhere = GcpKeyFacts {
            universe_domain: Some("attacker.example"),
            ..key_facts("service_account", email, GcpServiceAccountKey::TOKEN_URI)
        };
        let googles = GcpKeyFacts {
            universe_domain: Some(GcpServiceAccountKey::UNIVERSE_DOMAIN),
            ..key_facts("service_account", email, GcpServiceAccountKey::TOKEN_URI)
        };

        assert!(gcp_key(&elsewhere).is_err());
        assert!(gcp_key(&googles).is_ok());
    }

    /// A valid service-account key is held. It gives back its project,
    /// client id, key id and private key as read from the file.
    #[test]
    fn a_held_key_keeps_only_its_own_parts() {
        let key = gcp_key(&key_facts(
            "service_account",
            "svc@proj.iam.gserviceaccount.com",
            GcpServiceAccountKey::TOKEN_URI,
        ))
        .unwrap();

        assert_eq!(key.project_id().as_str(), "proj");
        assert_eq!(key.client_id().as_str(), "1234567890");
        assert_eq!(key.private_key_id().as_str(), "abc123");
        assert_eq!(key.private_key().expose(), "test-private-key-material");
    }

    /// Acme uploads a `service_account` key for the account it named, with
    /// Google's token endpoint. It is accepted.
    #[test]
    fn a_service_account_key_for_the_named_account_is_held() {
        let facts = key_facts(
            "service_account",
            "svc@proj.iam.gserviceaccount.com",
            GcpServiceAccountKey::TOKEN_URI,
        );

        assert!(gcp_key(&facts).is_ok());
    }

    /// External-account and user keys, a metadata token endpoint, and a
    /// mismatched service-account address all fail key validation.
    #[test]
    fn a_key_that_signs_in_elsewhere_or_is_not_a_service_account_is_refused() {
        let email = "svc@proj.iam.gserviceaccount.com";
        for facts in [
            key_facts("external_account", email, GcpServiceAccountKey::TOKEN_URI),
            key_facts("authorized_user", email, GcpServiceAccountKey::TOKEN_URI),
            key_facts("service_account", email, "http://169.254.169.254/token"),
            key_facts(
                "service_account",
                "other@proj.iam.gserviceaccount.com",
                GcpServiceAccountKey::TOKEN_URI,
            ),
        ] {
            assert!(gcp_key(&facts).is_err());
        }
    }

    /// A held GCP key is printed with `{:?}`. It prints only as redacted.
    #[test]
    fn a_gcp_key_is_never_printed() {
        let facts = key_facts(
            "service_account",
            "svc@proj.iam.gserviceaccount.com",
            GcpServiceAccountKey::TOKEN_URI,
        );

        assert_eq!(
            format!("{:?}", gcp_key(&facts).unwrap()),
            "GcpServiceAccountKey(<redacted>)"
        );
    }
}
