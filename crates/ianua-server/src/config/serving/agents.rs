//! Agents: how long their credentials, approvals and runs last, where
//! their model and tool calls may go, how a declared purpose is read, and
//! which platform attestations the deployment trusts.

use std::fmt;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{Audience, HttpsUrl};
use ianua_infra::proofs::KeyKeeping;

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86_400);

/// Where Google publishes the keys its instance identity tokens are signed
/// with.
const GOOGLE_CERTS: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// How long agents' credentials, approvals and runs last.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AgentLifetimes {
    /// `AGENT_CREDENTIAL_TTL_SECONDS` (3600): a credential minted from an
    /// attestation.
    pub bootstrap_credential: Duration,
    /// `AGENT_CREDENTIAL_DEFAULT_TTL_DAYS` (30).
    pub credential_default: Duration,
    /// `AGENT_CREDENTIAL_MAX_TTL_DAYS` (90).
    pub credential_max: Duration,
    /// `AGENT_CREDENTIAL_ROTATION_GRACE_SECONDS` (300).
    pub credential_rotation_grace: Duration,
    /// `AGENT_TASK_TOKEN_MAX_TTL_SECONDS` (3600).
    pub task_token_max: Duration,
    /// `AGENT_ATTESTATION_CHALLENGE_TTL_SECONDS` (120).
    pub attestation_challenge: Duration,
    /// `AGENT_APPROVAL_MAX_TTL_SECONDS` (86400).
    pub approval_max: Duration,
    /// `AGENT_APPROVAL_DECISION_WINDOW_SECONDS` (900): how long a person
    /// has to decide an action the gateway paused, from a minute to a day.
    pub approval_decision_window: Duration,
    /// `AGENT_RUN_APPROVAL_TTL_SECONDS` (86400).
    pub run_approval: Duration,
    /// `AGENT_APPROVAL_FACTS_WINDOW_HOURS` (24).
    pub approval_facts_window: Duration,
    /// `AGENT_CONVERGENCE_WINDOW_HOURS` (24).
    pub convergence_window: Duration,
}

/// How a declared purpose is read: by meaning, through an embeddings API,
/// when one is set up. `Debug` shows no key.
#[derive(Clone)]
pub(crate) struct EmbeddingConfig {
    /// `AGENT_INTENT_EMBEDDING_URL`, such as `https://api.openai.com/v1`.
    pub endpoint: url::Url,
    /// `AGENT_INTENT_EMBEDDING_MODEL` (`text-embedding-3-small`).
    pub model: String,
    /// `AGENT_INTENT_EMBEDDING_API_KEY`, or none for an API that takes
    /// none.
    pub api_key: Option<Secret>,
    /// `AGENT_INTENT_SIMILARITY_THRESHOLD` (0.35).
    pub threshold: f32,
}

impl fmt::Debug for EmbeddingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddingConfig")
            .field("endpoint", &self.endpoint.as_str())
            .field("model", &self.model)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

/// The SPIFFE trust domain whose SVIDs agents may attest with.
#[derive(Debug, Clone)]
pub(crate) struct SpiffeConfig {
    /// `AGENT_SPIFFE_TRUST_DOMAIN`, such as `prod.example.com`.
    pub trust_domain: String,
    /// The authorities in `AGENT_SPIFFE_TRUST_BUNDLE_PATH`, one PEM each.
    pub anchors: Vec<String>,
}

/// The platform attestations the deployment trusts, each turned on by its
/// name in `AGENT_ATTESTATION_ALLOWLIST` and each with what it is checked
/// against. Nothing listed trusts none.
#[derive(Debug, Clone)]
pub(crate) struct AttestationConfig {
    /// `spiffe`: SVIDs of one trust domain.
    pub spiffe: Option<SpiffeConfig>,
    /// `tpm`: quotes under the authorities in
    /// `AGENT_TPM_TRUST_BUNDLE_PATH`, those that issue the attestation
    /// identity keys of the trusted machines.
    pub tpm: Option<Vec<String>>,
    /// `gcp`: instance identity tokens under the keys at
    /// `AGENT_GCP_JWKS_URL`, Google's own by default.
    pub gcp: Option<url::Url>,
    /// `aws` or `aws_iam`: a signed `sts:GetCallerIdentity` request that
    /// AWS answers.
    pub aws_iam: bool,
    /// `AGENT_ISSUER_KEYS_TTL_SECONDS` (600) and
    /// `AGENT_ISSUER_KEYS_RENEW_SECONDS` (60): how long an issuer's keys
    /// are kept, and the least time between two fetches of them.
    pub issuer_keys: KeyKeeping,
}

/// Bounds machine-identity lifetimes and execution, and selects trusted proof sources.
#[derive(Debug, Clone)]
pub(crate) struct AgentsConfig {
    /// How long credentials, approvals and runs last.
    pub lifetimes: AgentLifetimes,
    /// `AGENT_APPROVAL_MAX_PER_HOUR` (30): approvals one person may give.
    pub approvals_per_hour: u32,
    /// `AGENT_APPROVAL_MAX_OPEN_PER_DELEGATION` (20): the undecided
    /// requests the gateway may open under one delegation; past it the
    /// agent is refused outright.
    pub approval_max_open_per_delegation: u32,
    /// `AGENT_RUN_DEFAULT_MAX_STEPS` (8).
    pub run_default_steps: u32,
    /// `AGENT_RUN_MAX_STEPS` (20).
    pub run_max_steps: u32,
    /// `SIGNAL_DISABLE_AFTER_FAILURES` (20): failed pushes after which a
    /// signal stream is switched off.
    pub signal_disable_after_failures: u32,
    /// `AGENT_TOKEN_AUDIENCE`: the audience agents sign their assertions
    /// for; `APP_BASE_URL` by default.
    pub token_audience: Audience,
    /// `AGENT_PROXY_BASE_URL`: the gateway agents' tool calls go through;
    /// none refuses every tool call.
    pub proxy_base_url: Option<url::Url>,
    /// `ALLOW_PRIVATE_MODEL_ENDPOINTS`: the private ranges a tenant's model
    /// endpoint may point into, comma-separated CIDR blocks; empty allows
    /// public addresses only. The metadata addresses stay refused.
    pub model_networks: UpstreamNetworks,
    /// `AGENT_MODEL_TIMEOUT_SECONDS` (30): one model call.
    pub model_timeout: Duration,
    /// `AGENT_TOOL_TIMEOUT_SECONDS` (30): one tool call.
    pub tool_timeout: Duration,
    /// How a declared purpose is read; none reads it by keyword.
    pub embeddings: Option<EmbeddingConfig>,
    /// The platform attestations trusted.
    pub attestation: AttestationConfig,
}

impl AgentsConfig {
    /// The agent settings `vars` holds, the token audience defaulting to
    /// `app_base_url`.
    ///
    /// # Errors
    ///
    /// A setting that does not read, credential lifetimes that do not
    /// nest, embedding settings without their endpoint, or an attestation
    /// listed without what it is checked against, or unlisted with it.
    pub(crate) fn read(vars: &Env, app_base_url: &HttpsUrl) -> Read<Self> {
        let run_default_steps = vars.number_in("AGENT_RUN_DEFAULT_MAX_STEPS", 8, 1..=1000)?;
        let run_max_steps = vars.number_in("AGENT_RUN_MAX_STEPS", 20, 1..=1000)?;
        ensure_run_steps(run_default_steps, run_max_steps)?;
        let audience = vars.text("AGENT_TOKEN_AUDIENCE", app_base_url.as_str())?;
        Ok(Self {
            lifetimes: lifetimes(vars)?,
            approvals_per_hour: vars.number_in("AGENT_APPROVAL_MAX_PER_HOUR", 30, 1..=10_000)?,
            approval_max_open_per_delegation: vars.number_in(
                "AGENT_APPROVAL_MAX_OPEN_PER_DELEGATION",
                20,
                1..=1000,
            )?,
            run_default_steps,
            run_max_steps,
            signal_disable_after_failures: vars.number_in(
                "SIGNAL_DISABLE_AFTER_FAILURES",
                20,
                1..=10_000,
            )?,
            token_audience: Audience::new(audience)
                .map_err(|cause| ConfigError::rejected("AGENT_TOKEN_AUDIENCE", cause))?,
            proxy_base_url: vars.url("AGENT_PROXY_BASE_URL")?,
            model_networks: vars.networks("ALLOW_PRIVATE_MODEL_ENDPOINTS")?,
            model_timeout: vars.seconds("AGENT_MODEL_TIMEOUT_SECONDS", Duration::from_secs(30))?,
            tool_timeout: vars.seconds("AGENT_TOOL_TIMEOUT_SECONDS", Duration::from_secs(30))?,
            embeddings: embeddings(vars)?,
            attestation: attestation(vars)?,
        })
    }
}

/// Refuses a default run allowance larger than the configured maximum.
fn ensure_run_steps(default: u32, maximum: u32) -> Read<()> {
    if default > maximum {
        return Err(ConfigError::contradicts(
            "AGENT_RUN_DEFAULT_MAX_STEPS",
            "is more than AGENT_RUN_MAX_STEPS",
        ));
    }
    Ok(())
}

/// Refuses zero-length default credentials and defaults exceeding the maximum.
fn ensure_credential_lifetimes(default: Duration, maximum: Duration) -> Read<()> {
    if default.is_zero() || default > maximum {
        return Err(ConfigError::contradicts(
            "AGENT_CREDENTIAL_DEFAULT_TTL_DAYS",
            "must be at least a day and at most AGENT_CREDENTIAL_MAX_TTL_DAYS",
        ));
    }
    Ok(())
}

/// Reads credential, approval and run lifetimes after checking their bounds.
fn lifetimes(vars: &Env) -> Read<AgentLifetimes> {
    let credential_default = vars.days("AGENT_CREDENTIAL_DEFAULT_TTL_DAYS", 30 * DAY)?;
    let credential_max = vars.days("AGENT_CREDENTIAL_MAX_TTL_DAYS", 90 * DAY)?;
    ensure_credential_lifetimes(credential_default, credential_max)?;
    Ok(AgentLifetimes {
        bootstrap_credential: vars.seconds_in(
            "AGENT_CREDENTIAL_TTL_SECONDS",
            HOUR,
            1..=DAY.as_secs(),
        )?,
        credential_default,
        credential_max,
        credential_rotation_grace: vars
            .seconds("AGENT_CREDENTIAL_ROTATION_GRACE_SECONDS", 5 * MINUTE)?,
        task_token_max: vars.seconds("AGENT_TASK_TOKEN_MAX_TTL_SECONDS", HOUR)?,
        attestation_challenge: vars
            .seconds("AGENT_ATTESTATION_CHALLENGE_TTL_SECONDS", 2 * MINUTE)?,
        approval_max: vars.seconds("AGENT_APPROVAL_MAX_TTL_SECONDS", DAY)?,
        approval_decision_window: vars.seconds_in(
            "AGENT_APPROVAL_DECISION_WINDOW_SECONDS",
            15 * MINUTE,
            MINUTE.as_secs()..=DAY.as_secs(),
        )?,
        run_approval: vars.seconds("AGENT_RUN_APPROVAL_TTL_SECONDS", DAY)?,
        approval_facts_window: vars.hours("AGENT_APPROVAL_FACTS_WINDOW_HOURS", DAY)?,
        convergence_window: vars.hours("AGENT_CONVERGENCE_WINDOW_HOURS", DAY)?,
    })
}

/// The embeddings API, when its endpoint is set.
fn embeddings(vars: &Env) -> Read<Option<EmbeddingConfig>> {
    let api_key = vars.secret("AGENT_INTENT_EMBEDDING_API_KEY")?;
    let model = vars.text("AGENT_INTENT_EMBEDDING_MODEL", "text-embedding-3-small")?;
    let threshold = vars.fraction("AGENT_INTENT_SIMILARITY_THRESHOLD", 0.35)?;
    let Some(endpoint) = vars.url("AGENT_INTENT_EMBEDDING_URL")? else {
        let model_set = vars.optional("AGENT_INTENT_EMBEDDING_MODEL")?.is_some();
        let stray = match (api_key.is_some(), model_set) {
            (true, _) => Some("AGENT_INTENT_EMBEDDING_API_KEY"),
            (false, true) => Some("AGENT_INTENT_EMBEDDING_MODEL"),
            (false, false) => None,
        };
        return match stray {
            Some(name) => Err(ConfigError::contradicts(
                name,
                "is set without AGENT_INTENT_EMBEDDING_URL",
            )),
            None => Ok(None),
        };
    };
    Ok(Some(EmbeddingConfig {
        endpoint,
        model,
        api_key,
        threshold,
    }))
}

/// Which attestation `AGENT_ATTESTATION_ALLOWLIST` names an entry as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Listed {
    Spiffe,
    Tpm,
    Gcp,
    AwsIam,
}

/// The attestations listed, each with what it is checked against.
fn attestation(vars: &Env) -> Read<AttestationConfig> {
    let listed = listed_attestations(vars)?;
    let on = |method: Listed| listed.contains(&method);
    Ok(AttestationConfig {
        spiffe: spiffe(vars, on(Listed::Spiffe))?,
        tpm: anchors_for(vars, "AGENT_TPM_TRUST_BUNDLE_PATH", "tpm", on(Listed::Tpm))?,
        gcp: gcp(vars, on(Listed::Gcp))?,
        aws_iam: on(Listed::AwsIam),
        issuer_keys: KeyKeeping {
            keep_for: vars.seconds("AGENT_ISSUER_KEYS_TTL_SECONDS", Duration::from_secs(600))?,
            renew_after: vars.seconds("AGENT_ISSUER_KEYS_RENEW_SECONDS", MINUTE)?,
        },
    })
}

/// The attestations `AGENT_ATTESTATION_ALLOWLIST` lists. Azure is refused
/// by name: nothing it signs can carry the binding of a challenge and the
/// key being enrolled, so no deployment may trust it.
fn listed_attestations(vars: &Env) -> Read<Vec<Listed>> {
    let name = "AGENT_ATTESTATION_ALLOWLIST";
    let mut listed = Vec::new();
    for entry in vars.list(name)? {
        let method = match entry.to_ascii_lowercase().as_str() {
            "spiffe" => Listed::Spiffe,
            "tpm" => Listed::Tpm,
            "gcp" | "gcp_instance_identity" => Listed::Gcp,
            "aws" | "aws_iam" => Listed::AwsIam,
            "azure" | "azure_managed_identity" => {
                return Err(ConfigError::invalid(
                    name,
                    "lists azure, which cannot bind its token to the enrolled key and is never trusted",
                ));
            }
            _ => {
                return Err(ConfigError::invalid(
                    name,
                    format!("must list spiffe, tpm, gcp or aws, got {entry:?}"),
                ));
            }
        };
        listed.push(method);
    }
    Ok(listed)
}

/// The SPIFFE trust domain and its bundle, when `spiffe` is listed.
fn spiffe(vars: &Env, listed: bool) -> Read<Option<SpiffeConfig>> {
    let trust_domain = vars.optional("AGENT_SPIFFE_TRUST_DOMAIN")?;
    let anchors = anchors_for(vars, "AGENT_SPIFFE_TRUST_BUNDLE_PATH", "spiffe", listed)?;
    match (anchors, trust_domain) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(ConfigError::contradicts(
            "AGENT_SPIFFE_TRUST_DOMAIN",
            "is set but AGENT_ATTESTATION_ALLOWLIST does not list spiffe",
        )),
        (Some(_), None) => Err(ConfigError::missing("AGENT_SPIFFE_TRUST_DOMAIN")),
        (Some(anchors), Some(trust_domain)) => Ok(Some(SpiffeConfig {
            trust_domain,
            anchors,
        })),
    }
}

/// The PEM blocks of the bundle `name` points at, when `method` is
/// `listed`; refused when it is listed without one, or set unlisted.
fn anchors_for(vars: &Env, name: &str, method: &str, listed: bool) -> Read<Option<Vec<String>>> {
    let bundle = vars.file_text(name)?;
    match (bundle, listed) {
        (None, false) => Ok(None),
        (None, true) => Err(ConfigError::missing(name)),
        (Some(_), false) => Err(ConfigError::contradicts(
            name,
            format!("is set but AGENT_ATTESTATION_ALLOWLIST does not list {method}"),
        )),
        (Some(text), true) => {
            let blocks = pem_blocks(&text);
            if blocks.is_empty() {
                return Err(ConfigError::invalid(
                    name,
                    "names a file with no PEM block in it",
                ));
            }
            Ok(Some(blocks))
        }
    }
}

/// Where Google's keys are read, when `gcp` is listed.
fn gcp(vars: &Env, listed: bool) -> Read<Option<url::Url>> {
    let name = "AGENT_GCP_JWKS_URL";
    let given = vars.url(name)?;
    match (given, listed) {
        (None, false) => Ok(None),
        (Some(_), false) => Err(ConfigError::contradicts(
            name,
            "is set but AGENT_ATTESTATION_ALLOWLIST does not list gcp",
        )),
        (Some(url), true) => Ok(Some(url)),
        (None, true) => url::Url::parse(GOOGLE_CERTS)
            .map(Some)
            .map_err(|cause| ConfigError::rejected(name, cause)),
    }
}

/// Every `-----BEGIN ...-----` to `-----END ...-----` block in `text`, one
/// string each: certificates or bare public keys alike.
fn pem_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in text.lines().map(str::trim_end) {
        if line.starts_with("-----BEGIN ") {
            current = vec![line];
            continue;
        }
        if current.is_empty() {
            continue;
        }
        current.push(line);
        if line.starts_with("-----END ") {
            blocks.push(current.join("\n"));
            current.clear();
        }
    }
    blocks
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    fn base() -> HttpsUrl {
        HttpsUrl::new("https://app.example.com").unwrap()
    }

    fn bundle() -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(PEM.as_bytes()).unwrap();
        file
    }

    /// With nothing set, no attestation is trusted, model endpoints reach
    /// public addresses only, and purposes are read by keyword.
    #[test]
    fn with_nothing_set_nothing_is_trusted() {
        let config = AgentsConfig::read(&Env::of([]), &base()).unwrap();

        assert!(config.attestation.spiffe.is_none());
        assert!(!config.attestation.aws_iam);
        assert!(config.embeddings.is_none());
        assert_eq!(config.model_networks, UpstreamNetworks::public_only());
        assert_eq!(config.token_audience.as_str(), "https://app.example.com");
        assert_eq!(config.model_timeout, Duration::from_secs(30));
    }

    /// An attestation allowlist containing Azure is refused, naming the
    /// invalid allowlist setting.
    #[test]
    fn azure_in_the_allowlist_is_refused() {
        let read = AgentsConfig::read(
            &Env::of([("AGENT_ATTESTATION_ALLOWLIST", "aws, azure")]),
            &base(),
        );

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "AGENT_ATTESTATION_ALLOWLIST")
        );
    }

    /// Both spellings of the AWS IAM attestation turn it on.
    #[test]
    fn both_spellings_of_aws_turn_it_on() {
        for spelling in ["aws", "aws_iam"] {
            let config = AgentsConfig::read(
                &Env::of([("AGENT_ATTESTATION_ALLOWLIST", spelling)]),
                &base(),
            )
            .unwrap();

            assert!(config.attestation.aws_iam);
        }
    }

    /// Listing SPIFFE without its trust bundle is refused, naming the
    /// missing bundle setting.
    #[test]
    fn spiffe_listed_without_its_bundle_is_refused() {
        let read = AgentsConfig::read(
            &Env::of([("AGENT_ATTESTATION_ALLOWLIST", "spiffe")]),
            &base(),
        );

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name == "AGENT_SPIFFE_TRUST_BUNDLE_PATH")
        );
    }

    /// SPIFFE listed with its bundle and trust domain is trusted.
    #[test]
    fn spiffe_with_its_bundle_and_domain_is_trusted() {
        let file = bundle();
        let path = file.path().to_str().unwrap().to_owned();
        let vars = Env::of([
            ("AGENT_ATTESTATION_ALLOWLIST", "spiffe"),
            ("AGENT_SPIFFE_TRUST_BUNDLE_PATH", path.as_str()),
            ("AGENT_SPIFFE_TRUST_DOMAIN", "prod.example.com"),
        ]);

        let spiffe = AgentsConfig::read(&vars, &base())
            .unwrap()
            .attestation
            .spiffe
            .unwrap();

        assert_eq!(spiffe.anchors.len(), 1);
    }

    /// A TPM trust bundle without TPM in the allowlist is refused as
    /// contradictory configuration.
    #[test]
    fn a_bundle_for_an_unlisted_attestation_is_refused() {
        let file = bundle();
        let path = file.path().to_str().unwrap().to_owned();

        let read = AgentsConfig::read(
            &Env::of([("AGENT_TPM_TRUST_BUNDLE_PATH", path.as_str())]),
            &base(),
        );

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "AGENT_TPM_TRUST_BUNDLE_PATH")
        );
    }

    /// A bundle with no PEM block in it is refused.
    #[test]
    fn a_bundle_with_no_pem_block_is_refused() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"not a certificate").unwrap();
        let path = file.path().to_str().unwrap().to_owned();
        let vars = Env::of([
            ("AGENT_ATTESTATION_ALLOWLIST", "tpm"),
            ("AGENT_TPM_TRUST_BUNDLE_PATH", path.as_str()),
        ]);

        assert!(AgentsConfig::read(&vars, &base()).is_err());
    }

    /// GCP listed reads Google's own keys unless another address is set.
    #[test]
    fn gcp_listed_reads_googles_keys() {
        let config =
            AgentsConfig::read(&Env::of([("AGENT_ATTESTATION_ALLOWLIST", "gcp")]), &base())
                .unwrap();

        assert_eq!(config.attestation.gcp.unwrap().as_str(), GOOGLE_CERTS);
    }

    /// An embeddings API key without an endpoint is refused as
    /// contradictory configuration.
    #[test]
    fn an_embeddings_key_without_its_endpoint_is_refused() {
        let read = AgentsConfig::read(
            &Env::of([("AGENT_INTENT_EMBEDDING_API_KEY", "sk-1")]),
            &base(),
        );

        assert!(matches!(read, Err(ConfigError::Contradicts { .. })));
    }

    /// A configured embeddings provider remains present while debug output
    /// omits its API key.
    #[test]
    fn the_embeddings_key_never_prints() {
        let vars = Env::of([
            ("AGENT_INTENT_EMBEDDING_URL", "https://api.openai.com/v1"),
            ("AGENT_INTENT_EMBEDDING_API_KEY", "sk-live-1"),
        ]);

        let config = AgentsConfig::read(&vars, &base()).unwrap();

        assert!(config.embeddings.is_some());
        assert!(!format!("{config:?}").contains("sk-live-1"));
    }

    /// Private model ranges are read as CIDR blocks; a word is refused.
    #[test]
    fn private_model_ranges_are_cidr_blocks() {
        let good = AgentsConfig::read(
            &Env::of([("ALLOW_PRIVATE_MODEL_ENDPOINTS", "10.0.0.0/8")]),
            &base(),
        )
        .unwrap();
        let word = AgentsConfig::read(
            &Env::of([("ALLOW_PRIVATE_MODEL_ENDPOINTS", "true")]),
            &base(),
        );

        assert!(good.model_networks.permits("10.1.2.3".parse().unwrap()));
        assert!(word.is_err());
    }

    /// With nothing set, a paused action waits fifteen minutes for a person,
    /// and a delegation may hold twenty such requests open.
    #[test]
    fn the_approval_gate_defaults_to_fifteen_minutes_and_twenty_open() {
        let config = AgentsConfig::read(&Env::of([]), &base()).unwrap();

        assert_eq!(
            config.lifetimes.approval_decision_window,
            Duration::from_secs(900)
        );
        assert_eq!(config.approval_max_open_per_delegation, 20);
    }

    /// Approval windows below one minute or above one day and a zero open
    /// request limit are refused, each naming its invalid setting.
    #[test]
    fn an_approval_gate_out_of_bounds_is_refused() {
        for (name, value) in [
            ("AGENT_APPROVAL_DECISION_WINDOW_SECONDS", "5"),
            ("AGENT_APPROVAL_DECISION_WINDOW_SECONDS", "1209600"),
            ("AGENT_APPROVAL_MAX_OPEN_PER_DELEGATION", "0"),
        ] {
            let read = AgentsConfig::read(&Env::of([(name, value)]), &base());

            assert!(
                matches!(read, Err(ConfigError::Invalid { name: ref refused, .. }) if refused == name),
                "{name}={value} was read"
            );
        }
    }

    /// A default credential lifetime past the longest is refused.
    #[test]
    fn a_default_credential_lifetime_past_the_longest_is_refused() {
        let read = AgentsConfig::read(
            &Env::of([("AGENT_CREDENTIAL_DEFAULT_TTL_DAYS", "120")]),
            &base(),
        );

        assert!(read.is_err());
    }

    /// PEM blocks are split one string each, whatever their label.
    #[test]
    fn pem_blocks_are_split_whatever_their_label() {
        let text =
            format!("{PEM}junk\n-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n");

        assert_eq!(pem_blocks(&text).len(), 2);
    }
}
