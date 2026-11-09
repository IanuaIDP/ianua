//! What a model provider points at: its kind, endpoint, model and key.

use crate::shared::errors::DomainError;
use crate::shared::validation::rules::url as web_url;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::SealedSecret;

/// The kind of model backend a provider points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ModelProviderKind {
    /// A self-hosted OpenAI-compatible endpoint, such as vLLM, Ollama or TGI.
    SelfHosted,
    /// OpenAI's API, which uses the OpenAI wire format.
    OpenAi,
    /// Anthropic's Messages API, which has its own wire format.
    Anthropic,
}

impl ModelProviderKind {
    /// The stored string representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfHosted => "self_hosted",
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
        }
    }

    /// Parses a stored representation.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the name is unknown. The row is
    ///   corrupt.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "self_hosted" => Ok(Self::SelfHosted),
            "openai" => Ok(Self::OpenAi),
            "anthropic" => Ok(Self::Anthropic),
            _ => Err(DomainError::corrupt_row(
                "model provider",
                "an unknown kind",
            )),
        }
    }

    /// Whether this backend speaks the OpenAI `/chat/completions` wire format.
    #[must_use]
    pub fn is_openai_compatible(self) -> bool {
        matches!(self, Self::SelfHosted | Self::OpenAi)
    }

    /// Whether this backend is always called with a key. Only a self-hosted
    /// endpoint may take none.
    #[must_use]
    pub fn requires_key(self) -> bool {
        !matches!(self, Self::SelfHosted)
    }
}

text_value! {
    /// The base URL of a model endpoint, over `http` or `https`.
    ///
    /// `http` is allowed because self-hosted endpoints are often reached at an
    /// address inside the cluster. Endpoints outside should use `https`.
    ///
    /// For the same reason an internal address is not refused here. Whether
    /// one may be reached is up to the deployment. It is decided where the
    /// connection is made, as the endpoint's name resolves, not from the
    /// text.
    pub struct ModelEndpoint;
}

impl TextValue for ModelEndpoint {
    const FIELD: &'static str = "endpoint";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.web_url(web_url::WEB)
    }
}

text_value! {
    /// The name of the model to ask for, such as `deepseek-chat` or
    /// `gpt-4o-mini`.
    pub struct ModelName;
}

impl TextValue for ModelName {
    const FIELD: &'static str = "model";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(200)
    }
}

/// The key a model provider is called with, or that its endpoint takes none.
#[derive(Clone, PartialEq, Eq)]
pub enum ProviderKey {
    /// A self-hosted endpoint that takes no key.
    Keyless,
    /// The encrypted API key.
    Sealed(SealedSecret),
}

impl ProviderKey {
    /// The key a stored column holds. None means keyless.
    #[must_use]
    pub fn from_stored(key: Option<SealedSecret>) -> Self {
        key.map_or(Self::Keyless, Self::Sealed)
    }

    /// The sealed key, when there is one. Storage keeps it in this form.
    #[must_use]
    pub fn sealed(&self) -> Option<&SealedSecret> {
        match self {
            Self::Keyless => None,
            Self::Sealed(key) => Some(key),
        }
    }
}

impl std::fmt::Debug for ProviderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keyless => f.write_str("Keyless"),
            Self::Sealed(_) => f.write_str("Sealed(<redacted>)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-cluster `http` address and a public `https` one are accepted.
    /// An `ftp` URL, a bare host and a URL with a space are refused.
    #[test]
    fn endpoint_accepts_http_and_https_rejects_other_schemes() {
        assert!(ModelEndpoint::new("http://svc:8000/v1").is_ok());
        assert!(ModelEndpoint::new("https://api.openai.com/v1").is_ok());
        assert!(ModelEndpoint::new("ftp://x").is_err());
        assert!(ModelEndpoint::new("api.openai.com").is_err());
        assert!(ModelEndpoint::new("https://x y").is_err());
    }

    /// Each kind reads back from its stored name. A self-hosted endpoint
    /// speaks the OpenAI format and Anthropic does not, which picks the
    /// adapter a run uses.
    #[test]
    fn kind_roundtrips_and_flags_openai_compatibility() {
        for k in [
            ModelProviderKind::SelfHosted,
            ModelProviderKind::OpenAi,
            ModelProviderKind::Anthropic,
        ] {
            assert_eq!(ModelProviderKind::from_stored(k.as_str()).unwrap(), k);
        }
        assert!(ModelProviderKind::SelfHosted.is_openai_compatible());
        assert!(!ModelProviderKind::Anthropic.is_openai_compatible());
    }

    /// Storage and transport are not trusted. A value that never passed the
    /// constructor must not become valid by being read back.
    #[cfg(feature = "serde")]
    mod serde_goes_through_the_constructor {
        use super::*;

        /// JSON holding an `ftp` endpoint, or one with a space, fails to read.
        /// Deserializing runs the same rules as the constructor.
        #[test]
        fn a_stored_endpoint_that_is_not_http_is_refused() {
            assert!(serde_json::from_str::<ModelEndpoint>(r#""ftp://models""#).is_err());
            assert!(serde_json::from_str::<ModelEndpoint>(r#""https://x y""#).is_err());
        }

        /// A valid endpoint written to JSON reads back equal.
        #[test]
        fn an_endpoint_reads_back_what_it_writes() {
            let endpoint = ModelEndpoint::new("https://api.openai.com/v1").unwrap();

            let json = serde_json::to_string(&endpoint).unwrap();

            assert_eq!(
                serde_json::from_str::<ModelEndpoint>(&json).unwrap(),
                endpoint
            );
        }

        /// JSON holding an empty model name, or one with a newline, fails to
        /// read.
        #[test]
        fn a_stored_model_name_that_is_empty_is_refused() {
            assert!(serde_json::from_str::<ModelName>(r#""""#).is_err());
            assert!(serde_json::from_str::<ModelName>(r#""gpt\n4""#).is_err());
        }

        /// A valid model name written to JSON reads back equal.
        #[test]
        fn a_model_name_reads_back_what_it_writes() {
            let model = ModelName::new("deepseek-chat").unwrap();

            let json = serde_json::to_string(&model).unwrap();

            assert_eq!(serde_json::from_str::<ModelName>(&json).unwrap(), model);
        }
    }
}
