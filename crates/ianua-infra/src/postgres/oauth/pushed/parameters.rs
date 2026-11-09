//! The authorization parameters a client pushed, in the shape the
//! `parameters` column keeps.

use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::oauth::grants::authorization_code::{CodeChallenge, NonceSent};
use ianua_domain::domains::oauth::grants::authorization_request::{
    AskedFlow, AskedPrompts, AskedRequest, AskedScopes, MaxAge, Prompt, RequestedAcr, ResponseMode,
};
use ianua_domain::domains::oauth::grants::pushed_request::{
    ClientState, PushedParameters, StateSent,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Nonce, RedirectUri, Scope};
use serde::{Deserialize, Serialize};

/// What a pushed request asks, as it is stored.
#[derive(Serialize, Deserialize)]
pub(super) struct StoredParameters {
    redirect_uri: RedirectUri,
    asked: StoredAsked,
    /// The longest a sign-in may be old, in seconds, or none for any age.
    max_age: Option<u32>,
    /// The `acr` value of the weakest level asked for, or none.
    acr: Option<String>,
    code_challenge: CodeChallenge,
    nonce: Option<Nonce>,
    state: Option<ClientState>,
}

/// The flow, scopes, prompts and response mode a request asked for.
#[derive(Serialize, Deserialize)]
struct StoredAsked {
    flow: StoredFlow,
    scopes: StoredScopes,
    prompts: StoredPrompts,
    response_mode: StoredResponseMode,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredFlow {
    CodeWithS256Challenge,
    NotCode,
    NoS256Challenge,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredScopes {
    Named(Vec<Scope>),
    Unreadable,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredPrompts {
    Named(Vec<StoredPrompt>),
    Unreadable,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredPrompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredResponseMode {
    Query,
    FormPost,
    Unsupported,
}

impl From<&PushedParameters> for StoredParameters {
    fn from(parameters: &PushedParameters) -> Self {
        Self {
            redirect_uri: parameters.redirect_uri.clone(),
            asked: StoredAsked::from(&parameters.asked),
            max_age: match parameters.max_age {
                MaxAge::Any => None,
                MaxAge::Seconds(seconds) => Some(seconds),
            },
            acr: match parameters.acr {
                RequestedAcr::Any => None,
                RequestedAcr::AtLeast(level) => Some(level.acr().to_owned()),
            },
            code_challenge: parameters.code_challenge.clone(),
            nonce: parameters.nonce.sent().cloned(),
            state: match &parameters.state {
                StateSent::NotSent => None,
                StateSent::Sent(state) => Some(state.clone()),
            },
        }
    }
}

impl TryFrom<StoredParameters> for PushedParameters {
    type Error = DomainError;

    fn try_from(stored: StoredParameters) -> Result<Self, DomainError> {
        Ok(Self {
            redirect_uri: stored.redirect_uri,
            asked: AskedRequest::from(stored.asked),
            max_age: stored.max_age.map_or(MaxAge::Any, MaxAge::Seconds),
            acr: acr_from(stored.acr)?,
            code_challenge: stored.code_challenge,
            nonce: NonceSent::from_stored(stored.nonce),
            state: stored.state.map_or(StateSent::NotSent, StateSent::Sent),
        })
    }
}

impl From<&AskedRequest> for StoredAsked {
    fn from(asked: &AskedRequest) -> Self {
        Self {
            flow: match asked.flow {
                AskedFlow::CodeWithS256Challenge => StoredFlow::CodeWithS256Challenge,
                AskedFlow::NotCode => StoredFlow::NotCode,
                AskedFlow::NoS256Challenge => StoredFlow::NoS256Challenge,
            },
            scopes: match &asked.scopes {
                AskedScopes::Named(scopes) => StoredScopes::Named(scopes.clone()),
                AskedScopes::Unreadable => StoredScopes::Unreadable,
            },
            prompts: match &asked.prompts {
                AskedPrompts::Named(prompts) => {
                    StoredPrompts::Named(prompts.iter().copied().map(StoredPrompt::from).collect())
                }
                AskedPrompts::Unreadable => StoredPrompts::Unreadable,
            },
            response_mode: match asked.response_mode {
                ResponseMode::Query => StoredResponseMode::Query,
                ResponseMode::FormPost => StoredResponseMode::FormPost,
                ResponseMode::Unsupported => StoredResponseMode::Unsupported,
            },
        }
    }
}

impl From<StoredAsked> for AskedRequest {
    fn from(stored: StoredAsked) -> Self {
        Self {
            flow: match stored.flow {
                StoredFlow::CodeWithS256Challenge => AskedFlow::CodeWithS256Challenge,
                StoredFlow::NotCode => AskedFlow::NotCode,
                StoredFlow::NoS256Challenge => AskedFlow::NoS256Challenge,
            },
            scopes: match stored.scopes {
                StoredScopes::Named(scopes) => AskedScopes::Named(scopes),
                StoredScopes::Unreadable => AskedScopes::Unreadable,
            },
            prompts: match stored.prompts {
                StoredPrompts::Named(prompts) => {
                    AskedPrompts::Named(prompts.into_iter().map(Prompt::from).collect())
                }
                StoredPrompts::Unreadable => AskedPrompts::Unreadable,
            },
            response_mode: match stored.response_mode {
                StoredResponseMode::Query => ResponseMode::Query,
                StoredResponseMode::FormPost => ResponseMode::FormPost,
                StoredResponseMode::Unsupported => ResponseMode::Unsupported,
            },
        }
    }
}

/// The level a stored `acr` value names.
fn acr_from(stored: Option<String>) -> Result<RequestedAcr, DomainError> {
    let Some(value) = stored else {
        return Ok(RequestedAcr::Any);
    };
    AssuranceLevel::from_acr(&value)
        .map(RequestedAcr::AtLeast)
        .ok_or_else(|| DomainError::corrupt_row("pushed authorization request", "an unknown acr"))
}

impl From<Prompt> for StoredPrompt {
    fn from(prompt: Prompt) -> Self {
        match prompt {
            Prompt::None => Self::None,
            Prompt::Login => Self::Login,
            Prompt::Consent => Self::Consent,
            Prompt::SelectAccount => Self::SelectAccount,
        }
    }
}

impl From<StoredPrompt> for Prompt {
    fn from(stored: StoredPrompt) -> Self {
        match stored {
            StoredPrompt::None => Self::None,
            StoredPrompt::Login => Self::Login,
            StoredPrompt::Consent => Self::Consent,
            StoredPrompt::SelectAccount => Self::SelectAccount,
        }
    }
}
