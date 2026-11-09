//! A sandbox's code beyond the platform on the wire: the body asking the
//! tenant's model to write or fix it, the code it wrote, and the body that
//! pushes a version to a repository.

use ianua_app::use_cases::workflows::sandboxes::code::{
    PushVersionRequest, WriteRequest, Writing, WrittenCode,
};
use ianua_domain::domains::workflows::data::FieldName;
use ianua_domain::domains::workflows::sandbox::recipe::SandboxCode;
use ianua_domain::domains::workflows::sandbox::source::{GitRef, RepositoryName, RepositoryPath};
use ianua_domain::types::{
    IntegrationAccountId, ModelProviderId, SandboxId, SandboxVersionId, Text, UntrustedText,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// Request body for asking the tenant's model to write a sandbox's code.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct WriteCodeBody {
    /// The tenant's model provider the words are given to.
    pub provider_id: Uuid,
    /// What the code should do, in up to 500 characters.
    pub words: String,
    /// The names of the fields the code is handed; never their values.
    #[serde(default)]
    pub inputs: Vec<String>,
    /// The packages it may import, by name, at most 50.
    #[serde(default)]
    pub packages: Vec<String>,
    /// Code that failed when tried, for the model to fix; left out to write
    /// afresh.
    #[serde(default)]
    pub fix: Option<FixBody>,
}

/// Code that failed when tried, and what its trial said.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct FixBody {
    /// The failed source submitted to the model for correction.
    pub code: String,
    /// What the trial said, such as the end of its error.
    pub failure: String,
}

impl WriteCodeBody {
    /// Asking for code for `sandbox_id`.
    ///
    /// # Errors
    ///
    /// - `422` when the words, an input's name or the code to fix are not
    ///   valid.
    pub(crate) fn request(self, sandbox_id: SandboxId) -> Result<WriteRequest, ApiError> {
        let inputs = self
            .inputs
            .iter()
            .map(|name| FieldName::new(name).map_err(ApiError::validation))
            .collect::<Result<Vec<_>, _>>()?;
        let writing = match self.fix {
            None => Writing::Fresh,
            Some(fix) => Writing::Fix {
                code: SandboxCode::new(fix.code).map_err(ApiError::validation)?,
                failure: UntrustedText::record(&fix.failure),
            },
        };
        Ok(WriteRequest {
            sandbox_id,
            provider_id: ModelProviderId::from_uuid(self.provider_id),
            words: Text::new("words", self.words).map_err(ApiError::validation)?,
            inputs,
            packages: self.packages,
            writing,
        })
    }
}

/// Code the tenant's model wrote. Nothing is saved: save it as a version
/// and try it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct WrittenCodeResponse {
    /// The model's proposed source, ready to review and save.
    pub code: String,
    /// What it does, as the model says, in at most 600 characters.
    pub explanation: String,
}

impl From<WrittenCode> for WrittenCodeResponse {
    fn from(written: WrittenCode) -> Self {
        Self {
            code: written.code.as_str().to_owned(),
            explanation: written.explanation,
        }
    }
}

/// Request body for pushing a sandbox version to a repository.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PushVersionBody {
    /// The GitHub or GitLab account it goes through, one the caller owns or
    /// may manage.
    pub account_id: Uuid,
    /// The repository, such as `acme/web`.
    pub repository: String,
    /// The branch it goes to, such as `ianua/tidy`. It must exist.
    pub branch: String,
    /// The folder its files go in, such as `scripts/tidy`.
    pub folder: String,
}

impl PushVersionBody {
    /// Pushing version `version_id` of `sandbox_id`.
    ///
    /// # Errors
    ///
    /// - `422` when the repository, branch or folder are not valid.
    pub(crate) fn request(
        self,
        sandbox_id: SandboxId,
        version_id: SandboxVersionId,
    ) -> Result<PushVersionRequest, ApiError> {
        Ok(PushVersionRequest {
            sandbox_id,
            version_id,
            account: IntegrationAccountId::from_uuid(self.account_id),
            repository: RepositoryName::new(self.repository).map_err(ApiError::validation)?,
            branch: GitRef::new(self.branch).map_err(ApiError::validation)?,
            folder: RepositoryPath::new(self.folder).map_err(ApiError::validation)?,
        })
    }
}
