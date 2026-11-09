//! The files a version is pushed as, and how a repository's refusal is
//! told: the code under the name its language runs it by, and its pinned
//! packages as the language's own manifest, so the copy in git can be read
//! and installed by anyone.

use ianua_domain::domains::workflows::sandbox::recipe::{CodeProgram, Program};
use ianua_domain::domains::workflows::sandbox::runtime::Language;
use ianua_domain::domains::workflows::sandbox::source::RepositoryPath;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use serde_json::{Map, Value};

use crate::error::AppError;
use crate::ports::workflows::{PushedFile, RepositoryRefusal};

/// The files `program` is pushed as, under the names its runtime's
/// language runs them by.
///
/// # Errors
///
/// - `AppError::Domain` when it is a company's image, which holds no code.
/// - `AppError::Internal` when a file's name is not one a repository takes,
///   which these fixed names always are.
pub(in crate::use_cases::workflows::sandboxes) fn version_files(
    program: &Program,
) -> Result<Vec<PushedFile>, AppError> {
    let Program::Code(code) = program else {
        return Err(no_code());
    };
    let (code_name, manifest_name, manifest) = match code.runtime().language() {
        Language::Python => ("main.py", "requirements.txt", requirements(code)),
        Language::JavaScript => ("main.js", "package.json", package_json(code)),
    };
    Ok(vec![
        PushedFile {
            name: file_name(code_name)?,
            content: code.code().as_str().to_owned(),
        },
        PushedFile {
            name: file_name(manifest_name)?,
            content: manifest,
        },
    ])
}

/// The refusal of code work on a sandbox of a company's image, which
/// holds no code to write, import or push.
pub(in crate::use_cases::workflows::sandboxes) fn no_code() -> AppError {
    AppError::from_domain(DomainError::invalid(message!(
        "workflows-an-image-sandbox-holds-no-code",
        "a sandbox of the company's own image holds no code to write or push"
    )))
}

/// How a repository refusing is told to the person.
pub(in crate::use_cases::workflows::sandboxes) fn refused(refusal: RepositoryRefusal) -> AppError {
    match refusal {
        RepositoryRefusal::NotOffered => AppError::from_domain(DomainError::invalid(message!(
            "workflows-this-integration-keeps-no-code",
            "this integration keeps no code repositories; pick GitHub or GitLab"
        ))),
        RepositoryRefusal::NotFound => AppError::NotFound(message!(
            "workflows-repository-file",
            "repository, file or branch"
        )),
        RepositoryRefusal::Refused(_) | RepositoryRefusal::Unreachable(_) => {
            AppError::upstream(refusal)
        }
    }
}

/// The pinned packages as pip's requirements, one `name==version` a line,
/// under a comment saying where they came from. The comment keeps a version
/// pinning nothing from writing an empty file, which a service takes as
/// content missing, while still replacing pins pushed before.
fn requirements(code: &CodeProgram) -> String {
    let pins: String = code
        .packages()
        .as_slice()
        .iter()
        .map(|package| {
            format!(
                "{}=={}\n",
                package.name().as_str(),
                package.version().as_str()
            )
        })
        .collect();
    format!("{REQUIREMENTS_HEADER}{pins}")
}

/// The line every pushed `requirements.txt` starts with.
const REQUIREMENTS_HEADER: &str = "# Packages pinned by the sandbox version.\n";

/// The pinned packages as an npm manifest's exact dependencies.
fn package_json(code: &CodeProgram) -> String {
    let dependencies: Map<String, Value> = code
        .packages()
        .as_slice()
        .iter()
        .map(|package| {
            (
                package.name().as_str().to_owned(),
                Value::String(package.version().as_str().to_owned()),
            )
        })
        .collect();
    let manifest = serde_json::json!({ "private": true, "dependencies": dependencies });
    format!("{manifest:#}\n")
}

/// The fixed file name `name`.
fn file_name(name: &str) -> Result<RepositoryPath, AppError> {
    RepositoryPath::new(name).map_err(|_| AppError::internal_msg("a fixed file name was refused"))
}
