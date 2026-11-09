//! GitLab's repositories, through the GitLab integration's own steps: a
//! file is read at a ref with the commit the ref pointed to (`get-file`),
//! and each pushed file is made or replaced as a commit of its own
//! (`get-file` on the branch to tell which, then `create-file` or
//! `update-file`). GitLab's writes name no commit, so the commit pushed is
//! the one the branch points to after the last write (`get-commit`).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_app::ports::workflows::{FileAt, Push, PushedFile, RepositoryRefusal};
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::sandbox::source::{CommitSha, RepositoryPath};
use ianua_domain::types::ActionClass;

use crate::integrations::repositories::calls::{Calls, Input, Step, decoded, text_at, unexpected};

/// The key GitLab's integration is installed under.
pub(super) const KEY: &str = "gitlab";

/// The text of the file `at` names and the commit it was read at.
///
/// # Errors
///
/// The [`RepositoryRefusal`] a call answered with, or
/// [`RepositoryRefusal::Refused`] when the answer is no text file.
pub(super) async fn read(
    calls: &mut Calls<'_>,
    at: &FileAt,
) -> Result<(String, CommitSha), RepositoryRefusal> {
    let file = file_at(calls, at.repository.as_str(), &at.path, at.at.as_str()).await?;
    let Some(encoded) = text_at(&file, "content") else {
        return Err(RepositoryRefusal::NotFound);
    };
    Ok((decoded(encoded)?, commit_in(&file, "commit_id")?))
}

/// Makes or replaces each of `push`'s files in its folder on its branch;
/// the commit the branch points to after the last.
///
/// # Errors
///
/// The [`RepositoryRefusal`] a call answered with. Files written before a
/// refusal stay written.
pub(super) async fn push(
    calls: &mut Calls<'_>,
    push: &Push,
) -> Result<CommitSha, RepositoryRefusal> {
    let project = push.target.repository.as_str();
    let branch = push.target.branch.as_str();
    for file in &push.files {
        write_file(calls, push, file).await?;
    }
    let head = calls
        .answer(Step {
            operation: "get-commit",
            class: ActionClass::Read,
            inputs: vec![Input::new("project", project), Input::new("ref", branch)],
        })
        .await?;
    commit_in(&head, "id")
}

/// Chooses create or update from the branch's current file before writing it.
async fn write_file(
    calls: &mut Calls<'_>,
    push: &Push,
    file: &PushedFile,
) -> Result<(), RepositoryRefusal> {
    let project = push.target.repository.as_str();
    let branch = push.target.branch.as_str();
    let path = format!("{}/{}", push.target.folder.as_str(), file.name.as_str());
    let path = RepositoryPath::new(path).map_err(|_| unexpected("the file's path is too long"))?;
    let operation = match file_at(calls, project, &path, branch).await {
        Ok(_) => "update-file",
        Err(RepositoryRefusal::NotFound) => "create-file",
        Err(refused) => return Err(refused),
    };
    calls
        .answer(Step {
            operation,
            class: ActionClass::Write,
            inputs: vec![
                Input::new("project", project),
                Input::new("path", path.as_str()),
                Input::new("branch", branch),
                Input::new("content", STANDARD.encode(file.content.as_bytes())),
                Input::new("message", push.message.as_str()),
            ],
        })
        .await?;
    Ok(())
}

/// GitLab's answer for the file at `path` of `project` at `reference`.
async fn file_at(
    calls: &mut Calls<'_>,
    project: &str,
    path: &RepositoryPath,
    reference: &str,
) -> Result<FlowData, RepositoryRefusal> {
    calls
        .answer(Step {
            operation: "get-file",
            class: ActionClass::Read,
            inputs: vec![
                Input::new("project", project),
                Input::new("path", path.as_str()),
                Input::new("ref", reference),
            ],
        })
        .await
}

/// The commit at `path` of `answer`.
fn commit_in(answer: &FlowData, path: &str) -> Result<CommitSha, RepositoryRefusal> {
    text_at(answer, path)
        .and_then(|sha| CommitSha::new(sha).ok())
        .ok_or_else(|| unexpected("GitLab's answer names no commit"))
}
