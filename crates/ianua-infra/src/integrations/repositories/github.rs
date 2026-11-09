//! GitHub's repositories, through the GitHub integration's own steps: a
//! file is read at the commit its ref points to (`get-commit`, then
//! `get-file` at that commit), and each pushed file is written as a commit
//! of its own (`get-file` on the branch for the version it replaces, then
//! `put-file`).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_app::ports::workflows::{FileAt, Push, PushedFile, RepositoryRefusal};
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::sandbox::source::{
    CommitSha, RepositoryName, RepositoryPath,
};
use ianua_domain::types::ActionClass;

use crate::integrations::repositories::calls::{Calls, Input, Step, decoded, text_at, unexpected};

/// The key GitHub's integration is installed under.
pub(super) const KEY: &str = "github";

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
    let commit = commit_of(calls, &at.repository, at.at.as_str()).await?;
    let file = calls
        .answer(Step {
            operation: "get-file",
            class: ActionClass::Read,
            inputs: vec![
                Input::new("repository", at.repository.as_str()),
                Input::new("path", at.path.as_str()),
                Input::new("ref", commit.as_str()),
            ],
        })
        .await?;
    let Some(encoded) = text_at(&file, "content") else {
        return Err(RepositoryRefusal::NotFound);
    };
    Ok((decoded(encoded)?, commit))
}

/// Writes each of `push`'s files to its folder on its branch; the commit
/// the last one became.
///
/// # Errors
///
/// The [`RepositoryRefusal`] a call answered with. Files written before a
/// refusal stay written.
pub(super) async fn push(
    calls: &mut Calls<'_>,
    push: &Push,
) -> Result<CommitSha, RepositoryRefusal> {
    let mut last = None;
    for file in &push.files {
        last = Some(write_file(calls, push, file).await?);
    }
    last.ok_or_else(|| unexpected("a push names no files"))
}

/// Replaces one branch file using its current version and returns the new commit.
async fn write_file(
    calls: &mut Calls<'_>,
    push: &Push,
    file: &PushedFile,
) -> Result<CommitSha, RepositoryRefusal> {
    let path = format!("{}/{}", push.target.folder.as_str(), file.name.as_str());
    let path = RepositoryPath::new(path).map_err(|_| unexpected("the file's path is too long"))?;
    let replaces = version_on(
        calls,
        &push.target.repository,
        &path,
        push.target.branch.as_str(),
    )
    .await?;
    let mut inputs = vec![
        Input::new("repository", push.target.repository.as_str()),
        Input::new("path", path.as_str()),
        Input::new("message", push.message.as_str()),
        Input::new("content", STANDARD.encode(file.content.as_bytes())),
        Input::new("branch", push.target.branch.as_str()),
    ];
    inputs.extend(replaces.map(|version| Input::new("replaces", version)));
    let written = calls
        .answer(Step {
            operation: "put-file",
            class: ActionClass::Write,
            inputs,
        })
        .await?;
    commit_in(&written, "commit.sha")
}

/// The commit `reference` of `repository` points to now.
async fn commit_of(
    calls: &mut Calls<'_>,
    repository: &RepositoryName,
    reference: &str,
) -> Result<CommitSha, RepositoryRefusal> {
    let commit = calls
        .answer(Step {
            operation: "get-commit",
            class: ActionClass::Read,
            inputs: vec![
                Input::new("repository", repository.as_str()),
                Input::new("ref", reference),
            ],
        })
        .await?;
    commit_in(&commit, "sha")
}

/// The version of the file at `path` on `branch` a write replaces, or none
/// when there is no such file yet.
async fn version_on(
    calls: &mut Calls<'_>,
    repository: &RepositoryName,
    path: &RepositoryPath,
    branch: &str,
) -> Result<Option<String>, RepositoryRefusal> {
    let read = calls
        .answer(Step {
            operation: "get-file",
            class: ActionClass::Read,
            inputs: vec![
                Input::new("repository", repository.as_str()),
                Input::new("path", path.as_str()),
                Input::new("ref", branch),
            ],
        })
        .await;
    match read {
        Ok(file) => Ok(text_at(&file, "sha").map(str::to_owned)),
        Err(RepositoryRefusal::NotFound) => Ok(None),
        Err(refused) => Err(refused),
    }
}

/// The commit at `path` of `answer`.
fn commit_in(answer: &FlowData, path: &str) -> Result<CommitSha, RepositoryRefusal> {
    text_at(answer, path)
        .and_then(|sha| CommitSha::new(sha).ok())
        .ok_or_else(|| unexpected("GitHub's answer names no commit"))
}
