//! A released migration never changes and is never removed.
//!
//! Someone running a released version has applied its migrations and
//! recorded each. A file changed since would stop their server at start; a
//! file removed would make an upgrade and a fresh install differ. The
//! released files are listed with the SHA-256 of their text in
//! `released-migrations.lock` beside the migrations, written by
//! `ianua-schema release`; every later change is a new file.

use std::fs;

use sha2::{Digest as _, Sha256};

use crate::conventions::infra::source::Findings;

/// The lock of released migrations, beside the migrations folder.
const LOCK: &str = "released-migrations.lock";

/// What is wrong with the released migrations the lock `text` lists, each
/// file read by `read`: changed since it was released, or gone.
pub(crate) fn broken(text: &str, read: impl Fn(&str) -> Option<Vec<u8>>) -> Findings {
    let mut found = Findings::default();
    for (at, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let line_number = at.saturating_add(1);
        let Some((digest, name)) = line.split_once("  ") else {
            found.flag_at(LOCK, line_number, "is not a digest and a file name");
            continue;
        };
        let name = name.trim();
        let Some(written) = read(name) else {
            found.flag_at(
                LOCK,
                line_number,
                format!("{name} was released and is gone"),
            );
            continue;
        };
        if digest_of(&written) != digest.trim() {
            found.flag_at(
                LOCK,
                line_number,
                format!("{name} was released and has changed since; put the change in a new file"),
            );
        }
    }
    found
}

/// The SHA-256 of `text`, in hex.
fn digest_of(text: &[u8]) -> String {
    Sha256::digest(text)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Stops: a released migration edited in place, or removed, which would
/// stop a server that applied it or leave an upgrade unlike a fresh
/// install.
#[cfg_attr(test, test)]
pub(crate) fn released_migrations_never_change() {
    let infra = crate::conventions::crate_dir("ianua-infra");
    let Ok(text) = fs::read_to_string(infra.join(LOCK)) else {
        return;
    };
    let migrations = infra.join("migrations");
    broken(&text, |name| fs::read(migrations.join(name)).ok())
        .assert_none("released migrations changed");
}

/// Pat edits a released migration and removes another; the third is kept
/// as released. The check names the two.
#[cfg_attr(test, test)]
pub(crate) fn the_released_check_finds_its_planted_break() {
    let kept = b"CREATE TABLE kept ();".to_vec();
    let text = format!(
        "# released\n{}  0001_kept.sql\n{}  0002_edited.sql\n{}  0003_gone.sql\n",
        digest_of(&kept),
        digest_of(b"CREATE TABLE edited ();"),
        digest_of(b"CREATE TABLE gone ();"),
    );
    let files = |name: &str| match name {
        "0001_kept.sql" => Some(kept.clone()),
        "0002_edited.sql" => Some(b"CREATE TABLE edited (id int);".to_vec()),
        _ => None,
    };

    let found = broken(&text, files);

    let lines = found.lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("0002_edited.sql was released and has changed since"));
    assert!(lines[1].contains("0003_gone.sql was released and is gone"));
}
