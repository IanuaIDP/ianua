//! The published API contract, kept as a snapshot.
//!
//! Every client reads the OpenAPI document: the dashboard, SDKs, people
//! calling the API by hand. A field renamed, an enum value dropped or a
//! route moved breaks them, even when every test of the server still
//! passes. So the whole document is kept beside the code, and any change
//! to it fails here until it is looked at and written again with
//! `IANUA_WRITE_SNAPSHOTS=1`. A domain rename that would change the JSON
//! shows up as a change to this file, not as a broken client.

#![cfg(test)]

use std::fs;
use std::path::PathBuf;

/// Where the snapshot of `name` is kept.
fn snapshot(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/contract")
        .join(name)
}

/// Compares `document` with the snapshot `name`, or writes it when asked.
fn matches_snapshot(name: &str, document: &utoipa::openapi::OpenApi) {
    let written = document.to_pretty_json().expect("the document serializes");
    let path = snapshot(name);
    if std::env::var_os("IANUA_WRITE_SNAPSHOTS").is_some() {
        fs::create_dir_all(path.parent().expect("the snapshot sits in a folder"))
            .expect("the snapshot folder is writable");
        fs::write(&path, format!("{written}\n")).expect("the snapshot is writable");
        return;
    }
    let kept = fs::read_to_string(&path).unwrap_or_default();
    assert!(
        kept.trim_end() == written.trim_end(),
        "the published contract in {} changed; review the difference, then run again with IANUA_WRITE_SNAPSHOTS=1",
        path.display(),
    );
}

/// The public document is the one kept.
#[test]
fn the_public_contract_is_the_one_kept() {
    matches_snapshot("public.json", &ianua_api::openapi::document());
}

/// The internal listener's document is the one kept.
#[test]
fn the_internal_contract_is_the_one_kept() {
    matches_snapshot("internal.json", &ianua_api::openapi::internal_document());
}

/// A domain enum is documented with the values it takes, not as a bare
/// string: a client reading the document sees `Optional` and `Enforced`
/// for how an organization enforces single sign-on.
#[test]
fn an_enum_is_documented_with_its_values() {
    let document = ianua_api::openapi::document()
        .to_json()
        .expect("the document serializes");

    assert!(document.contains(r#""enum":["Optional","Enforced"]"#));
}
