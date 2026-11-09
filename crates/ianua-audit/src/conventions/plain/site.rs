//! The docs site keeps the comments' rules: no filler, no history, no
//! curly quotes, outside its code examples.

use std::fs;
use std::path::{Path, PathBuf};

use crate::conventions::infra::source::Findings;
use crate::conventions::plain::docs::{FILLER, has_phrase};
use crate::conventions::plain::phrasing::history_phrase;

/// The curly quotes and apostrophes.
const CURLY: &[char] = &['\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}'];

/// One page of the docs site: where it is and what it says.
pub(crate) struct Page {
    /// Its path under the docs' content folder.
    pub path: String,
    /// Its text.
    pub text: String,
}

/// Every page of the docs site, or none where the workspace has no site.
pub(crate) fn pages() -> Vec<Page> {
    let root = crate::conventions::crate_dir("ianua-audit").join("../../docs/src/content/docs");
    let mut found = Vec::new();
    collect(&root, &root, &mut found);
    found
}

fn collect(root: &Path, dir: &Path, found: &mut Vec<Page>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect(root, &path, found);
            continue;
        }
        let is_page = path
            .extension()
            .is_some_and(|extension| extension == "md" || extension == "mdx");
        if !is_page {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let path = path
            .strip_prefix(root)
            .map(|relative| relative.to_string_lossy().into_owned())
            .unwrap_or_default();
        found.push(Page { path, text });
    }
}

/// Every line of `pages`, outside code examples, holding filler, history or
/// a curly quote.
pub(crate) fn padded_pages(pages: &[Page]) -> Findings {
    let mut found = Findings::default();
    for page in pages {
        let mut in_example = false;
        for (at, line) in page.text.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                in_example = !in_example;
                continue;
            }
            if in_example {
                continue;
            }
            let lower = line.to_lowercase();
            let filler = FILLER.iter().find(|phrase| has_phrase(&lower, phrase));
            let said = match (filler, history_phrase(line), line.contains(CURLY)) {
                (Some(phrase), _, _) => format!("\"{phrase}\" pads the page; say the thing itself"),
                (None, Some(phrase), _) => {
                    format!("\"{phrase}\" tells history; say what is so now")
                }
                (None, None, true) => "a curly quote; use ' and \"".to_owned(),
                (None, None, false) => continue,
            };
            found.flag_at(&format!("docs/{}", page.path), at.saturating_add(1), said);
        }
    }
    found
}
