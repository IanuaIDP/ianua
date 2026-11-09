//! Plain code: the rules every crate keeps so it reads as a person wrote
//! it for the next person, not as generated text.
//!
//! - Names a newcomer reads at once: [`names`].
//! - Comments that earn their place: [`docs`].
//! - Nothing a draft leaves behind: [`leftovers`].
//! - Nothing public that need not be: [`reach`].
//! - The limits the compiler checks for every crate: [`lints`].
//!
//! This tool's own crate is left out: its planted breaks are written badly
//! on purpose.

pub(crate) mod docs;
pub(crate) mod leftovers;
pub(crate) mod lints;
pub(crate) mod names;
pub(crate) mod phrasing;
pub(crate) mod reach;
pub(crate) mod site;
pub(crate) mod structure;
pub(crate) mod words;

use crate::conventions::infra::source::{
    SourceFile, workspace_files, workspace_production_files, workspace_target_files,
};

/// The folder of this tool's own crate, left out of these rules.
const THIS_TOOL: &str = "ianua-audit/";

/// Every crate's source but this tool's, tests included.
fn every_file() -> Vec<SourceFile> {
    without_this_tool(workspace_files())
}

/// Every crate's code that ships, but this tool's.
fn shipping_files() -> Vec<SourceFile> {
    without_this_tool(workspace_production_files())
}

fn without_this_tool(files: Vec<SourceFile>) -> Vec<SourceFile> {
    files
        .into_iter()
        .filter(|file| !file.path.starts_with(THIS_TOOL))
        .collect()
}

/// Stops: `kept`, `registered_and_kept`, `put_in_service`: an action named
/// as the value it would return.
#[cfg_attr(test, test)]
pub(crate) fn actions_are_named_by_their_verb() {
    names::actions_named_as_results(&shipping_files()).assert_none("actions named as results");
}

/// Stops: `helper`, `ThingManager`, `let tmp`, in code that ships; a
/// test's name may speak of "the old key".
#[cfg_attr(test, test)]
pub(crate) fn names_say_what_they_are() {
    names::vague_names(&shipping_files()).assert_none("vague names");
}

/// Stops: `test_parse`, `it_works`, `works`.
#[cfg_attr(test, test)]
pub(crate) fn tests_say_what_they_show() {
    names::tests_named_vaguely(&every_file()).assert_none("tests named vaguely");
}

/// Stops: "Its id." on `id`.
#[cfg_attr(test, test)]
pub(crate) fn comments_say_what_names_do_not() {
    docs::comments_restating_names(&every_file()).assert_none("comments restating names");
}

/// Stops: fifteen lines under `# Errors`.
#[cfg_attr(test, test)]
pub(crate) fn error_lists_stay_short() {
    docs::long_error_lists(&every_file()).assert_none("long error lists");
}

/// Stops: "This function simply leverages…".
#[cfg_attr(test, test)]
pub(crate) fn comments_hold_no_filler() {
    docs::filler_phrases(&every_file()).assert_none("filler in comments");
}

/// Stops: `saved_with_provenance_and_recorded_again`, in code that ships.
#[cfg_attr(test, test)]
pub(crate) fn names_stay_short() {
    names::long_names(&shipping_files()).assert_none("long names");
}

/// Stops: a private function that only hands its arguments to another.
#[cfg_attr(test, test)]
pub(crate) fn no_function_is_a_second_name() {
    names::pass_through_functions(&shipping_files()).assert_none("pass-through functions");
}

/// Stops: "Represents a…", "Handles…", "Ensures that…", curly quotes, a
/// doc comment far longer than its code, and code left in a comment.
#[cfg_attr(test, test)]
pub(crate) fn comments_are_phrased_plainly() {
    let files = every_file();
    let mut found = phrasing::stock_openers(&files);
    found.extend(phrasing::curly_quotes(&files));
    found.extend(phrasing::comments_longer_than_code(&files));
    found.extend(phrasing::commented_out_code(&files));
    found.assert_none("comments phrased badly");
}

/// Stops: "previously", "no longer", "this change" in a comment: history
/// instead of what the code is.
#[cfg_attr(test, test)]
pub(crate) fn comments_say_what_is_not_what_was() {
    phrasing::history_in_comments(&every_file()).assert_none("history in comments");
}

/// Stops: filler, history and curly quotes on the docs site.
#[cfg_attr(test, test)]
pub(crate) fn the_docs_site_is_plain() {
    site::padded_pages(&site::pages()).assert_none("padded docs pages");
}

/// Stops: two functions alike but for a value, a trait with one
/// implementation and no stand-in, a one-line private function called
/// once.
#[cfg_attr(test, test)]
pub(crate) fn code_is_cut_where_it_helps() {
    let shipping = shipping_files();
    let mut found = structure::copied_functions(&shipping);
    found.extend(structure::single_implementation_traits(
        &shipping,
        &every_file(),
    ));
    found.extend(structure::tiny_functions_used_once(&shipping));
    found.assert_none("code cut badly");
}

/// Stops: one label opening hundreds of comments, such as `Stops:`.
#[cfg_attr(test, test)]
pub(crate) fn comments_follow_no_formula() {
    structure::formula_openers(&every_file()).assert_none("formula openers");
}

/// The planted crate the structure rules are tried on.
fn structure_planted() -> String {
    let body = "let mut total = 0; let mut heavy = 0; for item in items { if *item > 10 { total += item * 3; heavy += 1; } else { total += item; } } if heavy > 2 { total += heavy * 5; } total";
    let formula: String = (0..=100)
        .map(|n| format!("/// Stops: case {n}.\nconst C{n}: u32 = {n};\n\n"))
        .collect();
    format!(
        "fn weigh(items: &[u32]) -> u32 {{ {body} }}\n\n\
         fn weigh_more(items: &[u32]) -> u32 {{ {} }}\n\n\
         trait Weighs {{ fn weight(&self) -> u32; }}\n\
         struct Parcel;\n\
         impl Weighs for Parcel {{ fn weight(&self) -> u32 {{ twice(1) }} }}\n\n\
         fn twice(value: u32) -> u32 {{ value * 2 }}\n\n\
         // The parcel previously weighed more.\n\
         {formula}",
        body.replace('3', "4")
    )
}

/// A planted crate with two functions alike but for a number, a trait with
/// one implementation beside it, a one-line function called once, a
/// comment saying "previously", a hundred and one comments opening
/// `Stops:`, and a docs page saying "simply". Each rule names its own.
#[cfg_attr(test, test)]
pub(crate) fn the_structure_rules_find_their_planted_breaks() {
    let files = [SourceFile::planted(
        "plain/src/lib.rs",
        &structure_planted(),
    )];
    let page = site::Page {
        path: "guides/weighing.mdx".to_owned(),
        text: "Weighing is simply counting.\n".to_owned(),
    };

    let copied = structure::copied_functions(&files);
    let single = structure::single_implementation_traits(&files, &files);
    let tiny = structure::tiny_functions_used_once(&files);
    let history = phrasing::history_in_comments(&files);
    let formulas = structure::formula_openers(&files);
    let padded = site::padded_pages(&[page]);

    assert!(
        copied.lines()[0].contains("`weigh_more`"),
        "{:?}",
        copied.lines()
    );
    assert!(single.lines()[0].contains("`Weighs`"));
    assert!(tiny.lines()[0].contains("`twice`"));
    assert!(history.lines()[0].contains("\"previously\""));
    assert_eq!(formulas.lines().len(), 101);
    assert!(formulas.lines()[0].contains("opens 101 comments"));
    assert!(padded.lines()[0].contains("\"simply\""));
}

/// Stops: a library's `pub fn` that only its own crate calls.
#[cfg_attr(test, test)]
pub(crate) fn public_items_are_used_outside_their_crate() {
    let mut readers = every_file();
    readers.extend(workspace_target_files());
    reach::public_items_used_only_inside(&shipping_files(), &readers)
        .assert_none("public without need");
}

/// Stops: a crate that does not take the workspace's lints, and so slips
/// past the limits on length, inputs, `unwrap` and visibility.
#[cfg_attr(test, test)]
pub(crate) fn every_crate_takes_the_shared_lints() {
    lints::crates_without_shared_lints(&lints::manifests()).assert_none("crates without lints");
}

/// Two planted libraries, one calling the other's `shared`, so handed its
/// `Weight` unspelled, but not its `own_step`, and two manifests, one
/// without `[lints]`. Each rule names its own.
#[cfg_attr(test, test)]
pub(crate) fn the_reach_rules_find_their_planted_breaks() {
    let library = SourceFile::planted(
        "weights/src/lib.rs",
        "pub fn shared() -> Weight { Weight(own_step()) }\n\npub fn own_step() -> u32 { 1 }\n\n\
         pub struct Weight(u32);\n",
    );
    let caller = SourceFile::planted(
        "parcels/src/lib.rs",
        "fn total() -> u32 { weights::shared() }\n",
    );
    let files = [library, caller];
    let manifests = [
        lints::Manifest {
            path: "crates/weights/Cargo.toml".to_owned(),
            text: "[package]\nname = \"weights\"\n\n[lints]\nworkspace = true\n".to_owned(),
        },
        lints::Manifest {
            path: "crates/parcels/Cargo.toml".to_owned(),
            text: "[package]\nname = \"parcels\"\n".to_owned(),
        },
    ];

    let reach = reach::public_items_used_only_inside(&files, &files);
    let missing = lints::crates_without_shared_lints(&manifests);

    assert_eq!(reach.lines().len(), 1, "{:?}", reach.lines());
    assert!(reach.lines()[0].contains("`own_step`"));
    assert_eq!(missing.lines().len(), 1, "{:?}", missing.lines());
    assert!(missing.lines()[0].starts_with("crates/parcels/"));
}

/// Stops: `todo!()` in code that ships, a `TODO` note, an emoji.
#[cfg_attr(test, test)]
pub(crate) fn drafts_leave_nothing_behind() {
    let mut found = leftovers::placeholder_macros(&shipping_files());
    found.extend(leftovers::notes_left_behind(&every_file()));
    found.extend(leftovers::emoji(&every_file()));
    found.assert_none("left behind");
}

/// A planted file with each break: an action named `kept`, a `helper`, a
/// `tmp`, a test called `test_parse`, "Its id.", a long error list,
/// "simply", a `todo!()` and a `TODO`. Each rule names its own.
#[cfg_attr(test, test)]
pub(crate) fn the_plain_code_rules_find_their_planted_breaks() {
    let files = [SourceFile::planted("plain/src/lib.rs", &plain_planted())];

    let actions = names::actions_named_as_results(&files);
    let vague = names::vague_names(&files);
    let tests = names::tests_named_vaguely(&files);
    let restating = docs::comments_restating_names(&files);
    let long = docs::long_error_lists(&files);
    let filler = docs::filler_phrases(&files);
    let placeholders = leftovers::placeholder_macros(&files);
    let notes = leftovers::notes_left_behind(&files);

    assert!(
        actions.lines()[0].contains("`kept`"),
        "{:?}",
        actions.lines()
    );
    assert_eq!(vague.lines().len(), 2, "{:?}", vague.lines());
    assert!(tests.lines()[0].contains("`test_parse`"));
    assert!(restating.lines()[0].contains("`id`"));
    assert!(long.lines()[0].contains("6 cases"));
    assert!(filler.lines()[0].contains("\"this function\""));
    assert!(placeholders.lines()[0].contains("todo!("));
    assert!(notes.lines()[0].contains("`TODO`"));
    assert_wording_breaks_found(&files);
}

/// The planted file the plain-code rules are tried on.
fn plain_planted() -> String {
    let errors: String = (1..=6).map(|n| format!("/// - case {n}\n")).collect();
    format!(
        "pub struct Key {{\n    /// Its id.\n    pub id: u32,\n}}\n\n\
         pub fn kept(store: &mut Vec<u32>) {{ let tmp = 1; store.push(tmp); }}\n\n\
         pub fn helper() -> u32 {{ 1 }}\n\n\
         /// This function simply saves.\n///\n/// # Errors\n///\n{errors}\
         pub fn save() -> Result<(), ()> {{ todo!() }}\n\n\
         // TODO: finish\n\
         #[test]\nfn test_parse() {{}}\n\n\
         /// Represents a store \u{2019}s rows.\n\
         pub fn saves_and_checks_and_records_the_row_again() {{}}\n\n\
         fn sum_of(left: u32, right: u32) -> u32 {{ add(left, right) }}\n\n\
         // let total = sum_of(1, 2);\n"
    )
}

/// The long name, the pass-through function, the stock opener, the curly
/// quote and the commented-out code planted in `files` are each found.
fn assert_wording_breaks_found(files: &[SourceFile]) {
    let long = names::long_names(files);
    let second_names = names::pass_through_functions(files);
    let openers = phrasing::stock_openers(files);
    let curly = phrasing::curly_quotes(files);
    let code = phrasing::commented_out_code(files);
    assert!(
        long.lines()[0].contains("takes 8 words"),
        "{:?}",
        long.lines()
    );
    assert!(second_names.lines()[0].contains("`sum_of`"));
    assert!(openers.lines()[0].contains("\"represents\""));
    assert_eq!(curly.lines().len(), 1);
    assert_eq!(code.lines().len(), 1);
}
