//! The plan written as the next migration files: one for every database,
//! one for the platform's alone, and a file of its own for each index made
//! concurrently, which runs outside any transaction.

use crate::plan::{Part, Plan, Running, Statement};

/// One migration file to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct File {
    /// Its name, such as `0038_pause_keys.sql`.
    pub(crate) name: String,
    /// SQL statements and explanatory comments ready to write to disk.
    pub(crate) text: String,
}

/// The files for `plan`, numbered from `next`, named after `name`.
pub(crate) fn files(plan: &Plan, next: u32, name: &str) -> Vec<File> {
    let mut files = Vec::new();
    let mut number = next;
    for part in [Part::Tenant, Part::Platform] {
        let together: Vec<&Statement> = plan
            .statements
            .iter()
            .filter(|statement| {
                statement.part == part && statement.running == Running::InTransaction
            })
            .collect();
        if !together.is_empty() {
            files.push(File {
                name: file_name(number, part, name),
                text: text_of(&together, Running::InTransaction),
            });
            number = number.saturating_add(1);
        }
        for alone in plan
            .statements
            .iter()
            .filter(|statement| statement.part == part && statement.running == Running::Alone)
        {
            files.push(File {
                name: file_name(number, part, &format!("{name}_index")),
                text: text_of(&[alone], Running::Alone),
            });
            number = number.saturating_add(1);
        }
    }
    files
}

/// The file name of migration `number` of `part`, after `name`.
fn file_name(number: u32, part: Part, name: &str) -> String {
    match part {
        Part::Tenant => format!("{number:04}_{name}.sql"),
        Part::Platform => format!("{number:04}_platform_{name}.sql"),
    }
}

/// The text of a file of `statements`, each under its note.
fn text_of(statements: &[&Statement], running: Running) -> String {
    let mut text = String::new();
    if running == Running::Alone {
        text.push_str(
            "-- no-transaction\n-- Made concurrently, outside a transaction, so the table goes on taking\n\
             -- writes while it is built.\n",
        );
    }
    for statement in statements {
        if !text.is_empty() {
            text.push('\n');
        }
        if let Some(note) = &statement.note {
            text.push_str(&commented(note));
        }
        text.push_str(&statement.sql);
        text.push('\n');
    }
    text
}

/// `note` as comment lines of at most 76 characters.
fn commented(note: &str) -> String {
    let mut lines = Vec::new();
    let mut line = String::from("--");
    for word in note.split_whitespace() {
        if line.len().saturating_add(word.len()) > 75 {
            lines.push(std::mem::replace(&mut line, String::from("--")));
        }
        line.push(' ');
        line.push_str(word);
    }
    lines.push(line);
    format!("{}\n", lines.join("\n"))
}

/// Whether `name` reads as a migration's name: lower case words joined by
/// `_`, as the house rules want.
pub(crate) fn is_a_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('_')
        && !name.ends_with('_')
        && !name.contains("__")
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::Step;

    /// A statement of `part`, run as `running`.
    fn statement(part: Part, running: Running, sql: &str) -> Statement {
        Statement {
            part,
            running,
            step: Step::AddColumn,
            note: Some("Why it is added.".to_owned()),
            sql: sql.to_owned(),
        }
    }

    /// A tenant's column, an index on it made concurrently, and a
    /// platform column.
    fn tenant_index_and_platform() -> Plan {
        Plan {
            statements: vec![
                statement(
                    Part::Tenant,
                    Running::InTransaction,
                    "ALTER TABLE notes ADD COLUMN a text;",
                ),
                statement(
                    Part::Tenant,
                    Running::Alone,
                    "CREATE INDEX CONCURRENTLY n ON notes (a);",
                ),
                statement(
                    Part::Platform,
                    Running::InTransaction,
                    "ALTER TABLE tenants ADD COLUMN b text;",
                ),
            ],
            refusals: Vec::new(),
        }
    }

    /// Tenant and platform changes go to files of their own, and each index
    /// made concurrently to its own file, run outside a transaction.
    #[test]
    fn each_part_and_each_concurrent_index_has_its_file() {
        let plan = tenant_index_and_platform();

        let files = files(&plan, 38, "notes_a");

        let names: Vec<&str> = files.iter().map(|file| file.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "0038_notes_a.sql",
                "0039_notes_a_index.sql",
                "0040_platform_notes_a.sql"
            ]
        );
        assert!(files[1].text.starts_with("-- no-transaction\n"));
        assert!(
            files[0]
                .text
                .starts_with("-- Why it is added.\nALTER TABLE notes")
        );
    }

    /// A migration's name is lower case words joined by `_`.
    #[test]
    fn a_name_is_lower_case_words() {
        assert!(is_a_name("pause_keys"));
        assert!(!is_a_name("Pause keys"));
        assert!(!is_a_name("pause__keys"));
        assert!(!is_a_name(""));
    }
}
