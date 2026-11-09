//! Text replacements at source positions, applied back to front so each
//! position still points where the parser saw it.

use proc_macro2::LineColumn;

/// One replacement of the source between two positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Replacement {
    /// Where the replaced text starts.
    pub(crate) start: LineColumn,
    /// Where it ends.
    pub(crate) end: LineColumn,
    /// What takes its place.
    pub(crate) text: String,
}

/// Maps the parser's line and character positions to byte offsets of one source.
pub(crate) struct Offsets<'a> {
    source: &'a str,
    line_starts: Vec<usize>,
}

impl<'a> Offsets<'a> {
    /// The offsets of `source`.
    pub(crate) fn new(source: &'a str) -> Self {
        let line_starts = std::iter::once(0)
            .chain(source.match_indices('\n').map(|(index, _)| index + 1))
            .collect();
        Self {
            source,
            line_starts,
        }
    }

    /// The byte offset of a one-based line and a column counted in characters.
    pub(crate) fn of(&self, position: LineColumn) -> Option<usize> {
        let start = *self.line_starts.get(position.line.checked_sub(1)?)?;
        let line = &self.source[start..];
        let within = line
            .char_indices()
            .map(|(index, _)| index)
            .chain(std::iter::once(line.len()))
            .nth(position.column)?;
        Some(start + within)
    }

    /// The source text between two positions.
    pub(crate) fn text(&self, start: LineColumn, end: LineColumn) -> Option<&'a str> {
        self.source.get(self.of(start)?..self.of(end)?)
    }
}

/// The source with every replacement made. Replacements that overlap one
/// already made, or point outside the source, are left out and returned.
pub(crate) fn applied(
    source: &str,
    mut replacements: Vec<Replacement>,
) -> (String, Vec<Replacement>) {
    let offsets = Offsets::new(source);
    replacements.sort_by_key(|replacement| (replacement.start.line, replacement.start.column));
    let mut result = source.to_owned();
    let mut skipped = Vec::new();
    let mut lowest_start = usize::MAX;
    for replacement in replacements.into_iter().rev() {
        let range = offsets
            .of(replacement.start)
            .zip(offsets.of(replacement.end))
            .filter(|(start, end)| start <= end && *end <= lowest_start);
        let Some((start, end)) = range else {
            skipped.push(replacement);
            continue;
        };
        result.replace_range(start..end, &replacement.text);
        lowest_start = start;
    }
    (result, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(line: usize, column: usize) -> LineColumn {
        LineColumn { line, column }
    }

    /// Columns count characters, so text after a multibyte character is found.
    #[test]
    fn columns_count_characters_not_bytes() {
        let source = "let a = \"ü\";\nlet b = \"x\";";
        let offsets = Offsets::new(source);
        assert_eq!(offsets.text(at(1, 8), at(1, 11)), Some("\"ü\""));
        assert_eq!(offsets.text(at(2, 8), at(2, 11)), Some("\"x\""));
    }

    /// Replacements on one line are all made, whatever order they come in.
    #[test]
    fn replacements_are_applied_back_to_front() {
        let source = "f(\"a\", \"b\")";
        let replacements = vec![
            Replacement {
                start: at(1, 2),
                end: at(1, 5),
                text: "A".to_owned(),
            },
            Replacement {
                start: at(1, 7),
                end: at(1, 10),
                text: "B".to_owned(),
            },
        ];
        let (result, skipped) = applied(source, replacements);
        assert_eq!(result, "f(A, B)");
        assert!(skipped.is_empty());
    }

    /// Overlapping replacements apply the inner edit and report the outer edit as skipped.
    #[test]
    fn overlapping_replacements_are_skipped() {
        let source = "f(g(\"a\"))";
        let replacements = vec![
            Replacement {
                start: at(1, 2),
                end: at(1, 8),
                text: "X".to_owned(),
            },
            Replacement {
                start: at(1, 4),
                end: at(1, 7),
                text: "Y".to_owned(),
            },
        ];
        let (result, skipped) = applied(source, replacements);
        assert_eq!(result, "f(g(Y))");
        assert_eq!(skipped.len(), 1);
    }
}
