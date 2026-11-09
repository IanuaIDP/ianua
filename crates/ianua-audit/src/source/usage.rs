//! What a file names and calls, read from its syntax and from the tokens of
//! the macros in it, whose insides the parser does not see.

use std::collections::BTreeMap;
use std::str::FromStr;

use proc_macro2::{Delimiter, Ident, Literal, Spacing, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Expr, ExprCall, ExprMethodCall, ExprStruct, File, ImplItemFn, ItemFn, LitStr, Macro,
    TraitItemFn,
};

use crate::source::syntax::line_of;

/// A name written somewhere, with where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Mention {
    /// The name, or the text of a string literal.
    pub(crate) name: String,
    /// The 1-based line.
    pub(crate) line: usize,
    /// The function it is written in, if any.
    pub(crate) within: Option<String>,
}

/// `Owner::name` written somewhere: a path of two segments in a row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pair {
    /// The first segment, such as `MessagingAction`.
    pub(crate) owner: String,
    /// The segment after it, such as `Delete`.
    pub(crate) name: String,
    /// The 1-based line.
    pub(crate) line: usize,
    /// The function it is written in, if any.
    pub(crate) within: Option<String>,
    /// The innermost macro it is written in, if any.
    pub(crate) in_macro: Option<String>,
}

/// A struct written out with its fields, such as `Ports { a, b: c }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StructLiteral {
    /// The struct's last name.
    pub(crate) name: String,
    /// The path it is written with, the name last, such as
    /// `["topics", "CreatePorts"]`; inside a macro, at most the segment
    /// before the name is read.
    pub(crate) path: Vec<String>,
    /// The fields set.
    pub(crate) fields: Vec<String>,
    /// Whether it ends in `..rest`, which sets every other field.
    pub(crate) has_rest: bool,
    /// The 1-based line.
    pub(crate) line: usize,
}

/// What a file names and calls outside its tests.
#[derive(Debug, Default)]
pub(crate) struct Usage {
    /// Every identifier, with the first line it is on.
    pub(crate) idents: BTreeMap<String, usize>,
    /// Every `A::B` written.
    pub(crate) pairs: Vec<Pair>,
    /// Every `.method(` called.
    pub(crate) method_calls: Vec<Mention>,
    /// Every `name(` called as a function, by the path's last name.
    pub(crate) fn_calls: Vec<Mention>,
    /// Every struct written out with its fields.
    pub(crate) struct_literals: Vec<StructLiteral>,
    /// Every string literal.
    pub(crate) strings: Vec<Mention>,
    /// Names imported under another name, as `alias => name`, from
    /// `use path::Name as Alias`.
    pub(crate) aliases: BTreeMap<String, String>,
}

impl Usage {
    /// What a parsed file names and calls.
    pub(crate) fn of_file(file: &File) -> Self {
        let mut collector = Collector::default();
        collector.visit_file(file);
        collector.usage
    }

    /// What a file that does not parse names, read from its tokens, or from
    /// its words when it does not even split into tokens.
    pub(crate) fn of_text(text: &str) -> Self {
        let mut collector = Collector::default();
        match TokenStream::from_str(text) {
            Ok(stream) => collector.tokens(stream),
            Err(_) => collector.words(text),
        }
        collector.usage
    }

    /// The name `written` stands for: what it was imported as, or itself.
    pub(crate) fn unaliased<'a>(&'a self, written: &'a str) -> &'a str {
        self.aliases.get(written).map_or(written, String::as_str)
    }
}

#[derive(Default)]
struct Collector {
    usage: Usage,
    functions: Vec<String>,
    macros: Vec<String>,
}

impl Collector {
    fn within(&self) -> Option<String> {
        self.functions.last().cloned()
    }

    fn ident(&mut self, ident: &Ident) {
        self.usage
            .idents
            .entry(ident.to_string())
            .or_insert_with(|| line_of(ident));
    }

    fn pair(&mut self, owner: String, name: String, line: usize) {
        self.usage.pairs.push(Pair {
            owner,
            name,
            line,
            within: self.within(),
            in_macro: self.macros.last().cloned(),
        });
    }

    fn method(&mut self, name: String, line: usize) {
        let within = self.within();
        self.usage.method_calls.push(Mention { name, line, within });
    }

    fn function_call(&mut self, name: String, line: usize) {
        let within = self.within();
        self.usage.fn_calls.push(Mention { name, line, within });
    }

    fn string(&mut self, value: String, line: usize) {
        let within = self.within();
        self.usage.strings.push(Mention {
            name: value,
            line,
            within,
        });
    }

    fn in_function(&mut self, name: &Ident, walk: impl FnOnce(&mut Self)) {
        self.functions.push(name.to_string());
        walk(self);
        self.functions.pop();
    }

    fn tokens(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        for (index, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Ident(ident) => self.ident_token(&trees, index, ident),
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Literal(literal) => self.literal(literal),
                TokenTree::Punct(_) => {}
            }
        }
    }

    fn ident_token(&mut self, trees: &[TokenTree], index: usize, ident: &Ident) {
        self.ident(ident);
        let line = line_of(ident);
        if let Some(name) = path_continuation(trees, index) {
            self.pair(ident.to_string(), name, line);
        }
        if opens(trees.get(index + 1), Delimiter::Parenthesis) {
            match follows_a_dot(trees, index) {
                true => self.method(ident.to_string(), line),
                false => self.function_call(ident.to_string(), line),
            }
        }
        if let Some(literal) = struct_literal_at(trees, index, ident) {
            self.usage.struct_literals.push(literal);
        }
    }

    fn literal(&mut self, literal: &Literal) {
        let text = literal.to_string();
        if !text.starts_with('"') {
            return;
        }
        if let Ok(parsed) = syn::parse_str::<LitStr>(&text) {
            self.string(parsed.value(), literal.span().start().line);
        }
    }

    fn words(&mut self, text: &str) {
        for (index, line) in text.lines().enumerate() {
            for word in line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
                let starts_well = word
                    .chars()
                    .next()
                    .is_some_and(|first| first.is_alphabetic() || first == '_');
                if starts_well {
                    self.usage
                        .idents
                        .entry(word.to_owned())
                        .or_insert(index + 1);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.in_function(&item.sig.ident, |this| visit::visit_item_fn(this, item));
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.in_function(&item.sig.ident, |this| {
            visit::visit_impl_item_fn(this, item);
        });
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        self.in_function(&item.sig.ident, |this| {
            visit::visit_trait_item_fn(this, item);
        });
    }

    fn visit_ident(&mut self, ident: &'ast Ident) {
        self.ident(ident);
    }

    fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
        self.usage
            .aliases
            .insert(rename.rename.to_string(), rename.ident.to_string());
        visit::visit_use_rename(self, rename);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<&syn::PathSegment> = path.segments.iter().collect();
        for window in segments.windows(2) {
            self.pair(
                window[0].ident.to_string(),
                window[1].ident.to_string(),
                line_of(&window[1].ident),
            );
        }
        visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        self.method(call.method.to_string(), line_of(&call.method));
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(path) = call.func.as_ref()
            && let Some(last) = path.path.segments.last()
        {
            self.function_call(last.ident.to_string(), line_of(&last.ident));
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_struct(&mut self, literal: &'ast ExprStruct) {
        if let Some(last) = literal.path.segments.last() {
            self.usage.struct_literals.push(StructLiteral {
                name: last.ident.to_string(),
                path: literal
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect(),
                fields: literal
                    .fields
                    .iter()
                    .filter_map(|field| match &field.member {
                        syn::Member::Named(ident) => Some(ident.to_string()),
                        syn::Member::Unnamed(_) => None,
                    })
                    .collect(),
                has_rest: literal.rest.is_some(),
                line: line_of(&last.ident),
            });
        }
        visit::visit_expr_struct(self, literal);
    }

    fn visit_lit_str(&mut self, literal: &'ast LitStr) {
        self.string(literal.value(), literal.span().start().line);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        self.macros.push(name);
        self.tokens(mac.tokens.clone());
        self.macros.pop();
        visit::visit_macro(self, mac);
    }
}

/// The name after `ident` when the tokens read `ident :: name`.
fn path_continuation(trees: &[TokenTree], index: usize) -> Option<String> {
    let (Some(TokenTree::Punct(first)), Some(TokenTree::Punct(second))) =
        (trees.get(index + 1), trees.get(index + 2))
    else {
        return None;
    };
    let joined =
        first.as_char() == ':' && first.spacing() == Spacing::Joint && second.as_char() == ':';
    let Some(TokenTree::Ident(name)) = trees.get(index + 3) else {
        return None;
    };
    joined.then(|| name.to_string())
}

/// The name before the token at `index` when the tokens read
/// `name :: ident`.
pub(crate) fn path_head(trees: &[TokenTree], index: usize) -> Option<String> {
    let start = index.checked_sub(3)?;
    let [
        TokenTree::Ident(head),
        TokenTree::Punct(first),
        TokenTree::Punct(second),
    ] = &trees[start..index]
    else {
        return None;
    };
    let joined =
        first.as_char() == ':' && first.spacing() == Spacing::Joint && second.as_char() == ':';
    joined.then(|| head.to_string())
}

/// Whether the token at `index` comes right after a `.`.
pub(crate) fn follows_a_dot(trees: &[TokenTree], index: usize) -> bool {
    index > 0 && matches!(&trees[index - 1], TokenTree::Punct(punct) if punct.as_char() == '.')
}

/// Whether `tree` is a group in `delimiter`.
pub(crate) fn opens(tree: Option<&TokenTree>, delimiter: Delimiter) -> bool {
    matches!(tree, Some(TokenTree::Group(group)) if group.delimiter() == delimiter)
}

/// Words after which a capitalised name and a brace are a declaration, a
/// condition or a return type, not a struct written out.
const NOT_BEFORE_A_LITERAL: &[&str] = &[
    "struct", "enum", "union", "trait", "impl", "mod", "fn", "for", "where", "match", "if",
    "while", "in", "dyn",
];

/// The struct written out at `index`, when the tokens read `Name { .. }`.
pub(crate) fn struct_literal_at(
    trees: &[TokenTree],
    index: usize,
    ident: &Ident,
) -> Option<StructLiteral> {
    let name = ident.to_string();
    if !name.starts_with(|c: char| c.is_ascii_uppercase()) {
        return None;
    }
    let Some(TokenTree::Group(group)) = trees.get(index + 1) else {
        return None;
    };
    if group.delimiter() != Delimiter::Brace || declared_or_returned(trees, index) {
        return None;
    }
    let (fields, has_rest) = literal_fields(group.stream());
    let mut path: Vec<String> = path_head(trees, index).into_iter().collect();
    path.push(name.clone());
    Some(StructLiteral {
        name,
        path,
        fields,
        has_rest,
        line: line_of(ident),
    })
}

fn declared_or_returned(trees: &[TokenTree], index: usize) -> bool {
    let Some(before) = index.checked_sub(1).map(|at| &trees[at]) else {
        return false;
    };
    match before {
        TokenTree::Ident(word) => NOT_BEFORE_A_LITERAL.contains(&word.to_string().as_str()),
        TokenTree::Punct(punct) => punct.as_char() == '>',
        _ => false,
    }
}

/// The field names a brace group sets, and whether it ends in `..rest`.
fn literal_fields(stream: TokenStream) -> (Vec<String>, bool) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let mut fields = Vec::new();
    let mut has_rest = false;
    for segment in trees.split(|tree| matches!(tree, TokenTree::Punct(p) if p.as_char() == ',')) {
        match segment {
            [TokenTree::Punct(dot), ..] if dot.as_char() == '.' => has_rest = true,
            [TokenTree::Ident(name)] => fields.push(name.to_string()),
            [TokenTree::Ident(name), TokenTree::Punct(colon), ..]
                if colon.as_char() == ':' && colon.spacing() == Spacing::Alone =>
            {
                fields.push(name.to_string());
            }
            _ => {}
        }
    }
    (fields, has_rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(text: &str) -> Usage {
        Usage::of_file(&syn::parse_file(text).unwrap())
    }

    #[test]
    fn a_path_inside_a_macro_is_a_pair() {
        let found = usage("fn f() -> bool { matches!(x, MessagingAction::Delete) }");

        let pair = found
            .pairs
            .iter()
            .find(|pair| pair.owner == "MessagingAction")
            .unwrap();

        assert_eq!(pair.name, "Delete");
        assert_eq!(pair.within.as_deref(), Some("f"));
        assert_eq!(pair.in_macro.as_deref(), Some("matches"));
    }

    #[test]
    fn a_struct_written_inside_a_macro_is_a_literal() {
        let found = usage("fn f() { let v = vec![Ports { a, b: c, ..rest }]; }");

        let literal = &found.struct_literals[0];

        assert_eq!(literal.name, "Ports");
        assert_eq!(literal.fields, ["a", "b"]);
        assert!(literal.has_rest);
    }

    #[test]
    fn a_struct_literal_keeps_the_path_it_is_written_with() {
        let found = usage("fn f() { let p = topics::CreatePorts { store }; }");

        assert_eq!(found.struct_literals[0].path, ["topics", "CreatePorts"]);
    }

    #[test]
    fn a_return_type_before_a_body_in_a_macro_is_no_literal() {
        let found = usage("m! { fn payload(&self) -> EventData { data() } }");

        assert!(found.struct_literals.is_empty());
    }

    #[test]
    fn a_method_call_inside_a_macro_is_seen() {
        let found = usage("fn f() { println!(\"{}\", auditor.dispatch(x)); }");

        assert!(
            found
                .method_calls
                .iter()
                .any(|call| call.name == "dispatch")
        );
    }

    #[test]
    fn a_name_imported_under_another_is_read_as_the_original() {
        let found =
            usage("use events::EnrollmentStarted as Started;\nfn f() { Started::observed(); }");

        assert_eq!(found.unaliased("Started"), "EnrollmentStarted");
        assert_eq!(found.unaliased("Other"), "Other");
    }

    #[test]
    fn string_literals_are_read_with_their_value() {
        let found = usage("const S: &[&str] = &[\"tenant.provisioned\"];");

        assert_eq!(found.strings[0].name, "tenant.provisioned");
    }

    #[test]
    fn text_that_does_not_lex_is_read_word_by_word() {
        let found = Usage::of_text("fn broken( {\nlet later_name = 1;");

        assert!(found.idents.contains_key("later_name"));
    }
}
