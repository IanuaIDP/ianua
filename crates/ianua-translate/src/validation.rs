//! Interpolation checks that retain data bindings without imposing English sentence structure.

use std::collections::BTreeSet;

use minijinja::Environment;

use crate::catalog::Syntax;
use crate::collect::tokens::placeholders;
use crate::error::{Error, Result};

/// Checks replacement fields or template inputs without running a translated template.
///
/// # Errors
///
/// Returns the original MiniJinja parse failure for an invalid template.
pub(crate) fn same_inputs(
    source: &str,
    translated: &str,
    syntax: Syntax,
    name: &str,
) -> Result<bool> {
    if syntax == Syntax::MiniJinja {
        return Ok(template_inputs(source, name)? == template_inputs(translated, name)?);
    }
    Ok(placeholders(source, syntax) == placeholders(translated, syntax))
}

/// Data and layout references that a localized template must retain.
#[derive(PartialEq, Eq)]
struct TemplateInputs {
    variables: BTreeSet<String>,
    outputs: BTreeSet<String>,
    layouts: BTreeSet<String>,
}

/// Parses a template and records external data, output expressions and imported layout paths.
fn template_inputs(source: &str, name: &str) -> Result<TemplateInputs> {
    let environment = Environment::new();
    let template = environment
        .template_from_named_str(name, source)
        .map_err(|source| Error::Template {
            name: name.to_owned(),
            source,
        })?;
    Ok(TemplateInputs {
        variables: template.undeclared_variables(true).into_iter().collect(),
        outputs: placeholders(source, Syntax::MiniJinja)
            .into_iter()
            .filter(|field| field.starts_with("{{"))
            .collect(),
        layouts: layouts(source),
    })
}

/// Keeps imports and inheritance fixed while allowing localized conditional prose.
fn layouts(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut rest = source;
    while let Some(start) = rest.find("{%") {
        rest = &rest[start + 2..];
        let Some(end) = rest.find("%}") else { break };
        let directive = rest[..end].trim().trim_matches('-').trim();
        if matches!(
            directive.split_whitespace().next(),
            Some("extends" | "import" | "from" | "include")
        ) {
            found.insert(directive.split_whitespace().collect::<Vec<_>>().join(" "));
        }
        rest = &rest[end + 2..];
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A translated greeting can add an optional-name condition while retaining the name output.
    #[test]
    fn language_specific_conditions_can_keep_the_same_data_inputs() {
        let source = "{% macro greeting(name) %}Hi {{ name }},{% endmacro %}";
        let target =
            "{% macro greeting(name) %}Hallo{% if name %} {{ name }}{% endif %},{% endmacro %}";
        assert!(same_inputs(source, target, Syntax::MiniJinja, "greeting/de").unwrap());
    }

    /// Translations that omit the name output or add an external input fail the input comparison.
    #[test]
    fn translated_templates_cannot_drop_outputs_or_add_external_inputs() {
        let source = "{% macro greeting(name) %}Hi {{ name }},{% endmacro %}";
        assert!(
            !same_inputs(
                source,
                "{% macro greeting(name) %}Hallo{% endmacro %}",
                Syntax::MiniJinja,
                "greeting/de"
            )
            .unwrap()
        );
        assert!(
            !same_inputs(
                "Hi {{ name }}",
                "Hallo {{ name }}{% if other %}!{% endif %}",
                Syntax::MiniJinja,
                "greeting/de"
            )
            .unwrap()
        );
    }

    /// A translated template extending a different layout fails the input comparison.
    #[test]
    fn translated_templates_retain_the_original_layout_paths() {
        let source = "{% extends \"layout.html\" %}{% block title %}Welcome{% endblock %}";
        let target = "{% extends \"other.html\" %}{% block title %}Willkommen{% endblock %}";
        assert!(!same_inputs(source, target, Syntax::MiniJinja, "page/de").unwrap());
    }

    /// An unclosed conditional makes translated-template validation return a parse error.
    #[test]
    fn translated_templates_must_parse() {
        assert!(
            same_inputs(
                "Hi {{ name }}",
                "{% if name %}Hallo {{ name }}",
                Syntax::MiniJinja,
                "greeting/de"
            )
            .is_err()
        );
    }
}
