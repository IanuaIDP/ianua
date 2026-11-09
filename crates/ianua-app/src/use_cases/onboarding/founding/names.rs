//! Name normalization shared by organization and tenant founding.

/// Derives a URL-safe slug from a company name.
pub(super) fn slugify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A company name becomes a lowercase slug, its other characters
    /// turned into single hyphens.
    #[test]
    fn slugify_lowercases_and_strips_special_chars() {
        assert_eq!(slugify("Acme Corp"), "acme-corp");
        assert_eq!(slugify("My Company, Inc."), "my-company-inc");
        assert_eq!(slugify("  Spaces  Everywhere  "), "spaces-everywhere");
        assert_eq!(slugify("UPPERCASE"), "uppercase");
        assert_eq!(slugify("already-slug"), "already-slug");
    }

    /// Digits stay in a slug.
    #[test]
    fn slugify_handles_numbers() {
        assert_eq!(slugify("Company 42"), "company-42");
    }
}
