//! How an integration presents itself to the people building workflows:
//! its name, what it is for, and the icon shown beside it.

use crate::domains::workflows::integration::IntegrationKey;
use crate::domains::workflows::integration::form::BrandColor;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{Label, Text};

text_value! {
    /// The name of the icon shown beside an integration, such as `github`.
    /// The dashboard draws the icon for the name; an unknown name gets a
    /// plain one.
    pub struct IntegrationIcon;
}

impl TextValue for IntegrationIcon {
    const FIELD: &'static str = "icon";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=64)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN)
    }
}

/// The most an integration's picture may hold: a mark of a few paths fits,
/// a drawing with pictures inside does not.
const MOST_PICTURE_BYTES: usize = 16 * 1024;

text_value! {
    /// An integration's own picture, as SVG markup drawn on a 24 by 24
    /// grid. The integration carries it, so no other part needs to know
    /// what the service looks like. The adapter that reads it checks it
    /// holds nothing but shapes; this value only bounds its size.
    pub struct IntegrationPicture;
}

impl TextValue for IntegrationPicture {
    const FIELD: &'static str = "picture";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_blank()
            .max_bytes(MOST_PICTURE_BYTES)
            .no_control_chars_but_line_breaks()
    }
}

/// How an integration is drawn for the people building workflows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrationLook {
    /// An outside service's integration carries the service's own picture.
    Picture(IntegrationPicture),
    /// A step the platform itself offers carries none: the dashboard draws
    /// it.
    BuiltIn,
}

/// The values an integration presents itself with.
pub struct IntegrationProfileParams {
    /// The key it is installed under.
    pub key: IntegrationKey,
    /// Its name for people, such as "GitHub".
    pub title: Label,
    /// What it lets a workflow do, in a sentence or two.
    pub description: Text,
    /// The icon shown beside it.
    pub icon: IntegrationIcon,
    /// How it is drawn.
    pub look: IntegrationLook,
    /// The colour its icon tile and its steps' accents are drawn in.
    pub brand: BrandColor,
}

/// How an integration presents itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationProfile {
    key: IntegrationKey,
    title: Label,
    description: Text,
    icon: IntegrationIcon,
    look: IntegrationLook,
    brand: BrandColor,
}

impl IntegrationProfile {
    /// The profile `params` describe. Each value was checked when it was
    /// made, so the profile itself cannot be refused.
    #[must_use]
    pub fn new(params: IntegrationProfileParams) -> Self {
        Self {
            key: params.key,
            title: params.title,
            description: params.description,
            icon: params.icon,
            look: params.look,
            brand: params.brand,
        }
    }

    /// The colour its icon tile and its steps' accents are drawn in.
    #[must_use]
    pub fn brand(&self) -> &BrandColor {
        &self.brand
    }

    /// The key it is installed under.
    #[must_use]
    pub fn key(&self) -> &IntegrationKey {
        &self.key
    }

    /// Its name for people.
    #[must_use]
    pub fn title(&self) -> &Label {
        &self.title
    }

    /// What it lets a workflow do.
    #[must_use]
    pub fn description(&self) -> &Text {
        &self.description
    }

    /// The icon shown beside it.
    #[must_use]
    pub fn icon(&self) -> &IntegrationIcon {
        &self.icon
    }

    /// Its own picture, or `None` for a step the platform itself offers,
    /// which the dashboard draws.
    #[must_use]
    pub fn picture(&self) -> Option<&IntegrationPicture> {
        match &self.look {
            IntegrationLook::Picture(picture) => Some(picture),
            IntegrationLook::BuiltIn => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An icon is named in lowercase letters, digits and dashes.
    #[test]
    fn an_icon_is_named_in_lowercase_words() {
        assert!(IntegrationIcon::new("github").is_ok());
        assert!(IntegrationIcon::new("google-sheets").is_ok());
    }

    /// An integration picture exceeding its byte limit is rejected, while a
    /// small SVG picture is accepted.
    #[test]
    fn a_picture_past_its_size_is_refused() {
        let huge = format!("<svg>{}</svg>", "x".repeat(MOST_PICTURE_BYTES));

        assert!(IntegrationPicture::new(huge).is_err());
        assert!(IntegrationPicture::new("<svg viewBox=\"0 0 24 24\"/>").is_ok());
    }

    /// Icon names reject paths, URLs, uppercase letters and empty strings.
    #[test]
    fn an_icon_named_by_a_path_or_address_is_refused() {
        for name in ["../logo.svg", "https://example.test/icon.png", "GitHub", ""] {
            assert!(IntegrationIcon::new(name).is_err(), "{name}");
        }
    }
}
