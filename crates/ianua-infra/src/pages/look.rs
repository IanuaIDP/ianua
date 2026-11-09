//! What a page wears: the tenant's name, logo and colours when it set them,
//! the platform's own otherwise, and its sanitized CSS.
//!
//! Colours reach the CSS only as checked hex colours, so nothing else can be
//! written into the style element through them. The tenant's CSS goes in
//! unescaped, since HTML escaping would break a `>` selector, but with every
//! `<` written as its CSS escape, so it can never close the element.

use ianua_domain::types::{HexColor, HttpsUrl, SanitizedCss};
use minijinja::context;
use minijinja::value::Value;

/// The platform's colour for buttons and links.
pub(crate) const DEFAULT_PRIMARY: &str = "#B1F15E";

/// The platform's page background.
pub(crate) const DEFAULT_BACKGROUND: &str = "#090A05";

/// Text on a light button.
const DARK_TEXT: &str = "#000000";

/// Text on a dark button.
const LIGHT_TEXT: &str = "#FFFFFF";

/// The luminance above which dark text reads better than light: where the
/// two contrast ratios meet.
const LIGHT_ENOUGH: f64 = 0.179;

/// The parts of a look a page is drawn in.
pub(crate) struct Look<'a> {
    /// The tenant's name, empty for the platform's own look.
    pub(crate) name: &'a str,
    /// The tenant's logo.
    pub(crate) logo_url: Option<&'a HttpsUrl>,
    /// The tenant's colour for buttons and links.
    pub(crate) primary: Option<&'a HexColor>,
    /// The tenant's page background.
    pub(crate) background: Option<&'a HexColor>,
    /// The tenant's sanitized CSS.
    pub(crate) custom_css: Option<&'a SanitizedCss>,
}

impl Look<'_> {
    /// The look as the layout reads it.
    pub(crate) fn value(&self) -> Value {
        let primary = self.primary.map_or(DEFAULT_PRIMARY, HexColor::as_str);
        let css = self.custom_css.map_or("", SanitizedCss::as_str);
        context! {
            name => self.name,
            logo_url => self.logo_url.map(HttpsUrl::as_str),
            primary => primary,
            on_primary => text_on(primary),
            background => self.background.map_or(DEFAULT_BACKGROUND, HexColor::as_str),
            custom_css => Value::from_safe_string(neutralize_markup(css)),
        }
    }
}

/// The text colour that reads best on `color`: dark on a light colour,
/// light on a dark one. A colour that does not parse gets dark text, as
/// the platform's own colour does.
fn text_on(color: &str) -> &'static str {
    let Some(luminance) = relative_luminance(color) else {
        return DARK_TEXT;
    };
    if luminance > LIGHT_ENOUGH {
        return DARK_TEXT;
    }
    LIGHT_TEXT
}

/// The relative luminance of the hex colour `color`, as the contrast rules
/// of WCAG define it, or `None` when it is not one.
fn relative_luminance(color: &str) -> Option<f64> {
    let [red, green, blue] = channels(color)?;
    Some(0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue))
}

/// The red, green and blue of `#RGB` or `#RRGGBB`, from 0 to 255.
fn channels(color: &str) -> Option<[u32; 3]> {
    let digits = color
        .strip_prefix('#')?
        .chars()
        .map(|c| c.to_digit(16))
        .collect::<Option<Vec<u32>>>()?;
    let width = match digits.len() {
        3 => 1,
        6 => 2,
        _ => return None,
    };
    let values: Vec<u32> = digits
        .chunks(width)
        .map(|chunk| match chunk {
            [one] => one.saturating_mul(17),
            [high, low] => high.saturating_mul(16).saturating_add(*low),
            _ => 0,
        })
        .collect();
    values.try_into().ok()
}

/// A channel from 0 to 255, as light it gives off.
fn linear(channel: u32) -> f64 {
    let share = f64::from(channel) / 255.0;
    if share <= 0.040_45 {
        return share / 12.92;
    }
    ((share + 0.055) / 1.055).powf(2.4)
}

/// CSS that cannot end the style element it is placed in: every `<` becomes
/// the CSS escape for it.
pub(crate) fn neutralize_markup(css: &str) -> String {
    css.replace('<', "\\3c ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The platform's own green and white get dark text; black and a deep
    /// blue get light text, so a button's label stays readable.
    #[test]
    fn a_button_label_contrasts_with_its_colour() {
        assert_eq!(text_on(DEFAULT_PRIMARY), DARK_TEXT);
        assert_eq!(text_on("#FFF"), DARK_TEXT);
        assert_eq!(text_on("#000000"), LIGHT_TEXT);
        assert_eq!(text_on("#1A237E"), LIGHT_TEXT);
    }

    /// Invalid hex colours have no luminance, and an invalid label colour falls
    /// back to dark text.
    #[test]
    fn a_value_that_is_not_a_colour_has_no_luminance() {
        for value in ["red", "#12", "#GGGGGG", "#FFFFFF;}body{display:none"] {
            assert!(relative_luminance(value).is_none(), "{value}");
        }
        assert_eq!(text_on("red"), DARK_TEXT);
    }

    /// Escaping CSS markup removes literal style-closing and script-opening
    /// tags from the result.
    #[test]
    fn css_cannot_close_its_style_element() {
        let css = neutralize_markup("a{}</style><script>alert(1)</script>");

        assert!(!css.contains("</style>"));
        assert!(!css.contains("<script>"));
    }
}
