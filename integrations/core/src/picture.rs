//! An integration's own picture: SVG an integration carries in its
//! `assets/icon.svg`, checked to hold nothing but shapes before it is
//! offered.
//!
//! A picture is served to people's browsers, so it may hold only what draws
//! a mark: the `svg` element, a title, groups and the basic shapes, each
//! with only the attributes that place and paint them. A script, an event
//! handler, a link, a style sheet, an embedded page or picture, a document
//! type and anything else are refused, rather than cleaned out, so an
//! integration that ships one never starts.

use ianua_domain::domains::workflows::integration::profile::IntegrationPicture;
use ianua_domain::shared::errors::DomainError;
use roxmltree::{Document, Node, ParsingOptions};

/// The namespace every element of a picture is in.
const SVG_NAMESPACE: &str = "http://www.w3.org/2000/svg";

/// The elements a picture may hold.
const ELEMENTS: &[&str] = &[
    "circle", "ellipse", "g", "line", "path", "polygon", "polyline", "rect", "svg", "title",
];

/// The attributes an element of a picture may carry.
const ATTRIBUTES: &[&str] = &[
    "clip-rule",
    "cx",
    "cy",
    "d",
    "fill",
    "fill-opacity",
    "fill-rule",
    "height",
    "opacity",
    "points",
    "r",
    "role",
    "rx",
    "ry",
    "stroke",
    "stroke-linecap",
    "stroke-linejoin",
    "stroke-opacity",
    "stroke-width",
    "transform",
    "viewBox",
    "width",
    "x",
    "x1",
    "x2",
    "y",
    "y1",
    "y2",
];

/// `svg` as an integration's picture, once it holds nothing but shapes.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the picture is too large, is not
/// SVG, or holds an element or attribute beyond the shapes it may.
pub fn picture(svg: &str) -> Result<IntegrationPicture, DomainError> {
    let picture = IntegrationPicture::new(svg)?;
    let options = ParsingOptions {
        allow_dtd: false,
        ..ParsingOptions::default()
    };
    let document = Document::parse_with_options(svg, options)
        .map_err(|_| refused("the picture is not well-formed SVG"))?;
    ensure_svg_root(&document)?;
    document
        .descendants()
        .filter(Node::is_element)
        .try_for_each(ensure_only_shapes)?;
    Ok(picture)
}

/// Refuses a picture whose outermost element is not `svg`.
fn ensure_svg_root(document: &Document<'_>) -> Result<(), DomainError> {
    let root = document.root_element();
    if root.tag_name().name() == "svg" && root.tag_name().namespace() == Some(SVG_NAMESPACE) {
        return Ok(());
    }
    Err(refused(
        "the picture is not an svg element in the SVG namespace",
    ))
}

/// Refuses `element` unless it is a shape, carrying only the attributes a
/// shape may.
fn ensure_only_shapes(element: Node<'_, '_>) -> Result<(), DomainError> {
    let name = element.tag_name();
    if name.namespace() != Some(SVG_NAMESPACE) || !ELEMENTS.contains(&name.name()) {
        return Err(refused(&format!(
            "the picture holds a {} element, and may hold only shapes",
            name.name()
        )));
    }
    let foreign = element.attributes().find(|attribute| {
        attribute.namespace().is_some() || !ATTRIBUTES.contains(&attribute.name())
    });
    let Some(attribute) = foreign else {
        return Ok(());
    };
    Err(refused(&format!(
        "the picture's {} element carries {}, and may carry only what places and paints a shape",
        name.name(),
        attribute.name()
    )))
}

/// The refusal of a picture, saying why.
fn refused(why: &str) -> DomainError {
    DomainError::invalid(why.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARK: &str = r#"<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>Acme</title><path d="M0 0h24v24H0z"/></svg>"#;

    /// A mark of a title and a path is a picture.
    #[test]
    fn a_mark_of_shapes_is_a_picture() {
        assert!(picture(MARK).is_ok());
    }

    /// Scripts, event handlers, links, embedded content, styles and document
    /// types are refused, as are non-SVG roots and missing SVG namespaces.
    #[test]
    fn anything_but_shapes_is_refused() {
        let svg = r#"xmlns="http://www.w3.org/2000/svg""#;
        let refused = [
            format!(r#"<svg {svg}><script>alert(1)</script></svg>"#),
            format!(r#"<svg {svg}><path d="M0 0" onclick="alert(1)"/></svg>"#),
            format!(r#"<svg {svg} onload="alert(1)"/>"#),
            format!(
                r#"<svg {svg} xmlns:x="http://www.w3.org/1999/xlink"><a x:href="https://evil.test"><path d="M0 0"/></a></svg>"#
            ),
            format!(r#"<svg {svg}><path d="M0 0" href="https://evil.test"/></svg>"#),
            format!(r#"<svg {svg}><foreignObject><div>hi</div></foreignObject></svg>"#),
            format!(r#"<svg {svg}><image width="1" height="1"/></svg>"#),
            format!(r#"<svg {svg}><style>path{{fill:url(https://evil.test)}}</style></svg>"#),
            format!(r#"<svg {svg}><path d="M0 0" style="fill:red"/></svg>"#),
            format!(r#"<!DOCTYPE svg [<!ENTITY a "b">]><svg {svg}/>"#),
            r#"<html><body>not a picture</body></html>"#.to_owned(),
            "<svg><path d=\"M0 0\"/></svg>".to_owned(),
        ];

        for svg in refused {
            assert!(picture(&svg).is_err(), "{svg}");
        }
    }
}
