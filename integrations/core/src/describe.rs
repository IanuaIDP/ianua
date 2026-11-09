//! Writing an integration's profile and its operations' guides as plain
//! text, each checked as the domain checks it.

use ianua_domain::domains::workflows::data::{DataPath, FieldName};
use ianua_domain::domains::workflows::integration::form::BrandColor;
use ianua_domain::domains::workflows::integration::guide::{
    InputNote, OperationGuide, OperationGuideParams, OutputNote,
};
use ianua_domain::domains::workflows::integration::profile::{
    IntegrationIcon, IntegrationLook, IntegrationProfile, IntegrationProfileParams,
};
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationKey};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, Text};

use crate::form::{FormText, PreviewText, Suggested, input_form, preview};
use crate::picture::picture;

/// How an integration presents itself, as text.
pub struct ProfileText<'a> {
    /// Its name for people.
    pub title: &'a str,
    /// What it lets a workflow do.
    pub description: &'a str,
    /// The name of its icon.
    pub icon: &'a str,
    /// Its own picture, SVG of shapes only, carried in the integration's
    /// `assets/icon.svg`.
    pub picture: &'a str,
    /// Its brand colour as six lowercase hex digits, such as `24292f`,
    /// dark enough that a white mark on it stays readable.
    pub brand: &'a str,
}

/// How a step the platform itself offers presents itself, as text. It
/// carries no picture: the dashboard draws the platform's own steps.
pub struct BuiltInText<'a> {
    /// Its name for people.
    pub title: &'a str,
    /// What it lets a workflow do.
    pub description: &'a str,
    /// The name of its icon.
    pub icon: &'a str,
    /// Its brand colour as six lowercase hex digits, such as `0f766e`.
    pub brand: &'a str,
}

/// How an operation is explained, as text.
pub struct GuideText<'a> {
    /// Stable key linking this guide to the callable action.
    pub operation: &'a str,
    /// Its name for people.
    pub title: &'a str,
    /// What it does.
    pub description: &'a str,
    /// Each input: what it means and how it is asked for.
    pub inputs: &'a [InputText<'a>],
    /// Each value it gives back: its path in the step's output and what it
    /// is.
    pub outputs: &'a [(&'a str, &'a str)],
    /// How its step is previewed, if it is.
    pub preview: Option<&'a PreviewText>,
}

/// Author-written explanation and form hints validated into an input note.
pub struct InputText<'a> {
    /// Argument key used to match this note to the operation's input.
    pub name: &'a str,
    /// What it means.
    pub meaning: &'a str,
    /// The block its kind suggests.
    pub suggested: Suggested,
    /// How it is asked for.
    pub form: FormText,
}

impl InputText<'_> {
    /// The note explaining this input.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when its name, meaning or form
    /// breaks its rules.
    pub fn note(&self) -> Result<InputNote, DomainError> {
        Ok(InputNote::new(
            FieldName::new(self.name)?,
            Text::new("description", self.meaning)?,
            input_form(self.name, self.suggested, &self.form)?,
        ))
    }
}

/// The profile of the integration `key`, as `text` writes it.
///
/// # Errors
///
/// Returns `DomainError::Validation` when a value breaks its rules, such as
/// a blank title, an icon name with capitals, a picture holding more than
/// shapes or a brand colour too light.
pub fn profile(
    key: &IntegrationKey,
    text: &ProfileText<'_>,
) -> Result<IntegrationProfile, DomainError> {
    Ok(IntegrationProfile::new(IntegrationProfileParams {
        key: key.clone(),
        title: Label::new("title", text.title)?,
        description: Text::new("description", text.description)?,
        icon: IntegrationIcon::new(text.icon)?,
        look: IntegrationLook::Picture(picture(text.picture)?),
        brand: BrandColor::new(text.brand)?,
    }))
}

/// The profile of a step the platform itself offers, which `text` writes,
/// with no picture of its own.
///
/// # Errors
///
/// Returns `DomainError::Validation` when a value breaks its rules, such as
/// a blank title, an icon name with capitals or a brand colour too light.
pub fn built_in_profile(
    key: &IntegrationKey,
    text: &BuiltInText<'_>,
) -> Result<IntegrationProfile, DomainError> {
    Ok(IntegrationProfile::new(IntegrationProfileParams {
        key: key.clone(),
        title: Label::new("title", text.title)?,
        description: Text::new("description", text.description)?,
        icon: IntegrationIcon::new(text.icon)?,
        look: IntegrationLook::BuiltIn,
        brand: BrandColor::new(text.brand)?,
    }))
}

/// The guide `text` writes.
///
/// # Errors
///
/// Returns `DomainError::Validation` when a value breaks its rules, such as
/// an output path that does not parse.
pub fn guide(text: &GuideText<'_>) -> Result<OperationGuide, DomainError> {
    let inputs = text
        .inputs
        .iter()
        .map(InputText::note)
        .collect::<Result<Vec<_>, DomainError>>()?;
    let outputs = text
        .outputs
        .iter()
        .map(|(path, meaning)| {
            Ok(OutputNote::new(
                DataPath::parse(path)?,
                Text::new("description", *meaning)?,
            ))
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    Ok(OperationGuide::new(OperationGuideParams {
        operation: OperationKey::new(text.operation)?,
        title: Label::new("title", text.title)?,
        description: Text::new("description", text.description)?,
        inputs,
        outputs,
        preview: text.preview.map(preview).transpose()?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A picture of one square.
    const MARK: &str = r#"<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M0 0h24v24H0z"/></svg>"#;

    fn plain(name: &'static str, meaning: &'static str) -> InputText<'static> {
        InputText {
            name,
            meaning,
            suggested: Suggested::Text,
            form: FormText::plain(),
        }
    }

    /// A guide written as text keeps every note.
    #[test]
    fn a_guide_keeps_every_note() {
        let written = guide(&GuideText {
            operation: "post-message",
            title: "Post a message",
            description: "Posts a message to a channel.",
            inputs: &[
                plain("channel", "The channel's id."),
                plain("text", "What it says."),
            ],
            outputs: &[("json.ts", "The message's id in the channel.")],
            preview: None,
        })
        .unwrap();

        assert_eq!(written.inputs().len(), 2);
        assert_eq!(written.outputs()[0].path().to_string(), "json.ts");
    }

    /// Building a profile fails when its icon name includes a file extension.
    #[test]
    fn a_profile_with_a_bad_icon_is_refused() {
        let key = IntegrationKey::new("chat").unwrap();

        let written = profile(
            &key,
            &ProfileText {
                title: "Chat",
                description: "Posts to chat.",
                icon: "chat.svg",
                picture: MARK,
                brand: "24292f",
            },
        );

        assert!(written.is_err());
    }

    /// Building a profile fails when its brand colour is too light for a white mark.
    #[test]
    fn a_profile_with_a_light_brand_is_refused() {
        let key = IntegrationKey::new("chat").unwrap();

        let written = profile(
            &key,
            &ProfileText {
                title: "Chat",
                description: "Posts to chat.",
                icon: "chat",
                picture: MARK,
                brand: "fafafa",
            },
        );

        assert!(written.is_err());
    }

    /// An SVG picture with an event handler prevents profile construction.
    #[test]
    fn a_profile_with_a_scripted_picture_is_refused() {
        let key = IntegrationKey::new("chat").unwrap();

        let written = profile(
            &key,
            &ProfileText {
                title: "Chat",
                description: "Posts to chat.",
                icon: "chat",
                picture: r#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>"#,
                brand: "24292f",
            },
        );

        assert!(written.is_err());
    }
}
