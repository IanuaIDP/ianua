//! Refusals worded in a reader's language from the generated Fluent
//! resources, `locales/<tag>/messages.ftl`, built into the binary.

use std::collections::HashMap;

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource};
use ianua_app::ports::shared::{PreferredLanguages, RefusalWording};
use ianua_domain::shared::errors::{DomainError, Refusal};
use unic_langid::LanguageIdentifier;

use crate::language::Language;

/// Each translated language's messages, as `ianua-translate write-fluent`
/// generates them. English needs none: every refusal carries its English.
const RESOURCES: [(Language, &str); 7] = [
    (
        Language::German,
        include_str!("../../locales/de/messages.ftl"),
    ),
    (
        Language::Spanish,
        include_str!("../../locales/es/messages.ftl"),
    ),
    (
        Language::French,
        include_str!("../../locales/fr/messages.ftl"),
    ),
    (
        Language::Japanese,
        include_str!("../../locales/ja/messages.ftl"),
    ),
    (
        Language::Georgian,
        include_str!("../../locales/ka/messages.ftl"),
    ),
    (
        Language::Ukrainian,
        include_str!("../../locales/uk/messages.ftl"),
    ),
    (
        Language::SimplifiedChinese,
        include_str!("../../locales/zh-Hans/messages.ftl"),
    ),
];

/// Words refusals through one Fluent bundle per translated language.
pub struct FluentRefusalWording {
    bundles: HashMap<Language, FluentBundle<FluentResource>>,
}

impl std::fmt::Debug for FluentRefusalWording {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FluentRefusalWording")
            .field("languages", &self.bundles.len())
            .finish()
    }
}

impl FluentRefusalWording {
    /// The wording of every shipped language, its resources parsed and loaded.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a resource does not
    /// parse or holds a message twice, which `ianua-translate
    /// check-fluent` and a test of every resource rule out.
    pub fn new() -> Result<Self, DomainError> {
        let bundles = RESOURCES
            .into_iter()
            .map(|(language, source)| Ok((language, bundle(language, source)?)))
            .collect::<Result<_, DomainError>>()?;
        Ok(Self { bundles })
    }

    /// `refusal` worded in `language`, when its bundle holds the key.
    fn in_language(&self, language: Language, key: &str, refusal: &Refusal) -> Option<String> {
        let bundle = self.bundles.get(&language)?;
        let pattern = bundle.get_message(key)?.value()?;
        let mut arguments = FluentArgs::new();
        for value in refusal.values() {
            arguments.set(value.name(), value.value());
        }
        let mut errors = Vec::new();
        let worded = bundle.format_pattern(pattern, Some(&arguments), &mut errors);
        errors.is_empty().then(|| worded.into_owned())
    }
}

impl RefusalWording for FluentRefusalWording {
    fn worded(&self, refusal: &Refusal, languages: &PreferredLanguages) -> Option<String> {
        let key = refusal.key()?;
        for language in languages
            .tags()
            .iter()
            .filter_map(|tag| Language::of_tag(tag))
        {
            if language == Language::English {
                return None;
            }
            if let Some(worded) = self.in_language(language, key, refusal) {
                return Some(worded);
            }
        }
        None
    }
}

/// The bundle of `language` holding `source`, its words shown without
/// Unicode isolation marks, which would reach JSON as stray characters.
fn bundle(language: Language, source: &str) -> Result<FluentBundle<FluentResource>, DomainError> {
    let resource = FluentResource::try_new(source.to_owned()).map_err(|(_, errors)| {
        DomainError::infra_msg(format!(
            "the {} messages do not parse: {errors:?}",
            language.tag()
        ))
    })?;
    let identifier: LanguageIdentifier = language.tag().parse().map_err(DomainError::infra)?;
    let mut bundle = FluentBundle::new_concurrent(vec![identifier]);
    bundle.set_use_isolating(false);
    bundle.add_resource(resource).map_err(|errors| {
        DomainError::infra_msg(format!(
            "the {} messages hold a message twice: {errors:?}",
            language.tag()
        ))
    })?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wording() -> FluentRefusalWording {
        FluentRefusalWording::new().unwrap()
    }

    fn languages(tags: &[&str]) -> PreferredLanguages {
        PreferredLanguages::new(tags.iter().map(|tag| (*tag).to_owned()).collect())
    }

    /// Every shipped resource parses and loads.
    #[test]
    fn every_resource_loads() {
        assert_eq!(wording().bundles.len(), RESOURCES.len());
    }

    /// Ann reads German. A refusal with a value is worded in German, the value filled in.
    #[test]
    fn a_keyed_refusal_is_worded_in_the_readers_language() {
        let refusal = ianua_domain::message!(
            "activity-calendar-range-must-not-exceed-days",
            format!("calendar range must not exceed {} days", 90)
        );

        let worded = wording().worded(&refusal, &languages(&["de-AT", "en"]));

        assert_eq!(
            worded.as_deref(),
            Some("Maximaler Kalenderzeitraum (Tage): 90")
        );
    }

    /// A reader who prefers English, or no shipped language, reads the refusal's own English.
    #[test]
    fn english_or_unshipped_languages_read_the_english() {
        let refusal = ianua_domain::message!("app-entity-not-found", "entity not found");

        assert_eq!(
            wording().worded(&refusal, &languages(&["en-GB", "de"])),
            None
        );
        assert_eq!(wording().worded(&refusal, &languages(&["it", "pt"])), None);
    }

    /// The first shipped language asked for wins over later ones.
    #[test]
    fn the_first_shipped_language_wins() {
        let refusal = ianua_domain::message!("app-entity-not-found", "entity not found");

        let worded = wording().worded(&refusal, &languages(&["it", "fr", "de"]));

        assert!(worded.is_some_and(|text| text != "entity not found"));
    }

    /// Missing or unknown message keys return no translation, leaving the caller's English fallback.
    #[test]
    fn an_unknown_or_missing_key_reads_the_english() {
        let plain = Refusal::new("an outside library said no");
        let unknown = ianua_domain::message!("people-not-a-real-key", "Not here");

        assert_eq!(wording().worded(&plain, &languages(&["de"])), None);
        assert_eq!(wording().worded(&unknown, &languages(&["de"])), None);
    }
}
