//! The eight languages every catalog entry has a column for.

use serde::{Deserialize, Serialize};

/// A language the backend ships. The variants are declared in tag order,
/// so a catalog's translation columns keep their alphabetical order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) enum Language {
    /// Translation column and resource folder tagged `de`.
    #[serde(rename = "de")]
    German,
    /// English, the source and every key's fallback.
    #[serde(rename = "en")]
    English,
    /// Translation column and resource folder tagged `es`.
    #[serde(rename = "es")]
    Spanish,
    /// Translation column and resource folder tagged `fr`.
    #[serde(rename = "fr")]
    French,
    /// Translation column and resource folder tagged `ja`.
    #[serde(rename = "ja")]
    Japanese,
    /// Translation column and resource folder tagged `ka`.
    #[serde(rename = "ka")]
    Georgian,
    /// Translation column and resource folder tagged `uk`.
    #[serde(rename = "uk")]
    Ukrainian,
    /// Translation column and resource folder tagged `zh-Hans`.
    #[serde(rename = "zh-Hans")]
    SimplifiedChinese,
}

impl Language {
    /// Every language in the agreed order: English first, then the seven targets.
    pub(crate) const ALL: [Self; 8] = [
        Self::English,
        Self::Ukrainian,
        Self::German,
        Self::French,
        Self::Georgian,
        Self::Spanish,
        Self::SimplifiedChinese,
        Self::Japanese,
    ];

    /// The BCP 47 tag the catalog, draft tables and locale folders use.
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::German => "de",
            Self::English => "en",
            Self::Spanish => "es",
            Self::French => "fr",
            Self::Japanese => "ja",
            Self::Georgian => "ka",
            Self::Ukrainian => "uk",
            Self::SimplifiedChinese => "zh-Hans",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The serialized name of each language is the tag its folders use.
    #[test]
    fn serialized_names_match_the_folder_tags() {
        for language in Language::ALL {
            let written = serde_json::to_string(&language).unwrap();
            assert_eq!(written, format!("\"{}\"", language.tag()));
        }
    }

    /// Declaration order keeps translation columns sorted by tag.
    #[test]
    fn ordering_follows_the_tags() {
        let mut sorted = Language::ALL;
        sorted.sort_unstable();
        let tags: Vec<_> = sorted.into_iter().map(Language::tag).collect();
        let mut expected = tags.clone();
        expected.sort_unstable();
        assert_eq!(tags, expected);
    }
}
