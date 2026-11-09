//! A logo a tenant uploads, checked before the platform keeps and serves
//! it on the tenant's sign-in pages and in its mail.
//!
//! The format is read from the image's own first bytes, never from a file
//! name or a content type the uploader sends: Mallory names a page
//! `logo.png`, and a browser shown it as one would run what is inside. Only
//! PNG and JPEG are taken. SVG is not, since an SVG can carry script that
//! runs on the sign-in page.
//!
//! The size and the dimensions are bounded too. A logo of fifty megabytes,
//! or one that unpacks to a hundred thousand pixels a side, slows every
//! sign-in page and every mail that carries it.

use std::fmt;

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;

/// The most bytes a logo may hold: half a mebibyte.
const MOST_BYTES: u32 = 512 * 1024;
/// The fewest pixels a side of a logo may have.
const SMALLEST_SIDE: u32 = 16;
/// The most pixels a side of a logo may have.
const LARGEST_SIDE: u32 = 4096;
/// The eight bytes every PNG file starts with.
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
/// The two bytes every JPEG file starts with.
const JPEG_START: [u8; 2] = [0xFF, 0xD8];

/// The image formats a logo may be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoFormat {
    /// Portable Network Graphics.
    Png,
    /// A compressed raster image recognized by its JPEG signature.
    Jpeg,
}

impl LogoFormat {
    /// The content type the logo is served with.
    #[must_use]
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }

    /// A stable name for the format, for storage and records.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
        }
    }

    /// The format `bytes` are in, read from their own signature, with the
    /// image's width and height as its header gives them.
    fn read(bytes: &[u8]) -> Result<(Self, LogoDimensions), DomainError> {
        if bytes.starts_with(&PNG_SIGNATURE) {
            return Ok((Self::Png, png_dimensions(bytes)?));
        }
        if bytes.starts_with(&JPEG_START) {
            return Ok((Self::Jpeg, jpeg_dimensions(bytes)?));
        }
        Err(DomainError::invalid(message!(
            "branding-a-logo-is-a-png-or",
            "a logo is a PNG or a JPEG image"
        )))
    }
}

/// A logo's width and height in pixels, each within the bounds a logo
/// keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogoDimensions {
    width: u32,
    height: u32,
}

impl LogoDimensions {
    /// `width` by `height`, once each is between 16 and 4096 pixels.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a side is outside those bounds.
    pub fn new(width: u32, height: u32) -> Result<Self, DomainError> {
        validate_range("logo_width", width, SMALLEST_SIDE..=LARGEST_SIDE)?;
        validate_range("logo_height", height, SMALLEST_SIDE..=LARGEST_SIDE)?;
        Ok(Self { width, height })
    }

    /// The width in pixels.
    #[must_use]
    pub fn width(&self) -> u32 {
        self.width
    }

    /// The height in pixels.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }
}

/// An uploaded logo: its bytes, the format they are in and its dimensions,
/// each checked.
#[derive(Clone, PartialEq, Eq)]
pub struct LogoImage {
    format: LogoFormat,
    dimensions: LogoDimensions,
    bytes: Vec<u8>,
}

impl LogoImage {
    /// The logo `bytes` hold, once they are a PNG or JPEG of at most half a
    /// mebibyte whose sides are each between 16 and 4096 pixels.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the bytes are empty or larger
    ///   than half a mebibyte, are not a PNG or a JPEG, carry no readable
    ///   size, or are smaller or larger than a logo may be.
    pub fn new(bytes: Vec<u8>) -> Result<Self, DomainError> {
        let size = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        validate_range("logo_bytes", size, 1..=MOST_BYTES)?;
        let (format, dimensions) = LogoFormat::read(&bytes)?;
        Ok(Self {
            format,
            dimensions,
            bytes,
        })
    }

    /// The format the image is in.
    #[must_use]
    pub fn format(&self) -> LogoFormat {
        self.format
    }

    /// Its width and height.
    #[must_use]
    pub fn dimensions(&self) -> LogoDimensions {
        self.dimensions
    }

    /// The image itself, to be kept and served.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Shows the format, the size and the length, never the bytes.
impl fmt::Debug for LogoImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogoImage")
            .field("format", &self.format)
            .field("dimensions", &self.dimensions)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// The width and height a PNG's header chunk gives: the first chunk, named
/// `IHDR`, holds them as two big-endian numbers.
fn png_dimensions(bytes: &[u8]) -> Result<LogoDimensions, DomainError> {
    if bytes.get(12..16) != Some(b"IHDR".as_slice()) {
        return Err(unreadable());
    }
    let width = big_endian(bytes, 16, 4)?;
    let height = big_endian(bytes, 20, 4)?;
    LogoDimensions::new(width, height)
}

/// The width and height the first frame header of a JPEG gives, found by
/// walking its segments from the start.
fn jpeg_dimensions(bytes: &[u8]) -> Result<LogoDimensions, DomainError> {
    let mut at = JPEG_START.len();
    loop {
        let marker = jpeg_marker(bytes, at)?;
        if is_frame_header(marker) {
            let height = big_endian(bytes, at.saturating_add(5), 2)?;
            let width = big_endian(bytes, at.saturating_add(7), 2)?;
            return LogoDimensions::new(width, height);
        }
        let length = big_endian(bytes, at.saturating_add(2), 2)?;
        let length = usize::try_from(length).map_err(|_| unreadable())?;
        at = at.saturating_add(2).saturating_add(length);
    }
}

/// The marker of the JPEG segment starting at `at`.
fn jpeg_marker(bytes: &[u8], at: usize) -> Result<u8, DomainError> {
    let Some([0xFF, marker]) = bytes.get(at..at.saturating_add(2)) else {
        return Err(unreadable());
    };
    Ok(*marker)
}

/// Whether `marker` starts a frame header, which carries the image's size.
/// The markers between `C0` and `CF` do, but for the three that hold
/// tables or are reserved.
fn is_frame_header(marker: u8) -> bool {
    (0xC0..=0xCF).contains(&marker) && !matches!(marker, 0xC4 | 0xC8 | 0xCC)
}

/// The big-endian number of `width` bytes at `at`.
fn big_endian(bytes: &[u8], at: usize, width: usize) -> Result<u32, DomainError> {
    let field = bytes
        .get(at..at.saturating_add(width))
        .ok_or_else(unreadable)?;
    Ok(field
        .iter()
        .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte)))
}

/// Why an image whose size cannot be read is refused.
fn unreadable() -> DomainError {
    DomainError::invalid(message!(
        "branding-the-logo-s-size-cannot-be",
        "the logo's size cannot be read from the image"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::branding::fixtures::png;

    /// The first bytes of a JPEG `width` by `height` pixels, with an `APP0`
    /// segment before its frame header, as cameras and editors write them.
    fn jpeg(width: u16, height: u16) -> Vec<u8> {
        let mut bytes = JPEG_START.to_vec();
        bytes.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        bytes.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        bytes.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&[0x03; 10]);
        bytes
    }

    /// Acme uploads a 400 by 120 PNG. It is taken as a PNG of that size.
    #[test]
    fn a_png_logo_is_read_with_its_size() {
        let logo = LogoImage::new(png(400, 120)).unwrap();

        assert_eq!(logo.format(), LogoFormat::Png);
        assert_eq!(logo.format().content_type(), "image/png");
        assert_eq!(
            (logo.dimensions().width(), logo.dimensions().height()),
            (400, 120)
        );
    }

    /// Acme uploads a 640 by 200 JPEG. The size is read from its frame
    /// header, past the segment before it.
    #[test]
    fn a_jpeg_logo_is_read_with_its_size() {
        let logo = LogoImage::new(jpeg(640, 200)).unwrap();

        assert_eq!(logo.format(), LogoFormat::Jpeg);
        assert_eq!(
            (logo.dimensions().width(), logo.dimensions().height()),
            (640, 200)
        );
    }

    /// An SVG containing a script is rejected because its bytes are neither
    /// PNG nor JPEG, regardless of the name an uploader might give it.
    #[test]
    fn an_svg_is_refused_whatever_it_is_called() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>steal()</script></svg>"#;

        let result = LogoImage::new(svg.to_vec());

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A PNG one byte over the size limit and an empty upload are both
    /// rejected as invalid logos.
    #[test]
    fn a_logo_too_large_or_empty_is_refused() {
        let mut huge = png(400, 120);
        huge.resize(usize::try_from(MOST_BYTES).unwrap() + 1, 0);

        assert!(matches!(
            LogoImage::new(huge),
            Err(DomainError::Validation(_))
        ));
        assert!(matches!(
            LogoImage::new(Vec::new()),
            Err(DomainError::Validation(_))
        ));
    }

    /// PNG headers claiming a width of 100,000 pixels or a height of eight
    /// pixels are rejected before a logo can be constructed.
    #[test]
    fn a_logo_too_wide_or_too_small_is_refused() {
        for (width, height) in [(100_000, 120), (400, 8)] {
            let result = LogoImage::new(png(width, height));

            assert!(
                matches!(result, Err(DomainError::Validation(_))),
                "{width}x{height}"
            );
        }
    }

    /// A JPEG truncated before its frame header is rejected because its
    /// dimensions cannot be read.
    #[test]
    fn a_truncated_image_is_refused() {
        let mut cut = jpeg(640, 200);
        cut.truncate(10);

        assert!(matches!(
            LogoImage::new(cut),
            Err(DomainError::Validation(_))
        ));
    }

    /// A logo written to a log shows its format and size, never its bytes.
    #[test]
    fn a_logo_never_prints_its_bytes() {
        let logo = LogoImage::new(png(400, 120)).unwrap();

        let printed = format!("{logo:?}");

        assert!(printed.contains("Png"));
        assert!(!printed.contains("IHDR"));
    }
}
