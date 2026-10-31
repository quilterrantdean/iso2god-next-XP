//! Game icons for the package's CON header.
//!
//! The header has room for one PNG of up to [`MAX_ICON_BYTES`] bytes, which the
//! console's dashboard shows for the game. An icon comes from either a picture
//! the user chose ([`from_file`]) or Microsoft's icon server ([`fetch`]); both
//! hand back a PNG that is ready for [`crate::ConvertOptions::icon`].

use std::io::{Cursor, Read};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Error, bail};
use image::codecs::png::{CompressionType, FilterType as PngFilter, PngEncoder};
use image::imageops::FilterType;
use image::{DynamicImage, ImageFormat, ImageReader, Limits};

/// Space the CON header reserves for each of its two thumbnails.
pub const MAX_ICON_BYTES: usize = 0x4000;

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// The size games ship their own icon at.
const ICON_SIZE: u32 = 64;

/// Edge lengths tried, largest first, until the PNG fits the header.
const FALLBACK_SIZES: [u32; 3] = [ICON_SIZE, 48, 32];

/// Square PNGs up to this edge length are used as they are.
const MAX_VERBATIM_EDGE: u32 = 128;

/// No real icon comes close; a bigger answer from the server is not an icon.
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Where Microsoft serves a title's 64x64 icon. The server only answers over
/// plain HTTP: its HTTPS certificate is issued for a different host name.
fn icon_url(title_id: u32) -> String {
    format!("http://image.xboxlive.com/global/t.{title_id:08X}/icon/0/8000")
}

/// Checks that `png` can be stored in the CON header as it is.
pub fn validate(png: &[u8]) -> Result<(), Error> {
    if !png.starts_with(PNG_SIGNATURE) {
        bail!("the game icon is not a PNG image");
    }
    if png.len() > MAX_ICON_BYTES {
        bail!(
            "the game icon is {} bytes, but the package has room for {MAX_ICON_BYTES}",
            png.len()
        );
    }
    Ok(())
}

/// Reads a picture (PNG or JPEG, any size) and turns it into a game icon.
pub fn from_file(path: &Path) -> Result<Vec<u8>, Error> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    prepare(&bytes).with_context(|| format!("cannot use {} as a game icon", path.display()))
}

/// Where a game's icon came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Read from the game's own `default.xex`.
    Game,
    /// Downloaded from Microsoft's icon server.
    Download,
}

/// Finds the icon of a game: the one in its own executable if that can be
/// read, otherwise (only if `download` is set) the one on Microsoft's icon
/// server. `Ok(None)` means neither has one.
///
/// A game that cannot be read is not an error as long as the download may
/// still help; if it is not allowed or fails too, the error is reported.
pub fn find(
    source: &Path,
    title_id: u32,
    download: bool,
) -> Result<Option<(Vec<u8>, Origin)>, Error> {
    let from_game = crate::convert::game_icon(source);
    if let Ok(Some(png)) = from_game {
        return Ok(Some((png, Origin::Game)));
    }

    if download {
        return fetch(title_id).map(|png| png.map(|png| (png, Origin::Download)));
    }

    from_game.map(|_| None)
}

/// Downloads the icon of a title from Microsoft's icon server.
///
/// `Ok(None)` means the server has no icon for this title.
pub fn fetch(title_id: u32) -> Result<Option<Vec<u8>>, Error> {
    // Not a real title; the server answers with a 4x4 placeholder.
    if title_id == 0 {
        return Ok(None);
    }

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("iso2god-next/", env!("CARGO_PKG_VERSION")))
        .build();

    let response = match agent.get(&icon_url(title_id)).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(404, _)) => return Ok(None),
        Err(error) => {
            return Err(Error::new(error)).context("cannot download the game icon");
        }
    };

    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_DOWNLOAD_BYTES + 1)
        .read_to_end(&mut body)
        .context("cannot download the game icon")?;
    if body.len() as u64 > MAX_DOWNLOAD_BYTES {
        bail!("the icon server sent something too large to be a game icon");
    }

    prepare(&body)
        .context("the icon server sent an unusable image")
        .map(Some)
}

/// Turns any PNG or JPEG into a PNG that fits the CON header.
///
/// A small square PNG that already fits is kept byte for byte. Anything else is
/// cropped to a centred square and scaled to the size games use, shrinking
/// further only if a very detailed picture still would not fit.
pub fn prepare(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut limits = Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(256 * 1024 * 1024);

    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .context("cannot read the image")?;
    reader.limits(limits);

    let format = reader.format();
    let image = reader.decode().context("not a PNG or JPEG image")?;
    let (width, height) = (image.width(), image.height());

    if format == Some(ImageFormat::Png)
        && width == height
        && width <= MAX_VERBATIM_EDGE
        && validate(bytes).is_ok()
    {
        return Ok(bytes.to_vec());
    }

    let side = width.min(height);
    let square = image.crop_imm((width - side) / 2, (height - side) / 2, side, side);

    for edge in FALLBACK_SIZES {
        let scaled = square.resize_exact(edge, edge, FilterType::Lanczos3);
        let png = encode_png(&scaled)?;
        if png.len() <= MAX_ICON_BYTES {
            return Ok(png);
        }
    }

    bail!("the picture is too detailed to fit in the package")
}

fn encode_png(image: &DynamicImage) -> Result<Vec<u8>, Error> {
    // Skip the alpha channel when nothing is transparent; it makes the file
    // noticeably smaller.
    let opaque =
        !image.color().has_alpha() || image.to_rgba8().pixels().all(|pixel| pixel[3] == 255);
    let image = if opaque {
        DynamicImage::ImageRgb8(image.to_rgb8())
    } else {
        DynamicImage::ImageRgba8(image.to_rgba8())
    };

    let mut png = Vec::new();
    let encoder =
        PngEncoder::new_with_quality(&mut png, CompressionType::Best, PngFilter::Adaptive);
    image
        .write_with_encoder(encoder)
        .context("cannot encode the game icon")?;
    Ok(png)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb, Rgba};

    /// A picture whose pixels are pseudo-random, so it barely compresses.
    fn noise(width: u32, height: u32) -> ImageBuffer<Rgba<u8>, Vec<u8>> {
        let mut state = 0x2545_f491_u32;
        ImageBuffer::from_fn(width, height, |_, _| {
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 8) as u8
            };
            Rgba([next(), next(), next(), next() | 0x80])
        })
    }

    fn encode(image: &DynamicImage, format: ImageFormat) -> Vec<u8> {
        let mut bytes = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), format)
            .unwrap();
        bytes
    }

    fn dimensions(png: &[u8]) -> (u32, u32) {
        image::load_from_memory(png)
            .map(|i| (i.width(), i.height()))
            .unwrap()
    }

    #[test]
    fn a_small_square_png_is_kept_as_it_is() {
        let original = encode(
            &DynamicImage::ImageRgb8(ImageBuffer::from_pixel(64, 64, Rgb([200, 30, 30]))),
            ImageFormat::Png,
        );

        assert_eq!(prepare(&original).unwrap(), original);
    }

    #[test]
    fn a_big_wide_picture_becomes_a_small_square_png() {
        let jpeg = encode(
            &DynamicImage::ImageRgb8(ImageBuffer::from_pixel(1200, 600, Rgb([10, 120, 200]))),
            ImageFormat::Jpeg,
        );

        let icon = prepare(&jpeg).unwrap();

        validate(&icon).unwrap();
        assert_eq!(dimensions(&icon), (ICON_SIZE, ICON_SIZE));
    }

    #[test]
    fn the_centre_of_a_wide_picture_is_what_remains() {
        // Red bars on both sides of a green middle square.
        let wide = ImageBuffer::from_fn(300, 100, |x, _| {
            if (100..200).contains(&x) {
                Rgb([0, 255, 0])
            } else {
                Rgb([255, 0, 0])
            }
        });
        let png = encode(&DynamicImage::ImageRgb8(wide), ImageFormat::Png);

        let icon = image::load_from_memory(&prepare(&png).unwrap())
            .unwrap()
            .to_rgb8();

        assert_eq!(icon.get_pixel(0, 0), &Rgb([0, 255, 0]));
        assert_eq!(icon.get_pixel(63, 63), &Rgb([0, 255, 0]));
    }

    #[test]
    fn a_picture_too_detailed_for_the_header_is_shrunk_until_it_fits() {
        // Noise at the full icon size cannot be squeezed under the limit, since
        // the PNG is then larger than the raw pixels (64 * 64 * 4 = 0x4000).
        let png = encode(&DynamicImage::ImageRgba8(noise(64, 64)), ImageFormat::Png);
        assert!(png.len() > MAX_ICON_BYTES);

        let icon = prepare(&png).unwrap();

        validate(&icon).unwrap();
        assert!(dimensions(&icon).0 < ICON_SIZE);
    }

    #[test]
    fn something_that_is_not_an_image_is_rejected() {
        assert!(prepare(b"definitely not a picture").is_err());
        assert!(prepare(&[]).is_err());
    }

    #[test]
    fn only_png_data_that_fits_is_valid() {
        assert!(validate(b"GIF89a").is_err());
        assert!(validate(&[]).is_err());

        let mut oversized = PNG_SIGNATURE.to_vec();
        oversized.resize(MAX_ICON_BYTES + 1, 0);
        assert!(validate(&oversized).is_err());

        oversized.truncate(MAX_ICON_BYTES);
        assert!(validate(&oversized).is_ok());
    }

    #[test]
    fn the_icon_url_uses_the_eight_digit_title_id() {
        assert_eq!(
            icon_url(0x4D53_07E6),
            "http://image.xboxlive.com/global/t.4D5307E6/icon/0/8000"
        );
        assert_eq!(
            icon_url(0x0000_07D1),
            "http://image.xboxlive.com/global/t.000007D1/icon/0/8000"
        );
    }

    #[test]
    fn title_zero_never_asks_the_server() {
        assert!(fetch(0).unwrap().is_none());
    }

    /// Talks to the real icon server: `cargo test -- --ignored`.
    #[test]
    #[ignore = "needs an internet connection"]
    fn the_icon_server_knows_a_real_title_and_not_a_made_up_one() {
        let icon = fetch(0x4D53_07E6).unwrap().expect("no icon for Halo 3");
        validate(&icon).unwrap();
        assert_eq!(dimensions(&icon), (ICON_SIZE, ICON_SIZE));

        assert!(fetch(0x1234_5678).unwrap().is_none());
    }
}
