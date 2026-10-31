//! The icon a game carries inside its `default.xex`.
//!
//! An Xbox 360 executable has a resource named after the title ID. It is an
//! XDBF file holding the game's achievements, strings and pictures, among them
//! the 64x64 icon the dashboard shows (image 0x8000). The resource lives in the
//! executable's image, which is usually AES-encrypted and may be compressed.
//!
//! Only what can be read without a decompressor is supported: images that are
//! stored plainly or with "basic" compression (runs of zeros left out). Images
//! packed with LZX, or as a delta patch, give an error.
//!
//! Layout notes: <https://free60.org/System-Software/Formats/XEX/> and
//! <https://free60.org/System-Software/Formats/XDBF/>.

use aes::Aes128;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecrypt, BlockDecryptMut, KeyInit, KeyIvInit};
use anyhow::{Context, Error, anyhow, bail};

/// The key every retail executable's own key is wrapped with.
const RETAIL_KEY: [u8; 16] = [
    0x20, 0xb1, 0x85, 0xa5, 0x9d, 0x28, 0xfd, 0xc3, 0x40, 0x58, 0x3f, 0xbb, 0x08, 0x96, 0xbf, 0x91,
];

/// The key of development kit executables.
const DEVKIT_KEY: [u8; 16] = [0; 16];

/// No resource this module reads comes anywhere near this.
const MAX_RESOURCE_BYTES: u32 = 16 * 1024 * 1024;

const FIELD_RESOURCE_INFO: u32 = 0x0000_02ff;
const FIELD_BASE_FILE_FORMAT: u32 = 0x0000_03ff;
const FIELD_IMAGE_BASE_ADDRESS: u32 = 0x0001_0201;
const FIELD_EXECUTION_ID: u32 = 0x0004_0006;

const ENCRYPTION_NONE: u16 = 0;
const ENCRYPTION_NORMAL: u16 = 1;
const COMPRESSION_NONE: u16 = 0;
const COMPRESSION_BASIC: u16 = 1;

const XDBF_NAMESPACE_IMAGE: u16 = 2;
const XDBF_TITLE_ICON: u64 = 0x8000;

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Reads the title icon (a PNG) out of the bytes of a `default.xex`.
///
/// `Ok(None)` means the executable has no icon; an error means it could not be
/// read, which includes image formats this module does not support.
pub fn from_xex(xex: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let bytes = Bytes(xex);
    if bytes.get(0, 4)? != b"XEX2" {
        bail!("missing 'XEX2' magic bytes in XEX header");
    }

    let image_offset = bytes.u32(8)? as usize;
    let security_offset = bytes.u32(16)? as usize;

    let mut resource_info = None;
    let mut base_file_format = None;
    let mut image_base = None;
    let mut title_id = None;

    for index in 0..bytes.u32(20)? as usize {
        let entry = 24 + index * 8;
        let (key, value) = (bytes.u32(entry)?, bytes.u32(entry + 4)?);
        match key {
            FIELD_RESOURCE_INFO => resource_info = Some(value as usize),
            FIELD_BASE_FILE_FORMAT => base_file_format = Some(value as usize),
            FIELD_IMAGE_BASE_ADDRESS => image_base = Some(value),
            // The title ID follows the media ID, version and base version.
            FIELD_EXECUTION_ID => title_id = Some(bytes.u32(value as usize + 12)?),
            _ => {}
        }
    }

    let (Some(resource_info), Some(base_file_format), Some(image_base)) =
        (resource_info, base_file_format, image_base)
    else {
        return Ok(None);
    };

    let image = Image::open(bytes, image_offset, security_offset, base_file_format)?;

    // Resources are 16-byte entries: an 8 character name, an address in the
    // loaded image and a size. The one that is named after the title ID is the
    // XDBF; the others are tried only if it is missing.
    let table_size = bytes.u32(resource_info)? as usize;
    let mut resources = Vec::new();
    for index in 0..table_size.saturating_sub(4) / 16 {
        let entry = resource_info + 4 + index * 16;
        let name = bytes.get(entry, 8)?;
        let address = bytes.u32(entry + 8)?;
        let size = bytes.u32(entry + 12)?;
        let named_for_title = title_id.is_some_and(|id| name == format!("{id:08X}").as_bytes());
        resources.push((!named_for_title, address, size));
    }
    resources.sort_by_key(|&(not_the_title, ..)| not_the_title);

    for (_, address, size) in resources {
        let Some(offset) = address.checked_sub(image_base) else {
            continue;
        };
        if size == 0 || size > MAX_RESOURCE_BYTES {
            continue;
        }

        let data = image.read(offset as usize, size as usize)?;
        if let Some(icon) = xdbf_title_icon(&data) {
            return Ok(Some(icon));
        }
    }

    Ok(None)
}

/// Finds the title icon in an XDBF file, or `None` if this is not one or it
/// has none.
fn xdbf_title_icon(xdbf: &[u8]) -> Option<Vec<u8>> {
    let bytes = Bytes(xdbf);
    if bytes.get(0, 4).ok()? != b"XDBF" {
        return None;
    }

    // Header: magic, version, then how many entries the entry table has room
    // for and how many it holds, and the same for the free space table. The
    // data follows the two tables.
    let entry_slots = bytes.u32(8).ok()? as usize;
    let entry_count = (bytes.u32(12).ok()? as usize).min(entry_slots);
    let free_slots = bytes.u32(16).ok()? as usize;
    let data_start = 24 + entry_slots.checked_mul(18)? + free_slots.checked_mul(8)?;

    for index in 0..entry_count {
        let entry = 24 + index * 18;
        let namespace = bytes.u16(entry).ok()?;
        let id = bytes.u64(entry + 2).ok()?;
        if namespace != XDBF_NAMESPACE_IMAGE || id != XDBF_TITLE_ICON {
            continue;
        }

        let offset = data_start.checked_add(bytes.u32(entry + 10).ok()? as usize)?;
        let length = bytes.u32(entry + 14).ok()? as usize;
        let icon = bytes.get(offset, length).ok()?;
        return icon.starts_with(PNG_SIGNATURE).then(|| icon.to_vec());
    }

    None
}

/// A stretch of the image that the file stores, as opposed to the zeros that
/// basic compression leaves out.
#[derive(Clone, Copy, Debug)]
struct Segment {
    /// Where the stretch starts in the image.
    image: usize,
    /// Where its bytes start in the stored data.
    stored: usize,
    length: usize,
}

/// The executable's image as stored in the file.
struct Image<'a> {
    bytes: Bytes<'a>,
    /// Where the stored data starts in the file.
    data_offset: usize,
    segments: Vec<Segment>,
    /// The AES key of the stored data, if it is encrypted.
    key: Option<[u8; 16]>,
}

impl<'a> Image<'a> {
    fn open(
        bytes: Bytes<'a>,
        data_offset: usize,
        security_offset: usize,
        format_offset: usize,
    ) -> Result<Self, Error> {
        let info_size = bytes.u32(format_offset)? as usize;
        let encryption = bytes.u16(format_offset + 4)?;
        let compression = bytes.u16(format_offset + 6)?;

        let stored_size = bytes
            .len()
            .checked_sub(data_offset)
            .context("the XEX has no image data")?;

        let segments = match compression {
            COMPRESSION_NONE => vec![Segment {
                image: 0,
                stored: 0,
                length: stored_size,
            }],
            COMPRESSION_BASIC => {
                // Pairs of (bytes stored, zero bytes left out).
                let mut segments = Vec::new();
                let (mut image, mut stored) = (0_usize, 0_usize);
                for index in 0..info_size.saturating_sub(8) / 8 {
                    let entry = format_offset + 8 + index * 8;
                    let length = bytes.u32(entry)? as usize;
                    let zeros = bytes.u32(entry + 4)? as usize;
                    segments.push(Segment {
                        image,
                        stored,
                        length,
                    });
                    image = image.saturating_add(length).saturating_add(zeros);
                    stored = stored.saturating_add(length);
                }
                if stored > stored_size {
                    bail!("the XEX image data is cut short");
                }
                segments
            }
            2 => bail!("the XEX image is LZX-compressed, which is not supported"),
            other => bail!("the XEX image uses compression type {other}, which is not supported"),
        };

        let key = match encryption {
            ENCRYPTION_NONE => None,
            ENCRYPTION_NORMAL => Some(find_session_key(bytes, data_offset, security_offset)?),
            other => bail!("the XEX image uses encryption type {other}, which is not supported"),
        };

        Ok(Image {
            bytes,
            data_offset,
            segments,
            key,
        })
    }

    /// Returns `length` bytes of the (decrypted, expanded) image from `offset`.
    fn read(&self, offset: usize, length: usize) -> Result<Vec<u8>, Error> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow!("the resource lies outside the image"))?;
        let mut out = vec![0_u8; length];
        let mut covered_any = false;

        for segment in &self.segments {
            let start = offset.max(segment.image);
            let stop = end.min(segment.image.saturating_add(segment.length));
            if start >= stop {
                continue;
            }
            covered_any = true;

            let stored = segment.stored + (start - segment.image);
            let chunk = self.read_stored(stored, stop - start)?;
            out[start - offset..stop - offset].copy_from_slice(&chunk);
        }

        if !covered_any {
            bail!("the resource lies outside the image");
        }
        Ok(out)
    }

    /// Reads and decrypts `length` bytes of the stored data from `offset`.
    fn read_stored(&self, offset: usize, length: usize) -> Result<Vec<u8>, Error> {
        let Some(key) = &self.key else {
            return Ok(self.bytes.get(self.data_offset + offset, length)?.to_vec());
        };

        // The data is one AES-CBC stream with a zero IV, so decryption can
        // begin at any block as long as the block before it is the IV.
        let first = offset & !15;
        let last = (offset + length).next_multiple_of(16);
        let mut data = self
            .bytes
            .get(self.data_offset + first, last - first)?
            .to_vec();
        let iv: [u8; 16] = if first == 0 {
            [0; 16]
        } else {
            self.bytes
                .get(self.data_offset + first - 16, 16)?
                .try_into()
                .expect("16 bytes")
        };

        decrypt_cbc(key, &iv, &mut data)?;
        Ok(data[offset - first..offset - first + length].to_vec())
    }
}

/// Unwraps the executable's own AES key with the retail key, or the development
/// kit key for executables made for one.
///
/// The right key is the one under which the image starts with `MZ`, like every
/// PE file.
fn find_session_key(
    bytes: Bytes<'_>,
    data_offset: usize,
    security_offset: usize,
) -> Result<[u8; 16], Error> {
    let wrapped: [u8; 16] = bytes
        .get(security_offset + 0x150, 16)?
        .try_into()
        .expect("16 bytes");
    let first_block: [u8; 16] = bytes
        .get(data_offset, 16)
        .context("the XEX has no image data")?
        .try_into()
        .expect("16 bytes");

    for wrapping_key in [RETAIL_KEY, DEVKIT_KEY] {
        let mut key = wrapped.into();
        Aes128::new(&wrapping_key.into()).decrypt_block(&mut key);
        let key: [u8; 16] = key.into();

        let mut probe = first_block;
        decrypt_cbc(&key, &[0; 16], &mut probe)?;
        if probe.starts_with(b"MZ") {
            return Ok(key);
        }
    }

    bail!("the XEX image is encrypted with a key this tool does not know")
}

fn decrypt_cbc(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> Result<(), Error> {
    cbc::Decryptor::<Aes128>::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(data)
        .map_err(|_| anyhow!("the encrypted XEX data is not a whole number of blocks"))?;
    Ok(())
}

/// Big-endian reads that fail instead of panicking on a truncated file.
#[derive(Clone, Copy)]
struct Bytes<'a>(&'a [u8]);

impl<'a> Bytes<'a> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn get(&self, offset: usize, length: usize) -> Result<&'a [u8], Error> {
        offset
            .checked_add(length)
            .and_then(|end| self.0.get(offset..end))
            .ok_or_else(|| {
                anyhow!("the XEX is truncated or damaged (reading {length} bytes at {offset:#x})")
            })
    }

    fn u16(&self, offset: usize) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.get(offset, 2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&self, offset: usize) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.get(offset, 4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&self, offset: usize) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.get(offset, 8)?.try_into().expect("8 bytes"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockEncrypt, BlockEncryptMut};

    const TITLE_ID: u32 = 0x4156_07F7;
    const BASE: u32 = 0x8200_0000;
    const SESSION_KEY: [u8; 16] = *b"0123456789abcdef";
    /// Not 16-aligned, so that decryption has to start mid-stream.
    const XDBF_AT: usize = 0x3123;
    const IMAGE_SIZE: usize = 0x4000;

    /// A PNG-looking icon; the reader never decodes it.
    fn icon() -> Vec<u8> {
        let mut png = PNG_SIGNATURE.to_vec();
        png.extend((0..300_u32).map(|i| (i * 7) as u8));
        png
    }

    fn xdbf(namespace: u16, id: u64, icon: &[u8]) -> Vec<u8> {
        let mut xdbf = Vec::new();
        xdbf.extend(b"XDBF");
        xdbf.extend(0x10000_u32.to_be_bytes());
        xdbf.extend(2_u32.to_be_bytes()); // entry slots
        xdbf.extend(1_u32.to_be_bytes()); // entries used
        xdbf.extend(1_u32.to_be_bytes()); // free slots
        xdbf.extend(0_u32.to_be_bytes()); // free used
        xdbf.extend(namespace.to_be_bytes());
        xdbf.extend(id.to_be_bytes());
        xdbf.extend(0_u32.to_be_bytes()); // offset in the data
        xdbf.extend((icon.len() as u32).to_be_bytes());
        xdbf.resize(24 + 2 * 18 + 8, 0);
        xdbf.extend(icon);
        xdbf
    }

    struct Layout {
        encrypted: bool,
        compression: u16,
        wrapping_key: [u8; 16],
    }

    impl Default for Layout {
        fn default() -> Self {
            Layout {
                encrypted: true,
                compression: COMPRESSION_BASIC,
                wrapping_key: RETAIL_KEY,
            }
        }
    }

    /// An XEX2 with a resource named after the title, holding `xdbf`.
    fn build_xex(xdbf: &[u8], layout: &Layout) -> Vec<u8> {
        let mut image = vec![0_u8; IMAGE_SIZE];
        image[..2].copy_from_slice(b"MZ");
        image[0x100..0x200].fill(0xaa);
        image[XDBF_AT..XDBF_AT + xdbf.len()].copy_from_slice(xdbf);
        // Basic compression drops 0x2000..0x3000; keep it empty.
        image[0x2000..0x3000].fill(0);

        let (stored, pairs): (Vec<u8>, Vec<(u32, u32)>) = if layout.compression == COMPRESSION_BASIC
        {
            let mut stored = image[..0x2000].to_vec();
            stored.extend(&image[0x3000..]);
            (stored, vec![(0x2000, 0x1000), (0x1000, 0)])
        } else {
            (image, Vec::new())
        };

        let mut stored = stored;
        if layout.encrypted {
            let len = stored.len();
            cbc::Encryptor::<Aes128>::new((&SESSION_KEY).into(), (&[0_u8; 16]).into())
                .encrypt_padded_mut::<NoPadding>(&mut stored, len)
                .unwrap();
        }

        let mut file_key = SESSION_KEY.into();
        Aes128::new((&layout.wrapping_key).into()).encrypt_block(&mut file_key);

        let mut xex = vec![0_u8; 0x1000];
        let put = |xex: &mut Vec<u8>, at: usize, value: u32| {
            xex[at..at + 4].copy_from_slice(&value.to_be_bytes())
        };
        xex[..4].copy_from_slice(b"XEX2");
        put(&mut xex, 8, 0x1000); // image data
        put(&mut xex, 16, 0x400); // security info
        put(&mut xex, 20, 4); // fields
        for (index, (key, value)) in [
            (FIELD_RESOURCE_INFO, 0x200),
            (FIELD_BASE_FILE_FORMAT, 0x240),
            (FIELD_IMAGE_BASE_ADDRESS, BASE),
            (FIELD_EXECUTION_ID, 0x280),
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut xex, 24 + index * 8, key);
            put(&mut xex, 28 + index * 8, value);
        }

        // Resources: one entry.
        put(&mut xex, 0x200, 20);
        xex[0x204..0x20c].copy_from_slice(format!("{TITLE_ID:08X}").as_bytes());
        put(&mut xex, 0x20c, BASE + XDBF_AT as u32);
        put(&mut xex, 0x210, xdbf.len() as u32);

        // File format.
        put(&mut xex, 0x240, 8 + pairs.len() as u32 * 8);
        let encryption = if layout.encrypted {
            ENCRYPTION_NORMAL
        } else {
            ENCRYPTION_NONE
        };
        xex[0x244..0x246].copy_from_slice(&encryption.to_be_bytes());
        xex[0x246..0x248].copy_from_slice(&layout.compression.to_be_bytes());
        for (index, (data, zeros)) in pairs.iter().enumerate() {
            put(&mut xex, 0x248 + index * 8, *data);
            put(&mut xex, 0x24c + index * 8, *zeros);
        }

        // Execution ID: media ID, version, base version, title ID.
        put(&mut xex, 0x28c, TITLE_ID);

        // Security info: the wrapped key.
        xex[0x400 + 0x150..0x400 + 0x160].copy_from_slice(&file_key);

        xex.extend(stored);
        xex
    }

    fn expected() -> Option<Vec<u8>> {
        Some(icon())
    }

    #[test]
    fn reads_the_icon_of_an_encrypted_basic_compressed_image() {
        let xex = build_xex(&xdbf(2, 0x8000, &icon()), &Layout::default());

        assert_eq!(from_xex(&xex).unwrap(), expected());
    }

    #[test]
    fn reads_the_icon_of_a_plain_uncompressed_image() {
        let xex = build_xex(
            &xdbf(2, 0x8000, &icon()),
            &Layout {
                encrypted: false,
                compression: COMPRESSION_NONE,
                ..Layout::default()
            },
        );

        assert_eq!(from_xex(&xex).unwrap(), expected());
    }

    #[test]
    fn reads_the_icon_of_an_encrypted_uncompressed_image() {
        let xex = build_xex(
            &xdbf(2, 0x8000, &icon()),
            &Layout {
                compression: COMPRESSION_NONE,
                ..Layout::default()
            },
        );

        assert_eq!(from_xex(&xex).unwrap(), expected());
    }

    #[test]
    fn a_development_kit_image_is_read_too() {
        let xex = build_xex(
            &xdbf(2, 0x8000, &icon()),
            &Layout {
                wrapping_key: DEVKIT_KEY,
                ..Layout::default()
            },
        );

        assert_eq!(from_xex(&xex).unwrap(), expected());
    }

    #[test]
    fn an_xdbf_without_a_title_icon_gives_none() {
        // A picture, but not the title icon (id 0x8000).
        let xex = build_xex(&xdbf(2, 0x1, &icon()), &Layout::default());

        assert_eq!(from_xex(&xex).unwrap(), None);
    }

    #[test]
    fn lzx_compressed_images_are_reported_as_unsupported() {
        let xex = build_xex(
            &xdbf(2, 0x8000, &icon()),
            &Layout {
                compression: 2,
                ..Layout::default()
            },
        );

        let error = from_xex(&xex).unwrap_err();
        assert!(format!("{error:#}").contains("LZX"), "{error:#}");
    }

    #[test]
    fn an_unknown_key_is_reported_instead_of_returning_garbage() {
        let xex = build_xex(
            &xdbf(2, 0x8000, &icon()),
            &Layout {
                wrapping_key: [7; 16],
                ..Layout::default()
            },
        );

        let error = from_xex(&xex).unwrap_err();
        assert!(format!("{error:#}").contains("key"), "{error:#}");
    }

    #[test]
    fn damaged_files_give_errors_and_never_panic() {
        let xex = build_xex(&xdbf(2, 0x8000, &icon()), &Layout::default());

        for length in (0..xex.len()).step_by(37) {
            let _ = from_xex(&xex[..length]);
        }

        // Garbage in every header field.
        for at in (0..0x420).step_by(4) {
            let mut damaged = xex.clone();
            damaged[at..at + 4].copy_from_slice(&[0xff; 4]);
            let _ = from_xex(&damaged);
        }

        assert!(from_xex(b"not an xex").is_err());
        assert!(from_xex(&[]).is_err());
    }
}
