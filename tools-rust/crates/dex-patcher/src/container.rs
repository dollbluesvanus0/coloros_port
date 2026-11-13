//! APK / JAR / DEX container reader and writer with 4-byte `zipalign` alignment
//! for uncompressed (`Stored`) ZIP entries (`classes*.dex`, `resources.arsc`, `*.so`, etc.).

use crate::dex::DexFile;
use anyhow::{bail, ensure, Context, Result};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

/// Returns `true` if `entry_name` is a DEX file inside an APK/JAR (e.g. `classes.dex`, `classes2.dex`).
pub fn is_dex_entry_name(entry_name: &str) -> bool {
    let base = entry_name.rsplit('/').next().unwrap_or(entry_name);
    (base.starts_with("classes") && base.ends_with(".dex")) || base.ends_with(".dex")
}

/// Returns `true` if `entry_name` should be stored uncompressed and 4-byte aligned in an APK/JAR.
pub fn should_store_aligned(entry_name: &str, original_method: CompressionMethod) -> bool {
    if original_method == CompressionMethod::Stored {
        return true;
    }
    let base = entry_name.rsplit('/').next().unwrap_or(entry_name);
    base == "resources.arsc" || (base.starts_with("classes") && base.ends_with(".dex"))
}

/// Apply `patch_fn` to a target file (which may be a raw `.dex` file or a `.apk`/`.jar`/`.zip` archive),
/// writing the result to `output_path` (or back to `input_path` if `output_path` is `None`).
///
/// Returns the total number of patches applied across all DEX images in the target.
pub fn patch_file_or_container<F>(
    input_path: &Path,
    output_path: Option<&Path>,
    mut patch_fn: F,
) -> Result<usize>
where
    F: FnMut(&str, &mut DexFile) -> Result<usize>,
{
    let raw_bytes =
        fs::read(input_path).with_context(|| format!("Failed to read {}", input_path.display()))?;
    let target_out = output_path.unwrap_or(input_path);

    if raw_bytes.starts_with(b"dex\n") {
        let mut dex = DexFile::parse(raw_bytes.clone())
            .with_context(|| format!("Failed to parse DEX file {}", input_path.display()))?;
        let count = patch_fn("classes.dex", &mut dex)?;
        if count > 0 {
            dex.update_hashes();
            write_atomic(target_out, &dex.data)?;
        } else if let Some(out) = output_path {
            if out != input_path {
                write_atomic(out, &raw_bytes)?;
            }
        }
        return Ok(count);
    }

    if raw_bytes.starts_with(b"PK\x03\x04") || raw_bytes.starts_with(b"PK\x05\x06") {
        let (new_zip_bytes, total_patched) = patch_zip_bytes(&raw_bytes, &mut patch_fn)
            .with_context(|| format!("Failed to patch ZIP container {}", input_path.display()))?;
        if total_patched > 0 {
            write_atomic(target_out, &new_zip_bytes)?;
        } else if let Some(out) = output_path {
            if out != input_path {
                write_atomic(out, &raw_bytes)?;
            }
        }
        return Ok(total_patched);
    }

    bail!(
        "Unsupported file format for {} (expected DEX or APK/JAR ZIP archive)",
        input_path.display()
    )
}

struct StoredEntry {
    name: String,
    data: Vec<u8>,
    method: CompressionMethod,
    unix_mode: Option<u32>,
    is_dir: bool,
    alignment: u16,
}

fn desired_stored_alignment(name: &str, orig_data_start: u64) -> u16 {
    if name.ends_with(".so") {
        if orig_data_start % 16384 == 0 {
            return 16384;
        }
        if orig_data_start % 4096 == 0 {
            return 4096;
        }
    }
    4
}

/// Patch all `classes*.dex` entries inside a ZIP archive in memory and repack with 4-byte alignment
/// for all uncompressed (`Stored`) entries.
pub fn patch_zip_bytes<F>(zip_bytes: &[u8], mut patch_fn: F) -> Result<(Vec<u8>, usize)>
where
    F: FnMut(&str, &mut DexFile) -> Result<usize>,
{
    let reader = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(reader).context("Invalid ZIP archive")?;

    let mut entries = Vec::with_capacity(archive.len());
    let mut total_patched = 0usize;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_string();
        let method = file.compression();
        let unix_mode = file.unix_mode();
        let is_dir = file.is_dir();
        let alignment = desired_stored_alignment(&name, file.data_start());

        let mut data = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut data)?;

        if !is_dir && is_dex_entry_name(&name) && data.starts_with(b"dex\n") {
            let mut dex = DexFile::parse(data)
                .with_context(|| format!("Failed to parse DEX entry {}", name))?;
            let count = patch_fn(&name, &mut dex)?;
            if count > 0 {
                dex.update_hashes();
                total_patched += count;
            }
            data = dex.data;
        }

        entries.push(StoredEntry {
            name,
            data,
            method,
            unix_mode,
            is_dir,
            alignment,
        });
    }

    let out_cursor = Cursor::new(Vec::with_capacity(zip_bytes.len() + 1024));
    let mut writer = ZipWriter::new(out_cursor);

    for entry in entries {
        if entry.is_dir {
            let mut opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            if let Some(mode) = entry.unix_mode {
                opts = opts.unix_permissions(mode);
            }
            writer.add_directory(&entry.name, opts)?;
            continue;
        }

        let store_uncompressed = should_store_aligned(&entry.name, entry.method);
        let method = if store_uncompressed {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };

        let mut opts = SimpleFileOptions::default().compression_method(method);
        if store_uncompressed {
            opts = opts.with_alignment(entry.alignment);
        }
        if let Some(mode) = entry.unix_mode {
            opts = opts.unix_permissions(mode);
        }

        writer.start_file(&entry.name, opts)?;
        writer.write_all(&entry.data)?;
    }

    let out_bytes = writer.finish()?.into_inner();
    Ok((out_bytes, total_patched))
}

/// Inspect a ZIP buffer and return `(entry_name, data_offset, compression_method)` for each entry
/// by walking the Central Directory and Local File Headers.
pub fn inspect_zip_data_offsets(zip_bytes: &[u8]) -> Result<Vec<(String, usize, CompressionMethod)>> {
    let reader = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(reader).context("Invalid ZIP archive")?;
    let mut results = Vec::with_capacity(archive.len());

    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        let method = file.compression();
        let data_offset = file.data_start() as usize;
        results.push((name, data_offset, method));
    }
    Ok(results)
}

/// Patch resources.arsc in memory inside a ZIP archive (or a raw resources.arsc buffer).
/// Repacks uncompressed with 4-byte alignment.
pub fn patch_arsc_in_container(
    input_path: &Path,
    output_path: Option<&Path>,
) -> Result<usize> {
    let raw_bytes = fs::read(input_path)
        .with_context(|| format!("Failed to read {}", input_path.display()))?;
    let target_out = output_path.unwrap_or(input_path);

    // Check if raw .arsc file: starts with RES_TABLE_TYPE (0x0002)
    if raw_bytes.len() >= 8 && u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]) == 0x0002 {
        let mut arsc_data = raw_bytes.clone();
        let count = crate::arsc::patch_arsc_buffer(&mut arsc_data);
        if count > 0 {
            write_atomic(target_out, &arsc_data)?;
        } else if let Some(out) = output_path {
            if out != input_path {
                write_atomic(out, &raw_bytes)?;
            }
        }
        return Ok(count);
    }

    // ZIP / APK container
    if raw_bytes.starts_with(b"PK\x03\x04") || raw_bytes.starts_with(b"PK\x05\x06") {
        let (new_zip_bytes, count) = patch_zip_arsc_bytes(&raw_bytes)
            .with_context(|| format!("Failed to patch ARSC in ZIP container {}", input_path.display()))?;
        if count > 0 {
            write_atomic(target_out, &new_zip_bytes)?;
        } else if let Some(out) = output_path {
            if out != input_path {
                write_atomic(out, &raw_bytes)?;
            }
        }
        return Ok(count);
    }

    bail!(
        "Unsupported file format for {} (expected resources.arsc or APK/ZIP archive)",
        input_path.display()
    )
}

/// Patch all `resources.arsc` entries inside a ZIP archive in memory and repack with 4-byte alignment
/// for all uncompressed (`Stored`) entries.
pub fn patch_zip_arsc_bytes(zip_bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
    let reader = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(reader).context("Invalid ZIP archive")?;

    let mut entries = Vec::with_capacity(archive.len());
    let mut total_patched = 0usize;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_string();
        let method = file.compression();
        let unix_mode = file.unix_mode();
        let is_dir = file.is_dir();
        let alignment = desired_stored_alignment(&name, file.data_start());

        let mut data = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut data)?;

        let base = name.rsplit('/').next().unwrap_or(&name);
        if !is_dir && base == "resources.arsc" {
            let count = crate::arsc::patch_arsc_buffer(&mut data);
            if count > 0 {
                total_patched += count;
            }
        }

        entries.push(StoredEntry {
            name,
            data,
            method,
            unix_mode,
            is_dir,
            alignment,
        });
    }

    let out_cursor = Cursor::new(Vec::with_capacity(zip_bytes.len() + 1024));
    let mut writer = ZipWriter::new(out_cursor);

    for entry in entries {
        if entry.is_dir {
            let mut opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            if let Some(mode) = entry.unix_mode {
                opts = opts.unix_permissions(mode);
            }
            writer.add_directory(&entry.name, opts)?;
            continue;
        }

        let store_uncompressed = should_store_aligned(&entry.name, entry.method);
        let method = if store_uncompressed {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };

        let mut opts = SimpleFileOptions::default().compression_method(method);
        if store_uncompressed {
            opts = opts.with_alignment(entry.alignment);
        }
        if let Some(mode) = entry.unix_mode {
            opts = opts.unix_permissions(mode);
        }

        writer.start_file(&entry.name, opts)?;
        writer.write_all(&entry.data)?;
    }

    let out_bytes = writer.finish()?.into_inner();
    Ok((out_bytes, total_patched))
}

/// Verify that every `Stored` (uncompressed) file entry in `zip_bytes` has a 4-byte aligned
/// data start offset (`data_offset % 4 == 0`).
pub fn verify_zip_alignment_4(zip_bytes: &[u8]) -> Result<()> {
    for (name, data_offset, method) in inspect_zip_data_offsets(zip_bytes)? {
        if method == CompressionMethod::Stored {
            ensure!(
                data_offset % 4 == 0,
                "Unaligned Stored ZIP entry '{}': data_offset={} (mod 4 = {})",
                name,
                data_offset,
                data_offset % 4
            );
        }
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, bytes).with_context(|| format!("Failed to write {}", path.display()))
}
