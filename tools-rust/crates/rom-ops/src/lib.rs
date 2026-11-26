//! Native Rust replacements for hot Python/Perl helpers in `bin/` and `port.sh`:
//! - `tree-size <dir>`: logical byte sum of regular files without following symlinks (`bin/tree_size.py`)
//! - `debloat <images_dir> <manifest>`: safe donor debloat with globbing & symlink-escape protection (`bin/debloat_rom.py`)
//! - `patch-vbmeta <img...>`: AVB vbmeta flag disabling (`bin/patch-vbmeta.py`)
//! - `strip-non-ascii [FILES...] [--dir <dir> [--name <glob>]]`: strip non-ASCII lines in-place

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use coloros_common::read_text_lossy;
use rayon::prelude::*;
use walkdir::WalkDir;

const AVB_MAGIC: &[u8; 4] = b"AVB0";
const VBMETA_FLAGS_OFFSET: u64 = 123;
const VBMETA_FLAGS_DISABLE: u8 = 0x03;

const ALLOWED_DEBLOAT_ROOTS: &[&str] = &["my_product", "my_stock", "my_preload", "system_ext"];

#[derive(Debug, Parser)]
#[command(
    name = "rom-ops",
    about = "Native Rust replacements for hot ROM porting helpers"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Measure logical byte size of regular files under a directory without following symlinks
    TreeSize {
        /// Directory to measure
        #[arg(value_name = "DIR")]
        dir: PathBuf,
    },

    /// Safely remove donor paths listed in a manifest with globbing & symlink-escape protection
    Debloat {
        /// Extracted images directory (containing my_product, my_stock, my_preload, ...)
        #[arg(value_name = "IMAGES_DIR")]
        images_dir: PathBuf,

        /// Debloat manifest file (e.g. bin/donor-debloat.txt)
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
    },

    /// Disable AVB verity/verification flags in one or more vbmeta images
    PatchVbmeta {
        /// One or more vbmeta*.img files to patch in-place
        #[arg(value_name = "IMG", required = true)]
        images: Vec<PathBuf>,
    },

    /// Strip lines containing non-ASCII bytes (>= 0x80) in-place
    StripNonAscii {
        /// Target file(s) to clean in-place
        #[arg(value_name = "FILES")]
        files: Vec<PathBuf>,

        /// Optional directory to scan recursively for files matching `--name`
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Filename glob filter when `--dir` is given (default: `*file_contexts`)
        #[arg(long, default_value = "*file_contexts")]
        name: String,
    },
}

/// Measure the logical byte sum (`st_size`) of regular files under `root` without following symlinks.
/// Matches `bin/tree_size.py`:
/// - Returns `0` if `root` itself is a symlink to a directory.
/// - Errors if `root` is empty, missing, or not a directory.
pub fn tree_size_bytes(root: &Path) -> Result<u64> {
    if root.as_os_str().is_empty() {
        bail!("Cannot measure tree size: empty path");
    }
    let root_sym_meta = fs::symlink_metadata(root)
        .with_context(|| format!("Cannot measure tree size: {}", root.display()))?;
    if root_sym_meta.file_type().is_symlink() {
        // Check if symlink points to a directory (matching Path(root).is_dir() then root.is_symlink() -> 0)
        if root.is_dir() {
            return Ok(0);
        }
        bail!("Not a directory: {}", root.display());
    }
    if !root_sym_meta.is_dir() {
        bail!("Not a directory: {}", root.display());
    }

    let mut pending = vec![root.to_path_buf()];
    let mut total: u64 = 0;

    while let Some(dir) = pending.pop() {
        let entries = fs::read_dir(&dir)
            .with_context(|| format!("Cannot read directory: {}", dir.display()))?;
        for entry_res in entries {
            let entry = entry_res?;
            let ftype = entry.file_type()?;
            if ftype.is_symlink() {
                continue;
            }
            if ftype.is_dir() {
                pending.push(entry.path());
            } else if ftype.is_file() {
                total += entry.metadata()?.len();
            }
        }
    }

    Ok(total)
}

/// Match a single filename component against a glob pattern supporting `*`, `?`, and `[...]` classes.
pub fn glob_match_component(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_chars(&pat, &txt)
}

fn glob_match_chars(pat: &[char], txt: &[char]) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < txt.len() {
        if pi < pat.len() && pat[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if pi < pat.len() && pat[pi] == '?' {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == '[' {
            if let Some((matched, next_pi)) = match_char_class(&pat[pi..], txt[ti]) {
                if matched {
                    pi += next_pi;
                    ti += 1;
                    continue;
                }
            } else if pat[pi] == txt[ti] {
                pi += 1;
                ti += 1;
                continue;
            }
            if let Some(sp) = star_pi {
                pi = sp + 1;
                star_ti += 1;
                ti = star_ti;
            } else {
                return false;
            }
        } else if pi < pat.len() && pat[pi] == txt[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

fn match_char_class(pat: &[char], ch: char) -> Option<(bool, usize)> {
    // Expect `[...]` starting at pat[0] == '['
    let mut i = 1usize;
    if i >= pat.len() {
        return None;
    }
    let negate = if pat[i] == '!' || pat[i] == '^' {
        i += 1;
        true
    } else {
        false
    };
    let mut matched = false;
    let mut first = true;
    while i < pat.len() {
        if pat[i] == ']' && !first {
            return Some((if negate { !matched } else { matched }, i + 1));
        }
        first = false;
        if i + 2 < pat.len() && pat[i + 1] == '-' && pat[i + 2] != ']' {
            let start = pat[i];
            let end = pat[i + 2];
            if start <= ch && ch <= end {
                matched = true;
            }
            i += 3;
        } else {
            if pat[i] == ch {
                matched = true;
            }
            i += 1;
        }
    }
    None
}

fn validate_debloat_pattern(pattern: &str) -> Result<Vec<String>> {
    let normalized = pattern.replace('\\', "/");
    let p = Path::new(&normalized);
    if p.is_absolute() || normalized.starts_with('/') {
        bail!("Unsafe debloat path: {pattern}");
    }
    let mut parts = Vec::new();
    for comp in p.components() {
        match comp {
            Component::Normal(s) => {
                let s_str = s.to_string_lossy().into_owned();
                parts.push(s_str);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("Unsafe debloat path: {pattern}");
            }
        }
    }
    if parts.len() < 2 || !ALLOWED_DEBLOAT_ROOTS.contains(&parts[0].as_str()) {
        bail!("Unsafe debloat path: {pattern}");
    }
    Ok(parts)
}

fn expand_glob_under_root(canonical_root: &Path, parts: &[String]) -> Result<Vec<PathBuf>> {
    let mut current = vec![canonical_root.to_path_buf()];

    for (idx, comp_pat) in parts.iter().enumerate() {
        let is_last = idx + 1 == parts.len();
        let has_glob = comp_pat.contains('*') || comp_pat.contains('?') || comp_pat.contains('[');
        let mut next = Vec::new();

        for dir in current {
            let dir_meta = match fs::symlink_metadata(&dir) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if dir_meta.file_type().is_symlink() {
                let canon_dir = fs::canonicalize(&dir)
                    .with_context(|| format!("Cannot resolve symlink ancestor: {}", dir.display()))?;
                ensure!(
                    canon_dir.starts_with(canonical_root),
                    "Unsafe symlink escape in parent directory: {}",
                    dir.display()
                );
            }
            if !dir.is_dir() {
                continue;
            }

            if !has_glob {
                let candidate = dir.join(comp_pat);
                if fs::symlink_metadata(&candidate).is_ok() {
                    if !is_last {
                        if let Ok(canon) = fs::canonicalize(&candidate) {
                            ensure!(
                                canon.starts_with(canonical_root),
                                "Unsafe symlink escape in parent directory: {}",
                                candidate.display()
                            );
                        }
                    }
                    next.push(candidate);
                }
            } else {
                let entries = match fs::read_dir(&dir) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for entry_res in entries {
                    let entry = entry_res?;
                    let fname = entry.file_name();
                    let fname_str = fname.to_string_lossy();
                    if glob_match_component(comp_pat, &fname_str) {
                        let candidate = entry.path();
                        if !is_last {
                            if let Ok(canon) = fs::canonicalize(&candidate) {
                                ensure!(
                                    canon.starts_with(canonical_root),
                                    "Unsafe symlink escape in parent directory: {}",
                                    candidate.display()
                                );
                            }
                        }
                        next.push(candidate);
                    }
                }
            }
        }

        current = next;
        if current.is_empty() {
            break;
        }
    }

    // Final parent check for every matched leaf (matching `path.parent.resolve().relative_to(root)`).
    for target in &current {
        let parent = target.parent().context("Target missing parent")?;
        let canon_parent = fs::canonicalize(parent)
            .with_context(|| format!("Cannot canonicalize parent: {}", parent.display()))?;
        ensure!(
            canon_parent.starts_with(canonical_root),
            "Unsafe symlink escape in parent of: {}",
            target.display()
        );
    }

    Ok(current)
}

fn remove_path_no_follow(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        // On Unix `remove_file` unlinks symlinks; on Windows a directory symlink needs `remove_dir`.
        if fs::remove_file(path).is_err() {
            fs::remove_dir(path)?;
        }
    } else if meta.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Execute donor debloat matching `bin/debloat_rom.py`.
/// Pre-validates ALL manifest patterns and symlink safety before performing any deletions.
pub fn debloat_rom(images_dir: &Path, manifest_path: &Path) -> Result<Vec<String>> {
    let canonical_root = fs::canonicalize(images_dir)
        .with_context(|| format!("Images directory not found: {}", images_dir.display()))?;
    ensure!(
        canonical_root.is_dir(),
        "Not a directory: {}",
        images_dir.display()
    );

    let manifest_text = read_text_lossy(manifest_path)
        .with_context(|| format!("Failed to read debloat manifest: {}", manifest_path.display()))?;

    let mut parsed_patterns = Vec::new();
    for raw in manifest_text.lines() {
        let pat = raw.trim();
        if pat.is_empty() || pat.starts_with('#') {
            continue;
        }
        parsed_patterns.push(validate_debloat_pattern(pat)?);
    }

    let mut target_set: HashSet<PathBuf> = HashSet::new();
    for parts in &parsed_patterns {
        for matched in expand_glob_under_root(&canonical_root, parts)? {
            target_set.insert(matched);
        }
    }

    let mut sorted_targets: Vec<PathBuf> = target_set.into_iter().collect();
    sorted_targets.sort_by(|a, b| {
        let ca = a.components().count();
        let cb = b.components().count();
        ca.cmp(&cb).then_with(|| a.cmp(b))
    });

    let mut removed = Vec::new();
    for path in sorted_targets {
        if fs::symlink_metadata(&path).is_err() {
            continue;
        }
        remove_path_no_follow(&path)
            .with_context(|| format!("Failed to remove {}", path.display()))?;
        let rel = path
            .strip_prefix(&canonical_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        println!("Debloat: removed {rel}");
        removed.push(rel);
    }
    println!("Debloat: removed {} paths", removed.len());
    Ok(removed)
}

/// Disable AVB verity & verification flags (`0x03` at offset 123) in a vbmeta image.
pub fn patch_vbmeta_file(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("Error reading file: {}", path.display()))?;

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).with_context(|| {
        format!(
            "Error: The provided image is not a valid vbmeta image: {}",
            path.display()
        )
    })?;
    ensure!(
        &magic == AVB_MAGIC,
        "Error: The provided image is not a valid vbmeta image ({}).",
        path.display()
    );

    let len = file.metadata()?.len();
    ensure!(
        len > VBMETA_FLAGS_OFFSET,
        "Error: vbmeta image too small ({} bytes): {}",
        len,
        path.display()
    );

    file.seek(SeekFrom::Start(VBMETA_FLAGS_OFFSET))?;
    file.write_all(&[VBMETA_FLAGS_DISABLE])?;
    Ok(())
}

/// Strip lines containing any non-ASCII byte (`>= 0x80`) from `bytes`.
/// Matches `perl -i -ne 'print if /^[\x00-\x7F]+$/'`.
pub fn strip_non_ascii_bytes(bytes: &[u8]) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(bytes.len());
    let mut removed = 0usize;

    for line in bytes.split_inclusive(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if line.iter().all(|&b| b <= 0x7F) {
            out.extend_from_slice(line);
        } else {
            removed += 1;
        }
    }

    (out, removed)
}

/// Clean a file in-place, returning the number of non-ASCII lines removed.
pub fn strip_non_ascii_file(path: &Path) -> Result<usize> {
    let raw = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let (cleaned, removed) = strip_non_ascii_bytes(&raw);
    if removed > 0 {
        fs::write(path, &cleaned).with_context(|| format!("Failed to write {}", path.display()))?;
    }
    Ok(removed)
}

pub fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::TreeSize { dir } => {
            let size = tree_size_bytes(&dir)?;
            println!("{size}");
            Ok(())
        }

        Commands::Debloat {
            images_dir,
            manifest,
        } => {
            debloat_rom(&images_dir, &manifest)?;
            Ok(())
        }

        Commands::PatchVbmeta { images } => {
            for img in &images {
                patch_vbmeta_file(img)?;
                println!("Patching successful.");
            }
            Ok(())
        }

        Commands::StripNonAscii { files, dir, name } => {
            let mut targets = files;
            if let Some(d) = dir {
                if d.exists() {
                    for entry in WalkDir::new(&d).into_iter().filter_map(|e| e.ok()) {
                        if entry.file_type().is_file() {
                            let fname = entry.file_name().to_string_lossy();
                            if glob_match_component(&name, &fname) {
                                targets.push(entry.into_path());
                            }
                        }
                    }
                }
            }
            targets.sort();
            targets.dedup();

            let total_removed: usize = targets
                .par_iter()
                .map(|p| strip_non_ascii_file(p))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .sum();

            println!(
                "[+] rom-ops strip-non-ascii: removed {total_removed} non-ASCII line(s) across {} file(s)",
                targets.len()
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_tree_size_logical_and_errors() {
        let td = TempDir::new().unwrap();
        let root = td.path();
        fs::create_dir_all(root.join("sub dir")).unwrap();
        fs::write(root.join("sub dir/a.txt"), b"abc").unwrap();
        fs::write(root.join("b.bin"), vec![0u8; 1024]).unwrap();

        assert_eq!(tree_size_bytes(root).unwrap(), 1027);
        assert!(tree_size_bytes(&root.join("b.bin")).is_err());
        assert!(tree_size_bytes(&root.join("missing")).is_err());
        assert!(tree_size_bytes(Path::new("")).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(root.join("sub dir"), root.join("dir_link")).unwrap();
            symlink(root.join("b.bin"), root.join("file_link")).unwrap();
            symlink(root.join("absent"), root.join("dangling_link")).unwrap();
            assert_eq!(tree_size_bytes(root).unwrap(), 1027);
            assert_eq!(tree_size_bytes(&root.join("dir_link")).unwrap(), 0);
        }
    }

    #[test]
    fn test_debloat_manifest_glob_and_safety() {
        let td = TempDir::new().unwrap();
        let images = td.path().join("images");
        fs::create_dir_all(&images).unwrap();

        let put = |rel: &str| {
            let p = images.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"fixture").unwrap();
            p
        };

        let del1 = put("my_stock/app/Browser/Browser.apk");
        let del2 = put("my_product/overlay/SystemUiFingerprintResOne/overlay.apk");
        let keep1 = put("my_stock/app/BrowserExtra/Keep.apk");
        let keep2 = put("vendor/app/Browser/Keep.apk");

        let manifest = td.path().join("debloat.txt");
        fs::write(
            &manifest,
            "# comment\nmy_stock/app/Browser\nmy_product/overlay/SystemUiFingerprintRes*\n",
        )
        .unwrap();

        let removed = debloat_rom(&images, &manifest).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(!del1.exists());
        assert!(!del2.exists());
        assert!(keep1.exists());
        assert!(keep2.exists());
        assert!(debloat_rom(&images, &manifest).unwrap().is_empty());

        // Unsafe manifest must fail BEFORE deleting anything
        let keep_target = put("my_stock/app/Browser/keep.apk");
        let bad_manifest = td.path().join("bad.txt");
        fs::write(&bad_manifest, "my_stock/app/Browser\n../outside\n").unwrap();
        assert!(debloat_rom(&images, &bad_manifest).is_err());
        assert!(keep_target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_debloat_symlink_safety_unix() {
        use std::os::unix::fs::symlink;
        let td = TempDir::new().unwrap();
        let images = td.path().join("images");
        let outside = td.path().join("outside");
        fs::create_dir_all(&images).unwrap();
        fs::create_dir_all(outside.join("del-app")).unwrap();
        fs::write(outside.join("del-app/keep"), b"keep").unwrap();

        let manifest = td.path().join("m.txt");
        fs::write(&manifest, "my_product/del-app\n").unwrap();

        // 1. Escaping parent symlink must fail
        symlink(&outside, images.join("my_product")).unwrap();
        assert!(debloat_rom(&images, &manifest).is_err());
        assert!(outside.join("del-app/keep").exists());
        fs::remove_file(images.join("my_product")).unwrap();

        // 2. Leaf symlink removed without touching target
        fs::create_dir_all(images.join("my_product")).unwrap();
        symlink(&outside, images.join("my_product/del-app")).unwrap();
        let removed = debloat_rom(&images, &manifest).unwrap();
        assert_eq!(removed, vec!["my_product/del-app"]);
        assert!(outside.join("del-app/keep").exists());
    }

    #[test]
    fn test_patch_vbmeta_multiple_and_invalid() {
        let td = TempDir::new().unwrap();
        let vb1 = td.path().join("vbmeta.img");
        let vb2 = td.path().join("vbmeta_system.img");
        let bad = td.path().join("bad.img");

        let mut img_bytes = vec![0u8; 256];
        img_bytes[0..4].copy_from_slice(b"AVB0");
        fs::write(&vb1, &img_bytes).unwrap();
        fs::write(&vb2, &img_bytes).unwrap();
        fs::write(&bad, b"NOT_AVB_IMAGE_123456").unwrap();

        run_cli(Cli {
            command: Commands::PatchVbmeta {
                images: vec![vb1.clone(), vb2.clone()],
            },
        })
        .unwrap();

        assert_eq!(fs::read(&vb1).unwrap()[123], 0x03);
        assert_eq!(fs::read(&vb2).unwrap()[123], 0x03);
        assert!(patch_vbmeta_file(&bad).is_err());
    }

    #[test]
    fn test_strip_non_ascii() {
        let td = TempDir::new().unwrap();
        let fc = td.path().join("system_file_contexts");
        fs::write(
            &fc,
            "/system/bin/sh u:object_r:shell_exec:s0\n/system/中文路径 u:object_r:system_file:s0\n\n/system/app/Foo u:object_r:system_file:s0\n",
        )
        .unwrap();

        run_cli(Cli {
            command: Commands::StripNonAscii {
                files: vec![],
                dir: Some(td.path().to_path_buf()),
                name: "*file_contexts".to_string(),
            },
        })
        .unwrap();

        let cleaned = fs::read_to_string(&fc).unwrap();
        assert_eq!(
            cleaned,
            "/system/bin/sh u:object_r:shell_exec:s0\n\n/system/app/Foo u:object_r:system_file:s0\n"
        );
    }
}
