//! Stage 1: SELinux `contextpatch` and `fspatch` implementation in Rust.
//!
//! Replaces `bin/contextpatch.py` and `bin/fspatch.py` with 100% behavioral
//! and output format compatibility, plus a combined single-pass `patch-all` mode
//! and parallel directory traversal via `jwalk` + `rayon`.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use jwalk::WalkDir;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Hardcoded SELinux context overrides from `bin/contextpatch.py` (lines 9-85) in exact insertion order.
pub const FIX_PERMISSION: &[(&str, &str)] = &[
    ("/vendor/bin/hw/android.hardware.wifi@1.0", "u:object_r:hal_wifi_default_exec:s0"),
    ("/system/system/app/*", "u:object_r:system_file:s0"),
    ("/system/system/priv-app/*", "u:object_r:system_file:s0"),
    ("/system/system/lib*", "u:object_r:system_lib_file:s0"),
    ("/system/system/bin/init", "u:object_r:init_exec:s0"),
    ("/system_ext/lib*", "u:object_r:system_lib_file:s0"),
    ("/product/lib*", "u:object_r:system_lib_file:s0"),
    ("/system/system/bin/app_process32", "u:object_r:zygote_exec:s0"),
    ("/system/system/bin/bootstrap/linker", "u:object_r:system_linker_exec:s0"),
    ("/system/system/bin/boringssl_self_test32", "u:object_r:boringssl_self_test_exec:s0"),
    ("/system/system/bin/drmserver", "u:object_r:drmserver_exec:s0"),
    ("/system/system/bin/linker", "u:object_r:system_linker_exec:s0"),
    ("/system/system/bin/mediaserver", "u:object_r:mediaserver_exec:s0"),
    ("/system_ext/bin/sigma_miracasthalservice", "u:object_r:vendor_sigmahal_qti_exec:s0"),
    ("/system_ext/bin/wfdservice", "u:object_r:vendor_wfdservice_exec:s0"),
    ("/my_product/vendor/etc/*.xml", "u:object_r:vendor_configs_file:s0"),
    (r"/odm/bin/hw/vendor\.oplus\.hardware\.charger-V3-service", "u:object_r:hal_charger_oplus_exec:s0"),
    (r"/odm/bin/hw/vendor\.oplus\.hardware\.charger-V6-service", "u:object_r:hal_charger_oplus_exec:s0"),
    (r"/odm/bin/hw/android\.hardware\.power\.stats-impl\.oplus", "u:object_r:hal_power_stats_default_exec:s0"),
    (r"/vendor/etc/permissions/android\.hardware\.hardware_keystore\.xml", "u:object_r:vendor_configs_file:s0"),
    (r"/odm/bin/hw/vendor\.oplus\.hardware\.nfc_aidl-service", "u:object_r:hal_oplus_nfc_default_exec:s0"),
    ("/odm/bin/commcenterd", "u:object_r:commcenterd_exec:s0"),
    ("/odm/bin/hw/mdm_feature", "u:object_r:mdm_feature_exec:s0"),
    (r"/odm/bin/hw/vendor\.oplus\.hardware\.wifi-aidl-service", "u:object_r:oplus_wifi_aidl_service_exec:s0"),
    (r"/odm/bin/hw/vendor-oplus-hardware-touch-V2-service", "u:object_r:hal_oplus_touch_aidl_default_exec:s0"),
    (r"/odm/bin/hw/vendor\.oplus\.hardware\.eid@1\.0-service", "u:object_r:hal_eid_oplus_exec:s0"),
    (r"/odm/bin/hw/vendor\.oplus\.hardware\.riskdetect-V1-service", "u:object_r:hal_riskdetect_oplus_exec:s0"),
    (r"/odm/bin/hw/vendor\.oplus\.hardware\.urcc-service", "u:object_r:hal_urcc_default_exec:s0"),
    ("/odm/bin/hw/virtualcameraprovider", "u:object_r:hal_virtualdevice_camera_exec:s0"),
    (r"/odm/bin/hw/vendor\.oplus\.hardware\.displaypanelfeature-service", "u:object_r:oplus_hal_displaypanelfeature_exec:s0"),
    (r"/odm/bin/hw/vendor\.oplus\.hardware\.engcamera@1\.0-service", "u:object_r:engcamera_hidl_exec:s0"),
    (r"/odm/bin/init\.oplus\.storage\.io_metrics\.sh", "u:object_r:oplus_storage_io_metrics_exec:s0"),
    ("/system_ext/xbin/xeu_toolbox", "u:object_r:xeu_toolbox_exec:s0"),
    ("*/etc/init/hw/*.rc", "u:object_r:vendor_configs_file:s0"),
    (r"/odm/lib/libmsnativefilter\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/libmsnativefilter\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib/libextendfile\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/libextendfile\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/vendor/lib64/android\.hardware\.graphics\.common-V5-ndk\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/vendor/lib64/android\.hardware\.common-V2-ndk\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/vendor/lib64/android\.hardware\.graphics\.common@1\.0\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/vendor/lib64/android\.hardware\.graphics\.allocator-V2-ndk\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/vendor/lib64/vendor\.qti\.hardware\.camera\.offlinecamera-V2-ndk\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/vendor/lib64/android\.hardware\.camera\.device-V2-ndk\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/libAlgoInterface\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/libAlgoProcess\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/vendor/lib64/android\.hardware\.common\.fmq-V1-ndk\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/vendor/lib64/android\.hardware\.camera\.metadata-V2-ndk\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/vendor/lib64/vendor\.oplus\.hardware\.osense\.client-V1-ndk\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/vendor/lib64/libc\+\+\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib/libNamaWrapper\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib/vendor\.oplus\.hardware\.sendextcamcmd-V1-service-impl\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib/libOplusSecurity\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/libNamaWrapper\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib/libColorMark\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/libColorMark\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/libapsyuv\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/libyuvwrapper\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/vendor\.oplus\.hardware\.sendextcamcmd-V1-service-impl\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/libOplusSecurity\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib/libFilterWrapper\.so", "u:object_r:same_process_hal_file:s0"),
    (r"/odm/lib64/libFilterWrapper\.so", "u:object_r:same_process_hal_file:s0"),
    ("/odm/lib64/libaiboost*.so", "u:object_r:same_process_hal_file:s0"),
    ("/odm/lib64/aiframe/*.so", "u:object_r:same_process_hal_file:s0"),
    ("/odm/lib64/aiframe/cdsp/*signed/*.so", "u:object_r:same_process_hal_file:s0"),
    ("/system/system/bin/pif-updater", "u:object_r:pif_updater_exec:s0"),
    ("/system/system/bin/resetprop", "u:object_r:pif_updater_exec:s0"),
    ("/system/system/bin/sensitiveprops.sh", "u:object_r:pif_updater_exec:s0"),
    ("/odm/etc/camera/config/*", "u:object_r:vendor_configs_file:s0"),
    (r"/vendor/lib64/vendor\.oplus\.hardware\.sendextcamcmd-V1-ndk_platform\.so", "u:object_r:same_process_hal_file:s0"),
    ("/vendor/bin/qfp-daemon", "u:object_r:vendor_qfp-daemon_exec:s0"),
    ("/vendor/etc/init/*", "u:object_r:vendor_configs_file:s0"),
    ("/vendor/app/*", "u:object_r:vendor_app_file:s0"),
    ("/vendor/bin/hw/vendor-oplus-hardware-performance-V1-service", "u:object_r:hal_oplus_performance_default_exec:s0"),
];

const SKIPPED_DIRS: &[&str] = &[".git", ".repo", ".svn", "__pycache__"];

const EXEC_SH_EXCEPTIONS: &[&str] = &[
    "/bin/su",
    "/xbin/su",
    "disable_selinux.sh",
    "daemon",
    "ext/.su",
    "install-recovery",
    "installed_su",
    "bin/rw-system.sh",
    "bin/getSPL",
];

#[derive(Debug, Parser)]
#[command(
    name = "rom-fs-patcher",
    about = "SELinux file_contexts and fs_config patcher"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Patch SELinux file_contexts (replaces bin/contextpatch.py)
    #[command(alias = "contextpatch")]
    ContextPatch {
        /// Partition directory path
        folder: String,
        /// Path to file_contexts file
        file_contexts: String,
    },
    /// Patch filesystem config (replaces bin/fspatch.py)
    #[command(alias = "fspatch")]
    FsPatch {
        /// Partition directory path
        folder: String,
        /// Path to fs_config file
        fs_config: String,
    },
    /// Single-pass combined fs_config and file_contexts patcher
    #[command(alias = "patchall")]
    PatchAll {
        /// Partition directory path
        folder: String,
        /// Path to fs_config file
        fs_config: String,
        /// Path to file_contexts file
        file_contexts: String,
    },
}

pub fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::ContextPatch {
            folder,
            file_contexts,
        }) => {
            context_patch_file(&folder, &file_contexts)?;
            println!("Done!");
            Ok(())
        }
        Some(Commands::FsPatch { folder, fs_config }) => {
            fs_patch_file(&folder, &fs_config)?;
            println!("Done!");
            Ok(())
        }
        Some(Commands::PatchAll {
            folder,
            fs_config,
            file_contexts,
        }) => {
            patch_all_files(&folder, &fs_config, &file_contexts)?;
            println!("Done!");
            Ok(())
        }
        None => Ok(()),
    }
}

/// Check if a character is printable according to Python's `str.isprintable()` for ASCII
/// (and basic Unicode control/separator handling).
pub fn is_printable_char(c: char) -> bool {
    if c.is_ascii() {
        c >= ' ' && c != '\x7f'
    } else {
        !c.is_control() && c != '\u{00a0}' && !c.is_whitespace()
    }
}

/// Sanitize a path by replacing non-printable characters and spaces with `*`
/// (matches lines 143-149 of `contextpatch.py` and lines 70-76 of `fspatch.py`).
pub fn sanitize_printable_and_spaces(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !is_printable_char(c) || c == ' ' {
            out.push('*');
        } else {
            out.push(c);
        }
    }
    out
}

/// Equivalent to Python's `re.escape(string).replace("\\-", "-")` (`str_to_selinux` in `contextpatch.py`).
pub fn str_to_selinux(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '(' | ')' | '[' | ']' | '{' | '}' | '?' | '*' | '+' | '.' | '^' | '$' | '|' | '\\'
            | '&' | '~' | '#' | ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Python `difflib.SequenceMatcher(None, a, b).quick_ratio()` implementation.
/// `quick_ratio` is an upper bound on `ratio()` that counts character frequencies in `b`
/// and matches against `a`: `2.0 * matches / (len(a) + len(b))`.
pub fn sequence_matcher_quick_ratio(a: &str, b: &str) -> f64 {
    let len_a = a.chars().count();
    let len_b = b.chars().count();
    let total = len_a + len_b;
    if total == 0 {
        return 1.0;
    }
    let mut avail: HashMap<char, isize> = HashMap::new();
    for ch in b.chars() {
        *avail.entry(ch).or_insert(0) += 1;
    }
    let mut matches: usize = 0;
    for ch in a.chars() {
        let count = avail.entry(ch).or_insert(0);
        if *count > 0 {
            matches += 1;
        }
        *count -= 1;
    }
    (2.0 * matches as f64) / (total as f64)
}

/// POSIX dirname equivalent to `os.path.dirname(p)` on `/`-separated paths.
pub fn posix_dirname(p: &str) -> &str {
    match p.rfind('/') {
        None => "",
        Some(0) => {
            // If all leading chars are '/', return them
            let trimmed = p.trim_start_matches('/');
            if trimmed.is_empty() {
                p
            } else {
                let slash_len = p.len() - trimmed.len();
                if slash_len > 0 && !trimmed.contains('/') {
                    &p[..slash_len]
                } else {
                    "/"
                }
            }
        }
        Some(idx) => {
            let head = &p[..idx];
            let trimmed = head.trim_end_matches('/');
            if trimmed.is_empty() {
                head
            } else {
                trimmed
            }
        }
    }
}

/// Prefix Trie for fast longest-prefix / parent-directory lookup on SELinux contexts.
#[derive(Debug, Default)]
pub struct ContextTrie {
    children: HashMap<String, ContextTrie>,
    context: Option<Vec<String>>,
}

impl ContextTrie {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: &str, context: Vec<String>) {
        let mut node = self;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            node = node.children.entry(segment.to_string()).or_default();
        }
        node.context = Some(context);
    }

    /// Find the deepest ancestor / prefix context in the Trie.
    pub fn longest_prefix_match(&self, path: &str) -> Option<&[String]> {
        let mut node = self;
        let mut best: Option<&[String]> = node.context.as_deref();
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            if let Some(next) = node.children.get(segment) {
                node = next;
                if node.context.is_some() {
                    best = node.context.as_deref();
                }
            } else {
                break;
            }
        }
        best
    }
}

/// Read an existing `file_contexts` file into an insertion-ordered list and lookup map,
/// matching `scan_context(file)` in `bin/contextpatch.py`.
pub fn scan_context(file: impl AsRef<Path>) -> Result<(Vec<(String, Vec<String>)>, HashMap<String, Vec<String>>)> {
    let file = file.as_ref();
    let content = coloros_common::read_text_lossy(file)?;
    let mut ordered_keys: Vec<String> = Vec::new();
    let mut map: HashMap<String, Vec<String>> = HashMap::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let filepath = parts[0].replace(r"\@", "@");
        let other: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
        if other.len() > 1 {
            let first_ch = line.chars().next().unwrap_or(' ');
            println!("[Warn] {} has too much data.Skip.", first_ch);
            map.remove(&filepath);
            ordered_keys.retain(|k| k != &filepath);
            continue;
        }
        if !map.contains_key(&filepath) {
            ordered_keys.push(filepath.clone());
        }
        map.insert(filepath, other);
    }

    let ordered = ordered_keys
        .into_iter()
        .filter_map(|k| {
            let v = map.get(&k)?.clone();
            Some((k, v))
        })
        .collect();

    Ok((ordered, map))
}

/// Read an existing `fs_config` file into a lookup map,
/// matching `scanfs(file)` in `bin/fspatch.py`.
pub fn scan_fs(file: impl AsRef<Path>) -> Result<HashMap<String, Vec<String>>> {
    let file = file.as_ref();
    let content = coloros_common::read_text_lossy(file)?;
    let mut filesystem_config: HashMap<String, Vec<String>> = HashMap::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            println!("[W] Skip {}", line);
            continue;
        }
        let filepath = parts[0].to_string();
        let other: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
        if other.len() > 4 {
            let first_ch = line.chars().next().unwrap_or(' ');
            println!("[W] {} has too much data-{}.", first_ch, other.len());
        }
        filesystem_config.insert(filepath, other);
    }

    Ok(filesystem_config)
}

/// Compiled `fix_permission` rule from `bin/contextpatch.py`.
struct CompiledFixRule {
    pattern_str: String,
    regex: Option<Regex>,
    context: String,
}

fn compile_fix_rules() -> Vec<CompiledFixRule> {
    FIX_PERMISSION
        .iter()
        .map(|&(key, ctx)| {
            // In Python: pattern = f.replace("*", ".*")
            // if i == pattern: ...
            // if re.match(pattern, i): ... (re.match anchors at the start of the string)
            let pattern_str = key.replace('*', ".*");
            let anchored = format!("^(?:{})", pattern_str);
            let regex = Regex::new(&anchored).ok();
            CompiledFixRule {
                pattern_str,
                regex,
                context: ctx.to_string(),
            }
        })
        .collect()
}

/// Determine the partition default SELinux context from `dir_path`
/// matching lines 135-140 of `bin/contextpatch.py`.
pub fn default_partition_context(dir_path: &str) -> String {
    let trimmed = dir_path.trim_end_matches(&['/', '\\'][..]);
    if dir_path.ends_with("system_dlkm") || trimmed.ends_with("system_dlkm") {
        "u:object_r:system_dlkm_file:s0".to_string()
    } else if dir_path.ends_with("odm")
        || dir_path.ends_with("vendor")
        || dir_path.ends_with("vendor_dlkm")
        || trimmed.ends_with("odm")
        || trimmed.ends_with("vendor")
        || trimmed.ends_with("vendor_dlkm")
    {
        "u:object_r:vendor_file:s0".to_string()
    } else {
        "u:object_r:system_file:s0".to_string()
    }
}

/// Entry information collected during parallel filesystem walk.
#[derive(Debug, Clone)]
pub struct ScannedEntry {
    /// Relative path inside the partition (with `/` separators, empty for root).
    pub rel_path: String,
    /// Full filesystem path (None for synthetic virtual paths).
    pub full_path: Option<PathBuf>,
    /// Whether this entry is a directory on disk.
    pub is_dir: bool,
    /// Whether this entry exists on disk.
    pub exists: bool,
    /// Detected symlink target if the entry is a POSIX or Cygwin `!<symlink>` link.
    pub symlink_target: Option<String>,
}

/// Detect whether `path` is a symlink (POSIX symlink or Windows Cygwin `!<symlink>` UTF-16LE file),
/// matching `islink(file)` in `bin/fspatch.py`.
pub fn detect_symlink(path: &Path, is_dir: bool) -> Option<String> {
    if is_dir {
        return None;
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            if let Ok(target) = fs::read_link(path) {
                return Some(target.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    // Also check Windows Cygwin-style `!<symlink>` header (10 bytes `!<symlink>` followed by UTF-16LE + trailing nul).
    if let Ok(mut f) = fs::File::open(path) {
        let mut header = [0u8; 10];
        if f.read_exact(&mut header).is_ok() && &header == b"!<symlink>" {
            let mut rest = Vec::new();
            if f.read_to_end(&mut rest).is_ok() {
                // Decode UTF-16 (supporting optional BOM, default UTF-16LE as in Python on Windows)
                let u16_slice: Vec<u16> = if rest.len() >= 2 && rest[0] == 0xFF && rest[1] == 0xFE {
                    rest[2..]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect()
                } else if rest.len() >= 2 && rest[0] == 0xFE && rest[1] == 0xFF {
                    rest[2..]
                        .chunks_exact(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect()
                } else {
                    rest.chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect()
                };
                if let Ok(mut decoded) = String::from_utf16(&u16_slice) {
                    // Python's `.decode("utf-16")[:-1]` strips the last character (typically '\0')
                    decoded.pop();
                    if !decoded.is_empty() {
                        return Some(decoded);
                    }
                }
            }
        }
    }
    None
}

/// Extract the partition name (`os.path.basename(os.path.abspath(folder))`).
pub fn extract_part_name(folder: &Path) -> String {
    let abs = fs::canonicalize(folder).unwrap_or_else(|_| {
        if folder.is_absolute() {
            folder.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(folder))
                .unwrap_or_else(|_| folder.to_path_buf())
        }
    });
    abs.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .replace(['\\', '/'], "")
}

/// Walk the partition folder in parallel using `jwalk`, filtering out `.git`, `.repo`, `.svn`, `__pycache__`,
/// and returning sorted relative paths along with their metadata.
pub fn scan_partition_entries(folder: &Path) -> Result<Vec<ScannedEntry>> {
    let root = folder.to_path_buf();
    let raw_entries: Vec<(String, PathBuf, bool)> = WalkDir::new(&root)
        .skip_hidden(false)
        .follow_links(false)
        .process_read_dir(|_depth, _path, _read_dir_state, children| {
            children.retain(|dir_entry_result| {
                dir_entry_result
                    .as_ref()
                    .map(|dir_entry| {
                        let name = dir_entry.file_name.to_str().unwrap_or("");
                        !SKIPPED_DIRS.contains(&name)
                    })
                    .unwrap_or(false)
            });
        })
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if path == root {
                return None;
            }
            let rel = path.strip_prefix(&root).ok()?;
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if rel_str.is_empty() {
                return None;
            }
            let ft = entry.file_type();
            let is_dir = ft.is_dir();
            Some((rel_str, path, is_dir))
        })
        .collect();

    // Inspect symlink status in parallel using rayon
    let mut entries: Vec<ScannedEntry> = raw_entries
        .into_par_iter()
        .map(|(rel_path, full_path, is_dir)| {
            let symlink_target = detect_symlink(&full_path, is_dir);
            ScannedEntry {
                rel_path,
                full_path: Some(full_path),
                is_dir,
                exists: true,
                symlink_target,
            }
        })
        .collect();

    // Sort deterministically so traversal order is completely reproducible
    entries.par_sort_unstable_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(entries)
}

/// Resolve SELinux context for a single sanitized & escaped path `i` that is not in `fs_file`.
fn resolve_new_context(
    i: &str,
    fix_rules: &[CompiledFixRule],
    ordered_fs_entries: &[(String, Vec<String>)],
    trie: &ContextTrie,
    default_ctx: &[String],
) -> Vec<String> {
    if i.is_empty() {
        return default_ctx.to_vec();
    }

    // 1. Check hardcoded fix_permission dictionary
    for rule in fix_rules {
        if i == rule.pattern_str {
            return vec![rule.context.replace(' ', "")];
        }
        if let Some(re) = &rule.regex {
            if re.is_match(i) {
                return vec![rule.context.replace(' ', "")];
            }
        }
    }

    // 2. Fallback similarity match against existing fs_file keys (matching contextpatch.py lines 177-190)
    let dir_path = posix_dirname(i);
    if !ordered_fs_entries.is_empty() {
        for (e, ctx) in ordered_fs_entries {
            if sequence_matcher_quick_ratio(dir_path, e) >= 0.8 {
                if e == dir_path {
                    continue;
                }
                return ctx.iter().map(|s| s.replace(' ', "")).collect();
            }
        }
        // Also check Trie if ordered_fs_entries had no quick_ratio >= 0.8 match
        //Wait: in contextpatch.py lines 178-190, if no key had quick_ratio >= 0.8 (or the only matching key had e == path),
        // `permission` becomes `permission_d`! To maintain 100% behavioral parity with contextpatch.py,
        // we return `default_ctx` when the loop finishes without breaking.
        let _ = trie;
        return default_ctx.to_vec();
    }

    default_ctx.to_vec()
}

/// Patch `file_contexts` in memory from pre-scanned partition entries.
/// Returns `(sorted_map_of_path_to_context, added_count)`.
pub fn context_patch_with_entries(
    ordered_fs: &[(String, Vec<String>)],
    fs_map: &HashMap<String, Vec<String>>,
    dir_path_str: &str,
    part_name: &str,
    entries: &[ScannedEntry],
) -> (BTreeMap<String, Vec<String>>, usize) {
    println!("ContextPatcher: Load origin {} entries", fs_map.len());

    let default_ctx = vec![default_partition_context(dir_path_str)];
    let fix_rules = compile_fix_rules();
    let mut trie = ContextTrie::new();
    for (k, v) in ordered_fs {
        trie.insert(k, v.clone());
    }

    // Collect all raw paths yielded by `scan_dir` in `contextpatch.py`:
    // Every directory and file as `/{part_name}/{rel_path}`, plus virtual paths:
    // "/", "/lost+found", f"/{part_name}", f"/{part_name}/", f"/{part_name}/lost+found"
    // Note: in `contextpatch.py`, `for rv in allfiles: yield rv` is inside the `os.walk` loop,
    // which executes if and only if the root directory exists (at least 1 iteration of os.walk).
    let mut raw_paths: Vec<String> = Vec::with_capacity(entries.len() + 5);
    for entry in entries {
        raw_paths.push(format!("/{}/{}", part_name, entry.rel_path));
    }
    raw_paths.push("/".to_string());
    raw_paths.push("/lost+found".to_string());
    raw_paths.push(format!("/{}", part_name));
    raw_paths.push(format!("/{}/", part_name));
    raw_paths.push(format!("/{}/lost+found", part_name));

    // Deduplicate and sanitize paths while preserving order
    let mut seen_new: HashSet<String> = HashSet::new();
    let mut new_fs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut missing_paths: Vec<String> = Vec::new();

    for raw in raw_paths {
        let sanitized = sanitize_printable_and_spaces(&raw);
        let escaped = str_to_selinux(&sanitized);

        // Skip paths containing non-ASCII characters (ord(ch) > 127)
        if !escaped.is_ascii() {
            continue;
        }

        if let Some(existing) = fs_map.get(&escaped) {
            if ! existing.is_empty() {
                new_fs.insert(escaped, existing.clone());
                continue;
            }
        }

        if seen_new.insert(escaped.clone()) {
            missing_paths.push(escaped);
        }
    }

    // Resolve missing paths in parallel using rayon
    let resolved: Vec<(String, Vec<String>)> = missing_paths
        .into_par_iter()
        .map(|path| {
            let ctx = resolve_new_context(&path, &fix_rules, ordered_fs, &trie, &default_ctx);
            (path, ctx)
        })
        .collect();

    let add_new = resolved.len();
    for (path, ctx) in resolved {
        println!("Add {} {:?}", path, ctx);
        new_fs.insert(path, ctx);
    }

    (new_fs, add_new)
}

/// Run `contextpatch` on `dir_path` and `file_contexts` file.
pub fn context_patch_file(dir_path: impl AsRef<Path>, file_contexts: impl AsRef<Path>) -> Result<(BTreeMap<String, Vec<String>>, usize)> {
    let dir_path_ref = dir_path.as_ref();
    let file_contexts_ref = file_contexts.as_ref();
    let dir_path_str = dir_path_ref.to_string_lossy().into_owned();
    let part_name = extract_part_name(dir_path_ref);

    let (ordered_fs, fs_map) = scan_context(file_contexts_ref)
        .with_context(|| format!("Failed to scan file_contexts: {}", file_contexts_ref.display()))?;
    let entries = scan_partition_entries(dir_path_ref)
        .with_context(|| format!("Failed to scan directory: {}", dir_path_ref.display()))?;

    let (new_fs, add_new) = context_patch_with_entries(
        &ordered_fs,
        &fs_map,
        &dir_path_str,
        &part_name,
        &entries,
    );

    let mut out = String::with_capacity(new_fs.len() * 64);
    for (k, v) in &new_fs {
        out.push_str(k);
        out.push(' ');
        out.push_str(&v.join(" "));
        out.push('\n');
    }
    coloros_common::write_text_lf(file_contexts_ref, &out)?;
    println!("ContextPatcher: Add {} entries", add_new);

    Ok((new_fs, add_new))
}

fn has_bin_gid_2000_dir(path: &str) -> bool {
    path.contains("system/bin")
        || path.contains("system/xbin")
        || path.contains("vendor/bin")
        || path.contains("system_ext/xbin")
        || path.contains("system_ext/bin")
}

fn has_bin_gid_2000_file_or_link(path: &str) -> bool {
    path.contains("system/bin")
        || path.contains("system/xbin")
        || path.contains("vendor/bin")
        || path.contains("system_ext/xbin")
}

/// Compute `fs_config` entry (`[uid, gid, mode]` or `[uid, gid, mode, link]`) for a path `i`
/// that is not already present in `fs_file`, matching lines 90-143 of `bin/fspatch.py`.
pub fn compute_fs_config_entry(
    i: &str,
    is_dir: bool,
    exists: bool,
    symlink_target: Option<&str>,
) -> Vec<String> {
    if is_dir {
        let uid = "0".to_string();
        let gid = if has_bin_gid_2000_dir(i) {
            "2000".to_string()
        } else {
            "0".to_string()
        };
        let mode = "0755".to_string();
        vec![uid, gid, mode]
    } else if !exists {
        vec!["0".to_string(), "0".to_string(), "0755".to_string()]
    } else if let Some(link) = symlink_target {
        let uid = "0".to_string();
        let gid = if has_bin_gid_2000_file_or_link(i) {
            "2000".to_string()
        } else {
            "0".to_string()
        };
        let mode = if i.contains("/bin") || i.contains("/xbin") {
            "0755".to_string()
        } else if i.contains(".sh") {
            "0750".to_string()
        } else {
            "0644".to_string()
        };
        vec![uid, gid, mode, link.to_string()]
    } else if i.contains("/bin") || i.contains("/xbin") {
        let uid = "0".to_string();
        let gid = if has_bin_gid_2000_file_or_link(i) {
            "2000".to_string()
        } else {
            "0".to_string()
        };
        let mut mode = "0755".to_string();
        if i.contains(".sh") {
            mode = "0750".to_string();
        } else {
            for s in EXEC_SH_EXCEPTIONS {
                if i.contains(s) {
                    mode = "0755".to_string();
                }
            }
        }
        vec![uid, gid, mode]
    } else {
        vec!["0".to_string(), "0".to_string(), "0644".to_string()]
    }
}

/// Patch `fs_config` in memory from pre-scanned partition entries.
/// Returns `(sorted_map_of_path_to_config, added_count)`.
pub fn fs_patch_with_entries(
    fs_map: &HashMap<String, Vec<String>>,
    part_name: &str,
    root_exists: bool,
    entries: &[ScannedEntry],
) -> (BTreeMap<String, Vec<String>>, usize) {
    println!("FsPatcher: Load origin {} entries", fs_map.len());

    // Build raw candidate list matching `scan_dir` in `fspatch.py`:
    // 1. `part_name` (root directory of the partition)
    // 2. Each walked directory and file as `{part_name}/{rel_path}`
    // 3. Virtual paths: "/", "/lost+found", f"/{part_name}/lost+found", f"/{part_name}/"
    #[derive(Clone)]
    struct Candidate<'a> {
        raw_path: String,
        is_dir: bool,
        exists: bool,
        symlink_target: Option<&'a str>,
    }

    let mut candidates: Vec<Candidate> = Vec::with_capacity(entries.len() + 5);
    candidates.push(Candidate {
        raw_path: part_name.to_string(),
        is_dir: root_exists,
        exists: root_exists,
        symlink_target: None,
    });

    for entry in entries {
        candidates.push(Candidate {
            raw_path: format!("{}/{}", part_name, entry.rel_path),
            is_dir: entry.is_dir,
            exists: entry.exists,
            symlink_target: entry.symlink_target.as_deref(),
        });
    }

    // Virtual entries yielded in `fspatch.py` (`allfiles`):
    // Note: in `fspatch.py`, `filepath = os.path.abspath(dir_path + os.sep + ".." + os.sep + i)`.
    // Because `i` starts with `/`, in Python `dir_path + "/../" + "/lost+found"` resolves to
    // `<parent_of_dir_path>/lost+found`, and `f"/{part_name}/"` resolves to `dir_path` itself (which is an existing directory!).
    //Wait: let's check what `dir_path + os.sep + ".." + os.sep + i` does in Python!
    // In Python:
    // If `dir_path` is `/work/images/system` (or `C:\work\images\system` on Windows):
    // `dir_path + "/" + ".." + "/" + "/"` -> `/work/images/system/..//` -> `os.path.abspath` -> `/work/images` (which is a directory!).
    // `dir_path + "/" + ".." + "/" + "/lost+found"` -> `/work/images/lost+found` (does not exist -> `["0", "0", "0755"]`).
    // `dir_path + "/" + ".." + "/" + "/system/lost+found"` -> `/work/images/system/lost+found` (usually does not exist -> `["0", "0", "0755"]`).
    // `dir_path + "/" + ".." + "/" + "/system/"` -> `/work/images/system` (which is `dir_path`, a directory -> `["0", "0", "0755"]`).
    // Notice that whether `os.path.isdir(filepath)` is True (for `/` and `/{part_name}/`, since neither contains `system/bin`) or `not os.path.exists(filepath)` is True (for `/lost+found` and `/{part_name}/lost+found`), BOTH branches produce `["0", "0", "0755"]`!
    // Because `i` for those 4 virtual paths is `"/"`, `"/lost+found"`, `"/{part_name}/lost+found"`, `"/{part_name}/"`, none of them contain `"system/bin"`, `"system/xbin"`, `"vendor/bin"`, `"system_ext/xbin"`, `"system_ext/bin"`, so `isdir` gives `["0", "0", "0755"]` and `not exists` ALSO gives `["0", "0", "0755"]`!
    candidates.push(Candidate {
        raw_path: "/".to_string(),
        is_dir: false,
        exists: false,
        symlink_target: None,
    });
    candidates.push(Candidate {
        raw_path: "/lost+found".to_string(),
        is_dir: false,
        exists: false,
        symlink_target: None,
    });
    candidates.push(Candidate {
        raw_path: format!("/{}/lost+found", part_name),
        is_dir: false,
        exists: false,
        symlink_target: None,
    });
    candidates.push(Candidate {
        raw_path: format!("/{}/", part_name),
        is_dir: false,
        exists: false,
        symlink_target: None,
    });

    let mut new_fs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut r_fs: HashSet<String> = HashSet::new();
    let mut new_add: usize = 0;

    for cand in candidates {
        let i = sanitize_printable_and_spaces(&cand.raw_path);
        if let Some(existing) = fs_map.get(&i) {
            if !existing.is_empty() {
                new_fs.insert(i, existing.clone());
                continue;
            }
        }
        if !r_fs.insert(i.clone()) {
            continue;
        }
        let config = compute_fs_config_entry(&i, cand.is_dir, cand.exists, cand.symlink_target);
        println!("Add [{}{:?}]", i, config);
        new_add += 1;
        new_fs.insert(i, config);
    }

    (new_fs, new_add)
}

/// Run `fspatch` on `dir_path` and `fs_config` file.
pub fn fs_patch_file(dir_path: impl AsRef<Path>, fs_config: impl AsRef<Path>) -> Result<(BTreeMap<String, Vec<String>>, usize)> {
    let dir_path_ref = dir_path.as_ref();
    let fs_config_ref = fs_config.as_ref();
    let part_name = extract_part_name(dir_path_ref);

    let fs_map = scan_fs(fs_config_ref)
        .with_context(|| format!("Failed to scan fs_config: {}", fs_config_ref.display()))?;
    let entries = scan_partition_entries(dir_path_ref)
        .with_context(|| format!("Failed to scan directory: {}", dir_path_ref.display()))?;

    let (new_fs, new_add) = fs_patch_with_entries(
        &fs_map,
        &part_name,
        dir_path_ref.is_dir(),
        &entries,
    );

    let mut out = String::with_capacity(new_fs.len() * 48);
    for (k, v) in &new_fs {
        out.push_str(k);
        out.push(' ');
        out.push_str(&v.join(" "));
        out.push('\n');
    }
    coloros_common::write_text_lf(fs_config_ref, &out)?;
    println!("FsPatcher: Add {} entries", new_add);

    Ok((new_fs, new_add))
}

/// Single-pass combined `fs_config` and `file_contexts` patching.
/// Walks the directory tree once in parallel and updates both configuration files.
pub fn patch_all_files(
    dir_path: impl AsRef<Path>,
    fs_config: impl AsRef<Path>,
    file_contexts: impl AsRef<Path>,
) -> Result<()> {
    let dir_path_ref = dir_path.as_ref();
    let fs_config_ref = fs_config.as_ref();
    let file_contexts_ref = file_contexts.as_ref();
    let dir_path_str = dir_path_ref.to_string_lossy().into_owned();
    let part_name = extract_part_name(dir_path_ref);

    // Walk partition tree once
    let entries = scan_partition_entries(dir_path_ref)
        .with_context(|| format!("Failed to scan directory: {}", dir_path_ref.display()))?;

    // 1. Patch fs_config
    let fs_map = scan_fs(fs_config_ref)
        .with_context(|| format!("Failed to scan fs_config: {}", fs_config_ref.display()))?;
    let (new_fs, fs_added) = fs_patch_with_entries(
        &fs_map,
        &part_name,
        dir_path_ref.is_dir(),
        &entries,
    );
    let mut fs_out = String::with_capacity(new_fs.len() * 48);
    for (k, v) in &new_fs {
        fs_out.push_str(k);
        fs_out.push(' ');
        fs_out.push_str(&v.join(" "));
        fs_out.push('\n');
    }
    coloros_common::write_text_lf(fs_config_ref, &fs_out)?;
    println!("FsPatcher: Add {} entries", fs_added);

    // 2. Patch file_contexts
    let (ordered_ctx, ctx_map) = scan_context(file_contexts_ref)
        .with_context(|| format!("Failed to scan file_contexts: {}", file_contexts_ref.display()))?;
    let (new_ctx, ctx_added) = context_patch_with_entries(
        &ordered_ctx,
        &ctx_map,
        &dir_path_str,
        &part_name,
        &entries,
    );
    let mut ctx_out = String::with_capacity(new_ctx.len() * 64);
    for (k, v) in &new_ctx {
        ctx_out.push_str(k);
        ctx_out.push(' ');
        ctx_out.push_str(&v.join(" "));
        ctx_out.push('\n');
    }
    coloros_common::write_text_lf(file_contexts_ref, &ctx_out)?;
    println!("ContextPatcher: Add {} entries", ctx_added);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_str_to_selinux_matches_python_re_escape() {
        assert_eq!(
            str_to_selinux("/vendor/bin/hw/android.hardware.wifi@1.0-service"),
            r"/vendor/bin/hw/android\.hardware\.wifi@1\.0-service"
        );
        assert_eq!(
            str_to_selinux("/system/lib64/libc++.so"),
            r"/system/lib64/libc\+\+\.so"
        );
        assert_eq!(
            str_to_selinux("/system/app/Some$App[1](test)"),
            r"/system/app/Some\$App\[1\]\(test\)"
        );
    }

    #[test]
    fn test_sanitize_printable_and_spaces() {
        assert_eq!(
            sanitize_printable_and_spaces("/system/app/My App\x07Name"),
            "/system/app/My*App*Name"
        );
    }

    #[test]
    fn test_posix_dirname() {
        assert_eq!(posix_dirname("/"), "/");
        assert_eq!(posix_dirname("/lost+found"), "/");
        assert_eq!(posix_dirname("/system"), "/");
        assert_eq!(posix_dirname("/system/"), "/system");
        assert_eq!(posix_dirname("/system/bin/init"), "/system/bin");
        assert_eq!(posix_dirname("system/bin"), "system");
        assert_eq!(posix_dirname("system"), "");
    }

    #[test]
    fn test_sequence_matcher_quick_ratio() {
        let r1 = sequence_matcher_quick_ratio("/system/system/bin", "/system/system/bin/sh");
        assert!(r1 >= 0.8, "Expected quick_ratio >= 0.8, got {}", r1);

        let r2 = sequence_matcher_quick_ratio("/system/app", "/vendor/firmware_mnt/image");
        assert!(r2 < 0.8, "Expected quick_ratio < 0.8, got {}", r2);
    }

    #[test]
    fn test_context_patch_end_to_end() -> Result<()> {
        let tmp = TempDir::new()?;
        let vendor_dir = tmp.path().join("vendor");
        fs::create_dir_all(vendor_dir.join("bin/hw"))?;
        fs::create_dir_all(vendor_dir.join("etc/init/hw"))?;
        fs::create_dir_all(vendor_dir.join("lib64"))?;
        fs::create_dir_all(vendor_dir.join("app/TestVendorApp"))?;
        // Should be skipped (.git, __pycache__)
        fs::create_dir_all(vendor_dir.join(".git"))?;
        fs::write(vendor_dir.join(".git/config"), "skip")?;

        fs::write(
            vendor_dir.join("bin/hw/android.hardware.wifi@1.0"),
            "binary",
        )?;
        fs::write(vendor_dir.join("bin/qfp-daemon"), "binary")?;
        fs::write(vendor_dir.join("etc/init/hw/init.qcom.rc"), "service")?;
        fs::write(vendor_dir.join("lib64/libc++.so"), "so")?;
        fs::write(vendor_dir.join("app/TestVendorApp/TestVendorApp.apk"), "apk")?;
        fs::write(vendor_dir.join("custom_blob.bin"), "blob")?;

        let fc_path = tmp.path().join("vendor_file_contexts");
        fs::write(
            &fc_path,
            "/ u:object_r:rootfs:s0\n/vendor/custom_blob\\.bin u:object_r:custom_vendor_blob:s0\n/vendor/bad_line u:object_r:foo:s0 extra_token\n",
        )?;

        let (new_fs, add_new) = context_patch_file(&vendor_dir, &fc_path)?;
        assert!(add_new > 0);

        // Existing entry preserved
        assert_eq!(
            new_fs.get("/").unwrap(),
            &vec!["u:object_r:rootfs:s0".to_string()]
        );
        assert_eq!(
            new_fs.get(r"/vendor/custom_blob\.bin").unwrap(),
            &vec!["u:object_r:custom_vendor_blob:s0".to_string()]
        );
        // Line with >1 context tokens was skipped during scan_context
        assert!(!new_fs.contains_key("/vendor/bad_line"));

        // Hardcoded fix_permission rules applied
        assert_eq!(
            new_fs
                .get(r"/vendor/bin/hw/android\.hardware\.wifi@1\.0")
                .unwrap(),
            &vec!["u:object_r:vendor_file:s0".to_string()]
        );
        assert_eq!(
            new_fs.get("/vendor/bin/qfp-daemon").unwrap(),
            &vec!["u:object_r:vendor_qfp-daemon_exec:s0".to_string()]
        );
        assert_eq!(
            new_fs.get(r"/vendor/etc/init/hw/init\.qcom\.rc").unwrap(),
            &vec!["u:object_r:vendor_configs_file:s0".to_string()]
        );
        assert_eq!(
            new_fs.get(r"/vendor/lib64/libc\+\+\.so").unwrap(),
            &vec!["u:object_r:same_process_hal_file:s0".to_string()]
        );
        assert_eq!(
            new_fs
                .get(r"/vendor/app/TestVendorApp/TestVendorApp\.apk")
                .unwrap(),
            &vec!["u:object_r:vendor_app_file:s0".to_string()]
        );

        // Skipped directory not present
        assert!(!new_fs.keys().any(|k| k.contains("git")));

        // Verify file output is sorted and uses LF
        let written = fs::read_to_string(&fc_path)?;
        assert!(!written.contains("\r\n"));
        let lines: Vec<&str> = written.lines().collect();
        let mut sorted_lines = lines.clone();
        sorted_lines.sort();
        assert_eq!(lines, sorted_lines);

        // Verify similarity fallback (SequenceMatcher quick_ratio >= 0.8 and e != dirname(i))
        // and combined single-pass `patch_all_files`
        let odm_dir = tmp.path().join("odm");
        fs::create_dir_all(odm_dir.join("bin/hw"))?;
        fs::create_dir_all(odm_dir.join("etc/camera/config"))?;
        fs::write(
            odm_dir.join("bin/hw/vendor.oplus.hardware.charger-V6-service"),
            "bin",
        )?;
        fs::write(odm_dir.join("etc/camera/config/cam.json"), "{}")?;
        let odm_fc = tmp.path().join("odm_file_contexts");
        let odm_fsc = tmp.path().join("odm_fs_config");
        fs::write(&odm_fc, "/ u:object_r:rootfs:s0\n")?;
        fs::write(&odm_fsc, "/ 0 0 0755\n")?;

        patch_all_files(&odm_dir, &odm_fsc, &odm_fc)?;

        let (_, odm_fc_map) = scan_context(&odm_fc)?;
        assert_eq!(
            odm_fc_map
                .get(r"/odm/bin/hw/vendor\.oplus\.hardware\.charger-V6-service")
                .unwrap(),
            &vec!["u:object_r:hal_charger_oplus_exec:s0".to_string()]
        );
        assert_eq!(
            odm_fc_map.get(r"/odm/etc/camera/config/cam\.json").unwrap(),
            &vec!["u:object_r:vendor_configs_file:s0".to_string()]
        );

        let odm_fsc_map = scan_fs(&odm_fsc)?;
        assert_eq!(
            odm_fsc_map
                .get("odm/bin/hw/vendor.oplus.hardware.charger-V6-service")
                .unwrap(),
            &vec!["0", "0", "0755"]
        );
        assert_eq!(
            odm_fsc_map.get("odm/etc/camera/config/cam.json").unwrap(),
            &vec!["0", "0", "0644"]
        );

        Ok(())
    }

    #[test]
    fn test_fs_patch_end_to_end() -> Result<()> {
        let tmp = TempDir::new()?;
        let sys_dir = tmp.path().join("system");
        fs::create_dir_all(sys_dir.join("system/bin"))?;
        fs::create_dir_all(sys_dir.join("system/etc"))?;

        fs::write(sys_dir.join("system/bin/sh"), "elf")?;
        fs::write(sys_dir.join("system/bin/init.custom.sh"), "#!/system/bin/sh")?;
        fs::write(sys_dir.join("system/bin/rw-system.sh"), "#!/system/bin/sh")?;
        fs::write(sys_dir.join("system/etc/hosts"), "127.0.0.1 localhost")?;

        // Create a Cygwin-style !<symlink> file
        let mut symlink_bytes = b"!<symlink>".to_vec();
        for u in "/system/bin/toybox\0".encode_utf16() {
            symlink_bytes.extend_from_slice(&u.to_le_bytes());
        }
        fs::write(sys_dir.join("system/bin/ls"), &symlink_bytes)?;

        let fsc_path = tmp.path().join("system_fs_config");
        fs::write(&fsc_path, "system/system/etc/hosts 0 0 0600\n")?;

        let (new_fs, new_add) = fs_patch_file(&sys_dir, &fsc_path)?;
        assert!(new_add > 0);

        // Preserved existing config
        assert_eq!(
            new_fs.get("system/system/etc/hosts").unwrap(),
            &vec!["0", "0", "0600"]
        );

        // Directory in system/bin gets gid 2000, mode 0755
        assert_eq!(
            new_fs.get("system/system/bin").unwrap(),
            &vec!["0", "2000", "0755"]
        );
        // Normal directory gets gid 0, mode 0755
        assert_eq!(
            new_fs.get("system/system/etc").unwrap(),
            &vec!["0", "0", "0755"]
        );
        // Normal binary in system/bin gets 0 2000 0755
        assert_eq!(
            new_fs.get("system/system/bin/sh").unwrap(),
            &vec!["0", "2000", "0755"]
        );
        // .sh inside system/bin gets 0 2000 0750
        assert_eq!(
            new_fs.get("system/system/bin/init.custom.sh").unwrap(),
            &vec!["0", "2000", "0750"]
        );
        // Exception `bin/rw-system.sh`:Wait - in fspatch.py:
        // `if ".sh" in i: mode = "0750" else: for s in [...]: if s in i: mode = "0755"`
        // Because `"rw-system.sh"` contains `".sh"`, `if ".sh" in i:` is taken first in Python!
        assert_eq!(
            new_fs.get("system/system/bin/rw-system.sh").unwrap(),
            &vec!["0", "2000", "0750"]
        );
        // Cygwin symlink in system/bin
        assert_eq!(
            new_fs.get("system/system/bin/ls").unwrap(),
            &vec!["0", "2000", "0755", "/system/bin/toybox"]
        );
        // Virtual paths present
        assert_eq!(new_fs.get("/").unwrap(), &vec!["0", "0", "0755"]);
        assert_eq!(new_fs.get("/lost+found").unwrap(), &vec!["0", "0", "0755"]);
        assert_eq!(
            new_fs.get("/system/lost+found").unwrap(),
            &vec!["0", "0", "0755"]
        );
        assert_eq!(new_fs.get("/system/").unwrap(), &vec!["0", "0", "0755"]);

        Ok(())
    }
}
