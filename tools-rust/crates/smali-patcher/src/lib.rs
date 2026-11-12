//! Stage 3: Parallel Regex Engine for Smali replacing `patchmethod_v2.py`, `patchmethod.py`,
//! `smalikit.py`, `patch_apk_protection.py`, `patch_cos17_engineer.py`, and
//! `patch_inspiration_aod_gate.py`.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use coloros_common::{color, log_colored, write_text_lf};
use jwalk::WalkDir as JWalkDir;
use memmap2::Mmap;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;

pub const STUB_TRUE: &str = "    .locals 1\n    const/4 v0, 0x1\n    return v0\n";
pub const STUB_FALSE: &str = "    .locals 1\n    const/4 v0, 0x0\n    return v0\n";
pub const STUB_VOID: &str = "    .locals 0\n    return-void\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnType {
    True,
    False,
    Void,
}

impl ReturnType {
    pub fn parse_str(s: &str) -> Result<Self> {
        match s {
            "true" => Ok(Self::True),
            "false" => Ok(Self::False),
            "void" => Ok(Self::Void),
            _ => bail!("Error: Invalid return type specified: {}", s),
        }
    }

    pub fn stub_body(self) -> &'static str {
        match self {
            Self::True => STUB_TRUE,
            Self::False => STUB_FALSE,
            Self::Void => STUB_VOID,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::True => "true",
            Self::False => "false",
            Self::Void => "void",
        }
    }
}

/// CLI entrypoint accepting both `smalikit.py`, `patchmethod_v2.py`, `patchmethod.py`,
/// and subcommand invocations.
#[derive(Debug, Parser)]
#[command(
    name = "smali-patcher",
    about = "Parallel Smali patcher replacing patchmethod_v2.py, patchmethod.py, and smalikit.py",
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct Cli {
    /// Arguments passed to smali-patcher
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// Configuration for `SmaliKit` mode (`bin/smalikit.py`).
#[derive(Debug, Clone, Default)]
pub struct SmaliKitConfig {
    pub path: PathBuf,
    pub method: Option<String>,
    pub iname: Option<String>,
    pub remake: Option<String>,
    pub replace_in_method: Option<(String, String)>,
    pub regex_replace: Option<(String, String)>,
    pub delete_in_method: Option<String>,
    pub delete_method: bool,
    pub after_line: Option<(String, String)>,
    pub before_line: Option<(String, String)>,
    pub recursive: bool,
}

/// Read a file using `memmap2` and only allocate a `String` (normalized to LF `\n`)
/// if `predicate` returns `true`. Drops the memory map before returning so the file
/// is never locked when subsequently written on Windows.
pub fn read_file_if_matches<F>(path: &Path, predicate: F) -> Result<Option<String>>
where
    F: FnOnce(&str) -> bool,
{
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to stat {}", path.display()))?;
    if metadata.len() == 0 {
        drop(file);
        if predicate("") {
            return Ok(Some(String::new()));
        }
        return Ok(None);
    }

    let content_opt = {
        // SAFETY: The file is opened read-only and map is dropped before any write occurs.
        let mmap = unsafe { Mmap::map(&file) };
        match mmap {
            Ok(map) => {
                let text = String::from_utf8_lossy(&map);
                if predicate(&text) {
                    Some(text.replace("\r\n", "\n"))
                } else {
                    None
                }
            }
            Err(_) => {
                let bytes = fs::read(path)
                    .with_context(|| format!("Failed to read {}", path.display()))?;
                let text = String::from_utf8_lossy(&bytes);
                if predicate(&text) {
                    Some(text.replace("\r\n", "\n"))
                } else {
                    None
                }
            }
        }
    };
    drop(file);
    Ok(content_opt)
}

/// Read a file using `memmap2` unconditionally into a normalized LF `String`.
pub fn read_file_mmap_lf(path: &Path) -> Result<String> {
    Ok(read_file_if_matches(path, |_| true)?.unwrap_or_default())
}

/// Collect `.smali` files under `root` (or return `vec![root]` if `root` is a file).
/// Uses `jwalk` for fast parallel directory walking when `recursive` is true.
pub fn collect_smali_files(
    root: &Path,
    recursive: bool,
    iname_filter: Option<&str>,
) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    if !root.is_dir() {
        return Vec::new();
    }

    let mut files: Vec<PathBuf> = if recursive {
        JWalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s == "smali")
                    .unwrap_or(false)
            })
            .filter(|p| {
                if let Some(filter) = iname_filter {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.contains(filter))
                        .unwrap_or(false)
                } else {
                    true
                }
            })
            .collect()
    } else {
        WalkDir::new(root)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| {
                p.extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s == "smali")
                    .unwrap_or(false)
            })
            .filter(|p| {
                if let Some(filter) = iname_filter {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.contains(filter))
                        .unwrap_or(false)
                } else {
                    true
                }
            })
            .collect()
    };

    files.sort();
    files
}

/// Convert Python `re.sub` replacement string syntax (`\1`, `\2`, `\g<1>`, `\g<name>`, `\n`, `\t`)
/// to Rust `regex` replacement syntax (`${1}`, `${2}`, `${name}`, newline, tab), while escaping
/// Smali inner-class `$` signs (such as `Settings$Secure` or `Bar$1`) to `$$` so Rust's `regex`
/// engine does not strip them as capture groups.
pub fn python_repl_to_rust_regex_repl(repl: &str) -> String {
    let mut out = String::with_capacity(repl.len() + 8);
    let chars: Vec<char> = repl.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            let next = chars[i + 1];
            match next {
                '\\' => {
                    out.push('\\');
                    i += 2;
                }
                'n' => {
                    out.push('\n');
                    i += 2;
                }
                'r' => {
                    out.push('\r');
                    i += 2;
                }
                't' => {
                    out.push('\t');
                    i += 2;
                }
                '1'..='9' => {
                    out.push_str("${");
                    out.push(next);
                    i += 2;
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        out.push(chars[i]);
                        i += 1;
                    }
                    out.push('}');
                }
                'g' if i + 2 < chars.len() && chars[i + 2] == '<' => {
                    if let Some(end_offset) = chars[i + 3..].iter().position(|&c| c == '>') {
                        let group_name: String =
                            chars[i + 3..i + 3 + end_offset].iter().collect();
                        out.push_str("${");
                        out.push_str(&group_name);
                        out.push('}');
                        i += 3 + end_offset + 1;
                    } else {
                        out.push(chars[i]);
                        i += 1;
                    }
                }
                _ => {
                    out.push(chars[i]);
                    out.push(next);
                    i += 2;
                }
            }
        } else if chars[i] == '$' {
            // Check if this `$` is part of a Smali inner-class identifier (e.g. `Settings$Secure` or `Foo$1`)
            let prev_is_ident = i > 0
                && (chars[i - 1].is_ascii_alphanumeric()
                    || chars[i - 1] == '_'
                    || chars[i - 1] == '$');
            let next_is_backref = i + 1 < chars.len()
                && (chars[i + 1].is_ascii_digit() || chars[i + 1] == '{');
            if prev_is_ident || !next_is_backref {
                out.push_str("$$");
            } else {
                out.push('$');
            }
            i += 1;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Unescape literal `\n` and `\t` sequences in a method body string (matching Python `re.sub`
/// and `smalikit.py` `-remake` behavior).
pub fn unescape_method_body(body: &str) -> String {
    body.replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\t", "\t")
}

// ============================================================================
// 1. SmaliKit implementation (replacing `bin/smalikit.py`)
// ============================================================================

impl SmaliKitConfig {
    pub fn process_content(&self, content: &str, file_path: &Path) -> Result<(String, bool)> {
        // Whole-file mode if `method` is None
        let Some(ref target_method) = self.method else {
            return self.process_whole_file(content);
        };

        let pattern_str = format!(
            r"(?ms)^(?P<header>[ \t]*\.method[^\n\r]*?{}[^\n\r]*)(?P<body>.*?)(?P<footer>^[ \t]*\.end method)",
            regex::escape(target_method)
        );
        let method_re = Regex::new(&pattern_str)
            .with_context(|| format!("Invalid method regex for {}", target_method))?;

        let Some(caps) = method_re.captures(content) else {
            return Ok((content.to_string(), false));
        };

        let file_name = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        log_colored(
            &format!("[*] Found method '{}' in: {}", target_method, file_name),
            color::OKBLUE,
        );

        let full_match = caps.get(0).unwrap().as_str();
        let header = caps.name("header").unwrap().as_str();
        let body = caps.name("body").unwrap().as_str();
        let footer = caps.name("footer").unwrap().as_str();

        let mut new_body = body.to_string();
        let mut is_modified = false;

        // 1. -remake
        if let Some(ref remake) = self.remake {
            println!("  -> Applying -remake...");
            let remake_content = remake.replace("\\n", "\n");
            new_body = format!("\n    {}\n", remake_content);
            is_modified = true;
        }

        // 2. -rim (plain string replacement in method)
        if let Some((ref old_str, ref new_str)) = self.replace_in_method {
            if new_body.contains(old_str) {
                println!("  -> Applying -rim...");
                new_body = new_body.replace(old_str, new_str);
                is_modified = true;
            }
        }

        // 3. -reg (regex replacement in method)
        if let Some((ref pattern_str, ref repl_str)) = self.regex_replace {
            let pattern = Regex::new(pattern_str)
                .with_context(|| format!("Invalid -reg pattern: {}", pattern_str))?;
            if pattern.is_match(&new_body) {
                println!("  -> Applying -reg (Regex Replace)...");
                let rust_repl = python_repl_to_rust_regex_repl(repl_str);
                new_body = pattern.replace_all(&new_body, rust_repl.as_str()).into_owned();
                is_modified = true;
            } else {
                log_colored("  -> [WARNING] Regex pattern not found.", color::WARNING);
            }
        }

        // 4. -dim (delete string in method)
        if let Some(ref target_str) = self.delete_in_method {
            if new_body.contains(target_str) {
                println!("  -> Applying -dim...");
                new_body = new_body.replace(target_str, "");
                is_modified = true;
            }
        }

        // 5. -dm (delete entire method)
        if self.delete_method {
            println!("  -> Applying -dm...");
            let new_content = content.replacen(full_match, "", 1);
            log_colored("  -> [SUCCESS] Saved.", color::OKGREEN);
            return Ok((new_content, true));
        }

        // 6. -al (insert after target line)
        if let Some((ref target_line, ref add_line)) = self.after_line {
            if new_body.contains(target_line) {
                println!("  -> Applying -al...");
                let replacement = format!("{}\n    {}", target_line, add_line);
                new_body = new_body.replace(target_line, &replacement);
                is_modified = true;
            }
        }

        // 7. -bl (insert before target line)
        if let Some((ref target_line, ref add_line)) = self.before_line {
            if new_body.contains(target_line) {
                println!("  -> Applying -bl...");
                let replacement = format!("    {}\n{}", add_line, target_line);
                new_body = new_body.replace(target_line, &replacement);
                is_modified = true;
            }
        }

        if is_modified {
            let modified_block = format!("{}{}{}", header, new_body, footer);
            if full_match != modified_block {
                let new_content = content.replacen(full_match, &modified_block, 1);
                log_colored("  -> [SUCCESS] Saved.", color::OKGREEN);
                return Ok((new_content, true));
            } else {
                log_colored("  -> [INFO] No changes needed.", color::WARNING);
            }
        }

        Ok((content.to_string(), false))
    }

    fn process_whole_file(&self, content: &str) -> Result<(String, bool)> {
        let mut new_content = content.to_string();
        let mut is_modified = false;

        if let Some((ref old_str, ref new_str)) = self.replace_in_method {
            if new_content.contains(old_str) {
                new_content = new_content.replace(old_str, new_str);
                is_modified = true;
            }
        }

        if let Some((ref pattern_str, ref repl_str)) = self.regex_replace {
            let pattern = Regex::new(pattern_str)
                .with_context(|| format!("Invalid -reg pattern: {}", pattern_str))?;
            if pattern.is_match(&new_content) {
                let rust_repl = python_repl_to_rust_regex_repl(repl_str);
                new_content = pattern
                    .replace_all(&new_content, rust_repl.as_str())
                    .into_owned();
                is_modified = true;
            }
        }

        if let Some(ref target_str) = self.delete_in_method {
            if new_content.contains(target_str) {
                new_content = new_content.replace(target_str, "");
                is_modified = true;
            }
        }

        if let Some((ref target_line, ref add_line)) = self.after_line {
            if new_content.contains(target_line) {
                let replacement = format!("{}\n    {}", target_line, add_line);
                new_content = new_content.replace(target_line, &replacement);
                is_modified = true;
            }
        }

        if let Some((ref target_line, ref add_line)) = self.before_line {
            if new_content.contains(target_line) {
                let replacement = format!("    {}\n{}", add_line, target_line);
                new_content = new_content.replace(target_line, &replacement);
                is_modified = true;
            }
        }

        let changed = is_modified && new_content != content;
        Ok((new_content, changed))
    }

    pub fn patch_file(&self, file_path: &Path) -> Result<bool> {
        let target_method = self.method.as_deref();
        let Some(content) = read_file_if_matches(file_path, |text| {
            if let Some(m) = target_method {
                text.contains(m)
            } else {
                true
            }
        })?
        else {
            return Ok(false);
        };

        let (new_content, patched) = self.process_content(&content, file_path)?;
        if patched {
            write_text_lf(file_path, &new_content)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn walk_and_patch(&self) -> Result<usize> {
        if !self.path.exists() {
            log_colored(
                &format!("[ERROR] Path not found: {}", self.path.display()),
                color::FAIL,
            );
            return Ok(0);
        }

        let candidates = if self.path.is_file() {
            vec![self.path.clone()]
        } else {
            collect_smali_files(&self.path, self.recursive, self.iname.as_deref())
        };

        let patched_count = AtomicUsize::new(0);
        candidates.par_iter().for_each(|candidate| {
            match self.patch_file(candidate) {
                Ok(true) => {
                    patched_count.fetch_add(1, Ordering::Relaxed);
                }
                Ok(false) => {}
                Err(e) => {
                    log_colored(
                        &format!("[ERROR] processing {}: {}", candidate.display(), e),
                        color::FAIL,
                    );
                }
            }
        });

        Ok(patched_count.load(Ordering::Relaxed))
    }
}

// ============================================================================
// 2. PatchMethod implementation (replacing `bin/patchmethod_v2.py` & `bin/patchmethod.py`)
// ============================================================================

/// Replace the body of `method_name` in `content` with `new_body` (matching `replace_method_body`
/// in `bin/patchmethod_v2.py`).
pub fn replace_method_body_in_str(
    content: &str,
    method_name: &str,
    new_body: &str,
) -> Result<(String, bool)> {
    let pattern_str = format!(
        r"(?s)(\.method[^\n]* {}\(.*?\n)(.*?)(\.end method)",
        regex::escape(method_name)
    );
    let re = Regex::new(&pattern_str)?;

    if !re.is_match(content) {
        return Ok((content.to_string(), false));
    }

    let formatted_body = unescape_method_body(new_body);
    let trimmed_body = formatted_body.trim();

    let mut changed = false;
    let new_content = re
        .replace_all(content, |caps: &regex::Captures| {
            changed = true;
            format!("{}{}\n{}", &caps[1], trimmed_body, &caps[3])
        })
        .into_owned();

    Ok((new_content, changed))
}

/// Replace the body of `method_name` in `smali_path` with `new_body`.
pub fn replace_method_body(
    smali_path: &Path,
    method_name: &str,
    new_body: &str,
) -> Result<bool> {
    let Some(content) = read_file_if_matches(smali_path, |text| text.contains(method_name))? else {
        println!(
            "----> Method '{}' not found in {}",
            method_name,
            smali_path.display()
        );
        return Ok(false);
    };

    let (new_content, changed) = replace_method_body_in_str(&content, method_name, new_body)?;
    if !changed {
        println!(
            "----> Method '{}' not found in {}",
            method_name,
            smali_path.display()
        );
        return Ok(false);
    }

    write_text_lf(smali_path, &new_content)?;
    println!(
        "----> Replaced body of method '{}' in: {}",
        method_name,
        smali_path.display()
    );
    Ok(true)
}

/// Stub methods in `content` according to `method_map` (`method_name -> ReturnType`).
/// Matches both `patchmethod_v2.py` (`patch_method_in_file`) and `patchmethod.py`.
pub fn patch_methods_in_str(
    content: &str,
    method_map: &HashMap<String, ReturnType>,
    smali_path_display: Option<&str>,
) -> (String, usize) {
    let method_header_re = Regex::new(
        r"\.method\s+(?:(?:public|private|protected)\s+)?(?:static\s+)?(?:final\s+)?([^\(]+)\(",
    )
    .unwrap();
    let bare_name_re = Regex::new(r"\.method\s+.*?([^\s\(]+)\(").unwrap();

    let mut current_method_name = String::new();
    let mut patched = String::with_capacity(content.len());
    let mut overwriting: Option<ReturnType> = None;
    let mut patched_count = 0usize;

    for line in content.lines() {
        let mut matched_header = false;
        if let Some(caps) = method_header_re.captures(line) {
            matched_header = true;
            let raw_name = caps.get(1).unwrap().as_str();
            current_method_name = raw_name.to_string();

            if let Some(&ret_type) = method_map.get(raw_name) {
                overwriting = Some(ret_type);
            } else if let Some(bare_caps) = bare_name_re.captures(line) {
                let bare_name = bare_caps.get(1).unwrap().as_str();
                if let Some(&ret_type) = method_map.get(bare_name) {
                    current_method_name = bare_name.to_string();
                    overwriting = Some(ret_type);
                }
            }
            patched.push_str(line);
            patched.push('\n');
        }

        if !matched_header {
            if line.contains(".end method") {
                if let Some(ret_type) = overwriting.take() {
                    patched.push_str(ret_type.stub_body());
                    patched.push_str(line);
                    patched.push('\n');
                    patched_count += 1;
                    if let Some(path_str) = smali_path_display {
                        println!(
                            "----> patched method in {}: {} => {}",
                            path_str,
                            current_method_name,
                            ret_type.label()
                        );
                    }
                } else {
                    patched.push_str(line);
                    patched.push('\n');
                }
            } else if overwriting.is_none() {
                patched.push_str(line);
                patched.push('\n');
            }
        }
    }

    (patched, patched_count)
}

/// Stub methods in `smali_path` with a single `ReturnType`.
pub fn patch_method_in_file(
    smali_path: &Path,
    methods: &HashSet<String>,
    return_type: ReturnType,
) -> Result<usize> {
    let mut map = HashMap::with_capacity(methods.len());
    for m in methods {
        map.insert(m.clone(), return_type);
    }
    patch_method_map_in_file(smali_path, &map)
}

/// Stub methods in `smali_path` with per-method `ReturnType` (supports both `patchmethod_v2.py`
/// and legacy `patchmethod.py` `-method` / `--method` syntax).
pub fn patch_method_map_in_file(
    smali_path: &Path,
    method_map: &HashMap<String, ReturnType>,
) -> Result<usize> {
    if !smali_path.is_file() {
        let base = smali_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        println!("----> Ignore patch: \"{}\" not found", base);
        return Ok(0);
    }

    if method_map.is_empty() {
        return Ok(0);
    }

    let content = read_file_mmap_lf(smali_path)?;
    let path_str = smali_path.to_string_lossy();
    let (patched, count) = patch_methods_in_str(&content, method_map, Some(&path_str));
    write_text_lf(smali_path, &patched)?;
    Ok(count)
}

/// Hook mode (`patchmethod_v2.py -d <dir> -k <keyword_regex> -hook <hook_line_with_reg>`):
/// Recursively scans `.smali` files in parallel, finds lines matching `keyword_pattern`,
/// and replaces the next `move-result <reg>` line with `hook_line_template.replace("reg", reg)`.
pub fn search_and_hook(
    smali_dir: &Path,
    keyword_pattern: &str,
    hook_line_template: &str,
) -> Result<usize> {
    let keyword_re = Regex::new(keyword_pattern)
        .with_context(|| format!("Invalid keyword regex: {}", keyword_pattern))?;
    let move_result_re = Regex::new(r"^\s*move-result\s+([vp]\d+)").unwrap();

    let files = collect_smali_files(smali_dir, true, None);
    let patched_files = AtomicUsize::new(0);

    files.par_iter().for_each(|path| {
        let Ok(Some(content)) = read_file_if_matches(path, |text| keyword_re.is_match(text)) else {
            return;
        };

        let mut modified = false;
        let mut found_keyword = false;
        let mut new_content = String::with_capacity(content.len() + 64);

        for line in content.split_inclusive('\n') {
            let line_no_nl = line.trim_end_matches('\n').trim_end_matches('\r');
            if !found_keyword && keyword_re.is_match(line_no_nl) {
                found_keyword = true;
            }

            if found_keyword {
                if let Some(caps) = move_result_re.captures(line_no_nl) {
                    let reg = caps.get(1).unwrap().as_str();
                    let hook_line = hook_line_template.replace("reg", reg);
                    new_content.push_str(&hook_line);
                    new_content.push('\n');
                    modified = true;
                    found_keyword = false;
                    continue;
                }
            }

            new_content.push_str(line_no_nl);
            new_content.push('\n');
        }

        if modified {
            if let Err(e) = write_text_lf(path, &new_content) {
                eprintln!("Error writing {}: {}", path.display(), e);
            } else {
                patched_files.fetch_add(1, Ordering::Relaxed);
                println!("----> Patched {}", path.display());
            }
        }
    });

    Ok(patched_files.load(Ordering::Relaxed))
}

/// Directory + keyword search mode (`patchmethod_v2.py -d <dir> -k <kw1> [kw2 ...] [-return ...] [-m <file>]`).
pub fn search_and_patch(
    smali_dir: &Path,
    keywords: &[String],
    return_type: ReturnType,
    method_body: Option<&str>,
) -> Result<usize> {
    let method_block_re = Regex::new(
        r"(?s)\.method\s+(?:(?:public|private|protected)\s+)?(?:static\s+)?(?:final\s+)?([^\(]+)\(.*?\.end method",
    )
    .unwrap();
    let method_header_re = Regex::new(
        r"\.method\s+(?:(?:public|private|protected)\s+)?(?:static\s+)?(?:final\s+)?([^\(]+)\(",
    )
    .unwrap();

    let files = collect_smali_files(smali_dir, true, None);
    let patched_methods = AtomicUsize::new(0);

    files.par_iter().for_each(|smali_path| {
        let Ok(Some(smali_content)) = read_file_if_matches(smali_path, |text| {
            keywords.iter().all(|kw| text.contains(kw.as_str()))
        }) else {
            return;
        };

        let mut matched_names: Vec<String> = Vec::new();
        for caps in method_block_re.captures_iter(&smali_content) {
            let method_content = caps.get(0).unwrap().as_str();
            if keywords.iter().all(|kw| method_content.contains(kw.as_str())) {
                if let Some(h_caps) = method_header_re.captures(method_content) {
                    let method_name = h_caps.get(1).unwrap().as_str().to_string();
                    println!(
                        "Found method '{}' in file: {}",
                        method_name,
                        smali_path.display()
                    );
                    matched_names.push(method_name);
                }
            }
        }

        if matched_names.is_empty() {
            return;
        }

        for method_name in matched_names {
            if let Some(body) = method_body {
                if let Ok(true) = replace_method_body(smali_path, &method_name, body) {
                    patched_methods.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                let mut set = HashSet::new();
                set.insert(method_name);
                if let Ok(cnt) = patch_method_in_file(smali_path, &set, return_type) {
                    patched_methods.fetch_add(cnt, Ordering::Relaxed);
                }
            }
        }
    });

    Ok(patched_methods.load(Ordering::Relaxed))
}

// ============================================================================
// 3. Specialized Smali Patchers (`patch_apk_protection.py`, `patch_cos17_engineer.py`,
//    `patch_inspiration_aod_gate.py`)
// ============================================================================

/// Patch `ApkSignatureVerifier.smali` content (`bin/patch_apk_protection.py`).
pub fn patch_apk_signature_verifier_str(content: &str) -> (String, bool) {
    let mut current = content.to_string();
    let mut modified = false;

    // 1. getMinimumSignatureSchemeVersionForTargetSdk -> return 1
    let min_sig_re = Regex::new(
        r"(?ms)(?P<header>^[ \t]*\.method[^\n\r]*?[ \t]getMinimumSignatureSchemeVersionForTargetSdk\([^\r\n]*\r?\n)(?P<body>.*?)(?P<footer>^[ \t]*\.end method)",
    )
    .unwrap();
    if let Some(caps) = min_sig_re.captures(&current) {
        let full = caps.get(0).unwrap();
        let header = caps.name("header").unwrap().as_str();
        let footer = caps.name("footer").unwrap().as_str();
        let replacement = format!(
            "{}\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n{}",
            header, footer
        );
        if full.as_str() != replacement {
            current.replace_range(full.range(), &replacement);
            modified = true;
        }
    }

    // 2. In verifySignaturesInternal, insert const/4 p3, 0x0 on a new line before verifyV calls
    let verify_re = Regex::new(
        r"(?ms)(?P<header>^[ \t]*\.method[^\n\r]*?[ \t]verifySignaturesInternal\([^\r\n]*\r?\n)(?P<body>.*?)(?P<footer>^[ \t]*\.end method)",
    )
    .unwrap();
    let indent_re = Regex::new(r"^(\s*)").unwrap();

    if let Some(caps) = verify_re.captures(&current) {
        let full = caps.get(0).unwrap();
        let header = caps.name("header").unwrap().as_str();
        let body = caps.name("body").unwrap().as_str();
        let footer = caps.name("footer").unwrap().as_str();

        if !body.contains("const/4 p3, 0x0") {
            let mut new_lines = String::with_capacity(body.len() + 32);
            let mut body_modified = false;
            for line in body.split_inclusive('\n') {
                if line.contains("Landroid/util/apk/ApkSignatureVerifier;->verifyV") {
                    let indent = indent_re
                        .captures(line)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str())
                        .unwrap_or("    ");
                    new_lines.push_str(indent);
                    new_lines.push_str("const/4 p3, 0x0\n");
                    body_modified = true;
                }
                new_lines.push_str(line);
            }
            if body_modified {
                let replacement = format!("{}{}{}", header, new_lines, footer);
                current.replace_range(full.range(), &replacement);
                modified = true;
            }
        }
    }

    (current, modified)
}

/// Apply APK Protection patch to `decompiled_dir` (`bin/patch_apk_protection.py`).
pub fn patch_apk_protection(decompiled_dir: &Path) -> Result<usize> {
    if !decompiled_dir.is_dir() {
        eprintln!("Error: {} is not a directory", decompiled_dir.display());
        bail!("{} is not a directory", decompiled_dir.display());
    }

    let candidates = collect_smali_files(decompiled_dir, true, Some("ApkSignatureVerifier.smali"));
    let total_patched = AtomicUsize::new(0);

    candidates.par_iter().for_each(|smali_file| {
        if smali_file.file_name().and_then(|s| s.to_str()) != Some("ApkSignatureVerifier.smali") {
            return;
        }
        let Ok(content) = read_file_mmap_lf(smali_file) else {
            return;
        };
        let (new_text, changed) = patch_apk_signature_verifier_str(&content);
        if changed {
            if write_text_lf(smali_file, &new_text).is_ok() {
                total_patched.fetch_add(1, Ordering::Relaxed);
                println!("[+] Patched ApkSignatureVerifier in {}", smali_file.display());
            }
        }
    });

    let count = total_patched.load(Ordering::Relaxed);
    println!(
        "[*] APK Protection patch finished. Patched {} files.",
        count
    );
    Ok(count)
}

/// Empty `OplusEngineerFwService.onBootPhase(I)V` in a decoded services JAR (`bin/patch_cos17_engineer.py`).
pub fn patch_cos17_engineer(root: &Path) -> Result<PathBuf> {
    let candidates = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        collect_smali_files(root, true, Some("OplusEngineerFwService.smali"))
            .into_iter()
            .filter(|p| {
                p.file_name().and_then(|s| s.to_str()) == Some("OplusEngineerFwService.smali")
            })
            .collect()
    };

    if candidates.len() != 1 {
        bail!(
            "Expected one OplusEngineerFwService.smali, found {}",
            candidates.len()
        );
    }

    let target = &candidates[0];
    let source = read_file_mmap_lf(target)?;
    let method_re = Regex::new(
        r"(?ms)^(\.method[^\r\n]*\b(?i:onbootphase)\(I\)V[^\r\n]*\r?\n).*?^\.end method\b",
    )
    .unwrap();
    let abstract_native_re = Regex::new(r"\b(?:abstract|native)\b").unwrap();

    let matches: Vec<_> = method_re.captures_iter(&source).collect();
    if matches.len() != 1 {
        bail!(
            "Expected one onBootPhase(I)V in {}, found {}",
            target.display(),
            matches.len()
        );
    }

    let header = matches[0].get(1).unwrap().as_str();
    if abstract_native_re.is_match(header) {
        bail!("Cannot replace an abstract/native onBootPhase method");
    }

    let full_match = matches[0].get(0).unwrap();
    let replacement = format!("{}    .locals 0\n    return-void\n.end method", header);
    let mut result = source.clone();
    result.replace_range(full_match.range(), &replacement);

    if result != source {
        write_text_lf(target, &result)?;
    }
    println!(
        "COS17: OplusEngineerFwService.onBootPhase(I)V -> return-void ({})",
        target.display()
    );
    Ok(target.clone())
}

const INSPIRATION_SETTING_KEY: &str = "oplus_keyguard_workshop_aod_support";
const INSPIRATION_MARKERS: &[&str] = &[
    "Landroid/provider/Settings$Secure;->getInt",
    "->b(Landroid/content/ContentResolver;Ljava/lang/String;I)I",
];

fn patch_inspiration_method(lines: &[&str]) -> (Vec<String>, bool) {
    let method_text = lines.concat();
    if !method_text.contains(INSPIRATION_SETTING_KEY)
        || !INSPIRATION_MARKERS
            .iter()
            .any(|marker| method_text.contains(marker))
    {
        return (lines.iter().map(|s| (*s).to_string()).collect(), false);
    }

    let Some(key_index) = lines
        .iter()
        .position(|line| line.contains(INSPIRATION_SETTING_KEY))
    else {
        return (lines.iter().map(|s| (*s).to_string()).collect(), false);
    };

    let Some(get_int_index) = (key_index..lines.len()).find(|&idx| {
        INSPIRATION_MARKERS
            .iter()
            .any(|marker| lines[idx].contains(marker))
    }) else {
        return (lines.iter().map(|s| (*s).to_string()).collect(), false);
    };

    let move_result_re =
        Regex::new(r"^(?P<indent>\s*)move-result(?:-wide)?\s+(?P<reg>[vp]\d+)\s*$").unwrap();

    let mut result_index = None;
    let mut result_register = String::new();
    let mut indent = String::new();

    for idx in (get_int_index + 1)..lines.len() {
        let trimmed = lines[idx].trim_end_matches('\n').trim_end_matches('\r');
        if let Some(caps) = move_result_re.captures(trimmed) {
            result_index = Some(idx);
            result_register = caps.name("reg").unwrap().as_str().to_string();
            indent = caps.name("indent").unwrap().as_str().to_string();
            break;
        }
        if lines[idx].contains("invoke-") && !lines[idx].contains("move-result") {
            break;
        }
    }

    let Some(res_idx) = result_index else {
        return (lines.iter().map(|s| (*s).to_string()).collect(), false);
    };

    let already_re =
        Regex::new(&format!(r"const/4\s+{},\s+0x1\s*$", regex::escape(&result_register))).unwrap();
    let end_check = (res_idx + 3).min(lines.len());
    for line in &lines[(res_idx + 1)..end_check] {
        if already_re.is_match(line.trim()) {
            return (lines.iter().map(|s| (*s).to_string()).collect(), false);
        }
    }

    let patch_line = format!(
        "{}# romport: make the A16 workshop AOD capability available\n{}const/4 {}, 0x1\n",
        indent, indent, result_register
    );

    let mut patched: Vec<String> = Vec::with_capacity(lines.len() + 1);
    for l in &lines[..=res_idx] {
        patched.push((*l).to_string());
    }
    patched.push(patch_line);
    for l in &lines[(res_idx + 1)..] {
        patched.push((*l).to_string());
    }

    (patched, true)
}

/// Patch ColorOS 16 inspiration-AOD gate in a single smali file (`bin/patch_inspiration_aod_gate.py`).
pub fn patch_inspiration_aod_gate_file(path: &Path) -> Result<Vec<String>> {
    let Some(text) = read_file_if_matches(path, |t| t.contains(INSPIRATION_SETTING_KEY))? else {
        return Ok(Vec::new());
    };

    let method_name_re = Regex::new(r"^\.method\s+.*?\s(?P<name>[^\s(]+)\(").unwrap();
    let lines: Vec<&str> = text.split_inclusive('\n').collect();

    let mut patched_lines: Vec<String> = Vec::with_capacity(lines.len() + 4);
    let mut patched_methods: Vec<String> = Vec::new();
    let mut method_start: Option<usize> = None;
    let mut method_name = String::from("<unknown>");
    let mut cursor = 0usize;

    for (index, &line) in lines.iter().enumerate() {
        if line.starts_with(".method ") {
            if method_start.is_some() {
                // Nested/malformed method block; leave untouched
                return Ok(Vec::new());
            }
            for &l in &lines[cursor..index] {
                patched_lines.push(l.to_string());
            }
            method_start = Some(index);
            let header = line.trim_end_matches(&['\r', '\n'][..]);
            method_name = method_name_re
                .captures(header)
                .and_then(|c| c.name("name"))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
        }
        if let Some(start) = method_start {
            if line.starts_with(".end method") {
                let (m_lines, changed) = patch_inspiration_method(&lines[start..=index]);
                if changed {
                    patched_methods.push(method_name.clone());
                }
                patched_lines.extend(m_lines);
                cursor = index + 1;
                method_start = None;
            }
        }
    }

    if method_start.is_some() {
        return Ok(Vec::new());
    }

    for &l in &lines[cursor..] {
        patched_lines.push(l.to_string());
    }

    if patched_methods.is_empty() {
        return Ok(Vec::new());
    }

    let new_content = patched_lines.concat();
    write_text_lf(path, &new_content)?;
    Ok(patched_methods)
}

/// Patch ColorOS 16 inspiration-AOD gate in a file or directory (`bin/patch_inspiration_aod_gate.py`).
pub fn patch_inspiration_aod_gate(target: &Path) -> Result<usize> {
    if !target.exists() {
        eprintln!("Target not found: {}", target.display());
        bail!("Target not found: {}", target.display());
    }

    let files = collect_smali_files(target, true, None);
    let results: Vec<(PathBuf, Vec<String>)> = files
        .par_iter()
        .filter_map(|path| match patch_inspiration_aod_gate_file(path) {
            Ok(methods) if !methods.is_empty() => Some((path.clone(), methods)),
            _ => None,
        })
        .collect();

    let mut changed = 0usize;
    for (path, methods) in results {
        for method in methods {
            changed += 1;
            println!(
                "----> patched inspiration AOD gate in {}: {}",
                path.display(),
                method
            );
        }
    }

    if changed == 0 {
        eprintln!("----> no ColorOS 16 inspiration AOD gate found; refusing a silent no-op");
        bail!("no ColorOS 16 inspiration AOD gate found; refusing a silent no-op");
    }

    Ok(changed)
}

// ============================================================================
// 4. Unified CLI Parser & Dispatcher
// ============================================================================

pub fn print_usage() {
    println!(
        "\
Usage:
  # SmaliKit mode (bin/smalikit.py compatible):
  smali-patcher [smalikit] -p <path> [-m <method>] [-in <filter>] [-remake <body>]
                [-rim <old> <new>] [-reg <pattern> <replacement>] [-dim <str>]
                [-dm] [-al <target_line> <add_line>] [-bl <target_line> <add_line>]
                [-recursive]

  # PatchMethod v2 modes (bin/patchmethod_v2.py compatible):
  smali-patcher [patchmethod] <smali_file> <method_name> [-return true|false|void] [<method_body_string>]
  smali-patcher [patchmethod] -d <directory> -k <keyword1> [keyword2 ...] [-return true|false|void] [-m <method_body_file>]
  smali-patcher [patchmethod] -d <directory> -k <keyword_regex> -hook <hook_code_with_reg>

  # Legacy PatchMethod mode (bin/patchmethod.py compatible):
  smali-patcher [patchmethod] <smali_file> [method | -method | --method ...]

  # Specialized Smali patches:
  smali-patcher apk-protection <decompiled_dir>
  smali-patcher cos17-engineer <decoded_jar_dir>
  smali-patcher inspiration-aod-gate <smali_file_or_dir>"
    );
}

fn parse_smalikit_args(args: &[String]) -> Result<SmaliKitConfig> {
    let mut cfg = SmaliKitConfig::default();
    let mut has_path = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--path" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing argument for -p"))?;
                cfg.path = PathBuf::from(val);
                has_path = true;
            }
            "-m" | "--method" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing argument for -m"))?;
                cfg.method = Some(val.clone());
            }
            "-in" | "--iname" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing argument for -in"))?;
                cfg.iname = Some(val.clone());
            }
            "-remake" | "--remake" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing argument for -remake"))?;
                cfg.remake = Some(val.clone());
            }
            "-rim" | "--replace-in-method" => {
                if i + 2 >= args.len() {
                    bail!("Missing arguments for -rim <old> <new>");
                }
                cfg.replace_in_method = Some((args[i + 1].clone(), args[i + 2].clone()));
                i += 2;
            }
            "-reg" | "--regex-replace" => {
                if i + 2 >= args.len() {
                    bail!("Missing arguments for -reg <pattern> <replacement>");
                }
                cfg.regex_replace = Some((args[i + 1].clone(), args[i + 2].clone()));
                i += 2;
            }
            "-dim" | "--delete-in-method" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing argument for -dim"))?;
                cfg.delete_in_method = Some(val.clone());
            }
            "-dm" | "--delete-method" => {
                cfg.delete_method = true;
            }
            "-al" | "--after-line" => {
                if i + 2 >= args.len() {
                    bail!("Missing arguments for -al <target_line> <add_line>");
                }
                cfg.after_line = Some((args[i + 1].clone(), args[i + 2].clone()));
                i += 2;
            }
            "-bl" | "--before-line" => {
                if i + 2 >= args.len() {
                    bail!("Missing arguments for -bl <target_line> <add_line>");
                }
                cfg.before_line = Some((args[i + 1].clone(), args[i + 2].clone()));
                i += 2;
            }
            "-recursive" | "--recursive" | "-r" => {
                cfg.recursive = true;
            }
            other => {
                bail!("Unknown smalikit argument: {}", other);
            }
        }
        i += 1;
    }

    if !has_path {
        bail!("Missing required argument -p <path>");
    }
    if cfg.method.is_none() && (cfg.remake.is_some() || cfg.delete_method) {
        bail!("Missing required argument -m <method> for -remake / -dm");
    }

    Ok(cfg)
}

fn is_probable_method_body(s: &str) -> bool {
    s.contains('\n')
        || s.contains("\\n")
        || s.contains('\t')
        || s.contains("\\t")
        || s.contains(' ')
        || s.trim_start().starts_with('.')
}

fn run_patchmethod_args(args: &[String]) -> Result<()> {
    if args.is_empty() {
        print_usage();
        bail!("No arguments provided");
    }

    let has_d = args.iter().any(|a| a == "-d");
    let has_k = args.iter().any(|a| a == "-k");
    let has_hook = args.iter().any(|a| a == "-hook");

    // 1. Hook mode: -d <dir> -k <keyword_regex> -hook <hook_line_with_reg>
    if has_d && has_k && has_hook {
        let dir_idx = args.iter().position(|a| a == "-d").unwrap() + 1;
        let key_idx = args.iter().position(|a| a == "-k").unwrap() + 1;
        let hook_idx = args.iter().position(|a| a == "-hook").unwrap() + 1;

        if dir_idx >= args.len() || key_idx >= args.len() || hook_idx >= args.len() {
            bail!("Error: Missing argument for -d, -k or -hook.");
        }

        let smali_dir = Path::new(&args[dir_idx]);
        let keyword_pattern = &args[key_idx];
        let hook_line_template = &args[hook_idx];

        search_and_hook(smali_dir, keyword_pattern, hook_line_template)?;
        return Ok(());
    }

    let mut return_type = ReturnType::True;
    if let Some(pos) = args.iter().position(|a| a == "-return") {
        let val = args
            .get(pos + 1)
            .ok_or_else(|| anyhow!("Error: Missing return type after -return."))?;
        return_type = ReturnType::parse_str(val)?;
    }

    let mut method_body: Option<String> = None;
    if let Some(pos) = args.iter().position(|a| a == "-m") {
        let method_file = args
            .get(pos + 1)
            .ok_or_else(|| anyhow!("Error: Missing method body file after -m."))?;
        let path = Path::new(method_file);
        if !path.is_file() {
            bail!("Error: Cannot find method body file {}", method_file);
        }
        method_body = Some(read_file_mmap_lf(path)?);
    }

    // 2. Directory + keyword match mode: -d <dir> -k <kw1> [kw2 ...] [-return ...] [-m <file>]
    if has_d && has_k {
        let dir_idx = args.iter().position(|a| a == "-d").unwrap() + 1;
        if dir_idx >= args.len() {
            bail!("Error: Missing directory after -d.");
        }
        let smali_dir = Path::new(&args[dir_idx]);

        let keyword_idx = args.iter().position(|a| a == "-k").unwrap() + 1;
        let mut keywords = Vec::new();
        let mut i = keyword_idx;
        while i < args.len() {
            if args[i] == "-return" || args[i] == "-m" || args[i] == "-d" {
                break;
            }
            keywords.push(args[i].clone());
            i += 1;
        }

        if keywords.is_empty() {
            bail!("Error: Missing keywords after -k.");
        }

        search_and_patch(smali_dir, &keywords, return_type, method_body.as_deref())?;
        return Ok(());
    }

    // 3. Single-file mode (`patchmethod_v2.py` and legacy `patchmethod.py`)
    let smali_path = Path::new(&args[0]);
    if args.len() == 1 {
        return Ok(());
    }

    // Collect remaining arguments excluding `-return <type>`
    let mut positional: Vec<String> = Vec::new();
    let mut has_explicit_return = false;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-return" {
            has_explicit_return = true;
            if i + 1 < args.len() {
                return_type = ReturnType::parse_str(&args[i + 1])?;
                i += 2;
                continue;
            } else {
                bail!("Error: Missing return type after -return.");
            }
        }
        positional.push(args[i].clone());
        i += 1;
    }

    if positional.is_empty() {
        bail!("Error: Missing method name");
    }

    // Check if this is `patchmethod_v2.py <file> <method_name> <extra_method_body>`
    if positional.len() == 2
        && !positional[0].starts_with('-')
        && is_probable_method_body(&positional[1])
    {
        if !smali_path.is_file() {
            bail!("Error: Smali file not found: {}", smali_path.display());
        }
        replace_method_body(smali_path, &positional[0], &positional[1])?;
        return Ok(());
    }

    // Otherwise, build `method_map` supporting both `patchmethod_v2.py` and legacy `patchmethod.py`
    // prefix syntax (`--method` => void, `-method` => false, `method` => return_type).
    let mut method_map: HashMap<String, ReturnType> = HashMap::new();
    for raw_arg in positional {
        if let Some(stripped) = raw_arg.strip_prefix("--") {
            if !stripped.is_empty() {
                method_map.insert(stripped.to_string(), ReturnType::Void);
            }
        } else if let Some(stripped) = raw_arg.strip_prefix('-') {
            if !stripped.is_empty() {
                let rt = if has_explicit_return {
                    return_type
                } else {
                    ReturnType::False
                };
                method_map.insert(stripped.to_string(), rt);
            }
        } else {
            method_map.insert(raw_arg, return_type);
        }
    }

    patch_method_map_in_file(smali_path, &method_map)?;
    Ok(())
}

pub fn run_cli(cli: Cli) -> Result<()> {
    let args = &cli.args;
    if args.is_empty()
        || (args.len() == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help"))
    {
        print_usage();
        return Ok(());
    }

    if args.len() == 1 && (args[0] == "-V" || args[0] == "--version") {
        println!("smali-patcher {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Subcommand / explicit mode dispatch
    match args[0].as_str() {
        "smalikit" => {
            let cfg = parse_smalikit_args(&args[1..])?;
            cfg.walk_and_patch()?;
            return Ok(());
        }
        "patchmethod" | "patchmethod_v2" => {
            return run_patchmethod_args(&args[1..]);
        }
        "apk-protection" | "--apk-protection" => {
            let dir = args
                .get(1)
                .ok_or_else(|| anyhow!("Usage: smali-patcher apk-protection <decompiled_dir>"))?;
            patch_apk_protection(Path::new(dir))?;
            return Ok(());
        }
        "cos17-engineer" | "--cos17-engineer" => {
            let dir = args
                .get(1)
                .ok_or_else(|| anyhow!("Usage: smali-patcher cos17-engineer <decoded_jar_dir>"))?;
            patch_cos17_engineer(Path::new(dir))?;
            return Ok(());
        }
        "inspiration-aod-gate" | "--inspiration-aod-gate" => {
            let target = args.get(1).ok_or_else(|| {
                anyhow!("Usage: smali-patcher inspiration-aod-gate <smali-file-or-directory>")
            })?;
            patch_inspiration_aod_gate(Path::new(target))?;
            return Ok(());
        }
        _ => {}
    }

    // Auto-detect SmaliKit mode when `-p` is passed (and `-d` is not passed)
    let is_smalikit = args.iter().any(|a| a == "-p" || a == "--path")
        && !args.iter().any(|a| a == "-d");

    if is_smalikit {
        let cfg = parse_smalikit_args(args)?;
        cfg.walk_and_patch()?;
        Ok(())
    } else {
        run_patchmethod_args(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const SAMPLE_SMALI: &str = "\
.class public Lcom/oplus/test/Sample;
.super Ljava/lang/Object;

.method public isSupport()Z
    .locals 2
    const/4 v0, 0x0
    return v0
.end method

.method public static isGmsRestricted(Ljava/lang/String;)Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method

.method public assertMinSignatureSchemeIsValid(I)V
    .locals 1
    new-instance v0, Ljava/lang/SecurityException;
    throw v0
.end method

.method public final getFirstApiLevel()I
    .locals 2
    const-string v0, \"ro.product.first_api_level\"
    const/16 v1, 0x1e
    invoke-static {v0, v1}, Landroid/os/SystemProperties;->getInt(Ljava/lang/String;I)I
    move-result v0
    return v0
.end method
";

    #[test]
    fn test_smalikit_all_flags() -> Result<()> {
        let tmp = TempDir::new()?;
        let smali_file = tmp.path().join("Sample.smali");
        write_text_lf(&smali_file, SAMPLE_SMALI)?;

        // 1. -remake
        run_cli(Cli {
            args: vec![
                "-p".into(),
                smali_file.to_string_lossy().into_owned(),
                "-m".into(),
                "isSupport()Z".into(),
                "-remake".into(),
                ".locals 1\\n    const/4 v0, 0x1\\n    return v0".into(),
            ],
        })?;
        let text = read_file_mmap_lf(&smali_file)?;
        assert!(text.contains(
            ".method public isSupport()Z\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method"
        ));

        // 2. -rim, -al, -bl, -dim on getFirstApiLevel
        run_cli(Cli {
            args: vec![
                "-p".into(),
                smali_file.to_string_lossy().into_owned(),
                "-m".into(),
                "getFirstApiLevel".into(),
                "-rim".into(),
                "0x1e".into(),
                "0x22".into(),
                "-al".into(),
                ".locals 2".into(),
                "# after locals".into(),
                "-bl".into(),
                "return v0".into(),
                "# before return".into(),
            ],
        })?;
        let text = read_file_mmap_lf(&smali_file)?;
        assert!(text.contains("const/16 v1, 0x22"));
        assert!(text.contains(".locals 2\n    # after locals"));
        assert!(text.contains("        # before return\nreturn v0"));

        // 3. -dim
        run_cli(Cli {
            args: vec![
                "-p".into(),
                smali_file.to_string_lossy().into_owned(),
                "-m".into(),
                "getFirstApiLevel".into(),
                "-dim".into(),
                "    # after locals\n".into(),
            ],
        })?;
        let text = read_file_mmap_lf(&smali_file)?;
        assert!(!text.contains("# after locals"));

        // 4. -reg with Python \1 backreference AND Smali inner-class `$` (e.g. Settings$Secure / Foo$1)
        let model_smali = tmp.path().join("Model.smali");
        write_text_lf(
            &model_smali,
            ".class public LModel;\n.super Ljava/lang/Object;\n.method public getModel()Ljava/lang/String;\n    .locals 1\n    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;\n    return-object v0\n.end method\n",
        )?;
        run_cli(Cli {
            args: vec![
                "-p".into(),
                tmp.path().to_string_lossy().into_owned(),
                "-m".into(),
                "getModel".into(),
                "-in".into(),
                "Model".into(),
                "-reg".into(),
                r"sget-object ([vp]\d+), Landroid/os/Build;->MODEL:Ljava/lang/String;".into(),
                r#"const-string \1, "PLG110$1""#.into(),
                "-recursive".into(),
            ],
        })?;
        let model_text = read_file_mmap_lf(&model_smali)?;
        assert!(model_text.contains(r#"const-string v0, "PLG110$1""#));

        // 5. -dm (delete method)
        run_cli(Cli {
            args: vec![
                "-p".into(),
                smali_file.to_string_lossy().into_owned(),
                "-m".into(),
                "assertMinSignatureSchemeIsValid".into(),
                "-dm".into(),
            ],
        })?;
        let text = read_file_mmap_lf(&smali_file)?;
        assert!(!text.contains("assertMinSignatureSchemeIsValid"));

        Ok(())
    }

    #[test]
    fn test_patchmethod_legacy_and_v2_single_file() -> Result<()> {
        let tmp = TempDir::new()?;
        let smali_file = tmp.path().join("Sample.smali");
        write_text_lf(&smali_file, SAMPLE_SMALI)?;

        // Legacy patchmethod.py syntax: `isSupport` (true), `-isGmsRestricted` (false), `--assertMinSignatureSchemeIsValid` (void)
        run_cli(Cli {
            args: vec![
                smali_file.to_string_lossy().into_owned(),
                "isSupport".into(),
                "-isGmsRestricted".into(),
                "--assertMinSignatureSchemeIsValid".into(),
            ],
        })?;

        let text = read_file_mmap_lf(&smali_file)?;
        assert!(text.contains(
            ".method public isSupport()Z\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method"
        ));
        assert!(text.contains(
            ".method public static isGmsRestricted(Ljava/lang/String;)Z\n    .locals 1\n    const/4 v0, 0x0\n    return v0\n.end method"
        ));
        assert!(text.contains(
            ".method public assertMinSignatureSchemeIsValid(I)V\n    .locals 0\n    return-void\n.end method"
        ));

        // patchmethod_v2.py inline body replacement with \n and \t escapes (port.sh line 1449)
        run_cli(Cli {
            args: vec![
                smali_file.to_string_lossy().into_owned(),
                "getFirstApiLevel".into(),
                ".locals 1\\n\\tconst/16 v0, 0x22\\n\\treturn v0".into(),
            ],
        })?;
        let text = read_file_mmap_lf(&smali_file)?;
        assert!(text.contains(
            ".method public final getFirstApiLevel()I\n.locals 1\n\tconst/16 v0, 0x22\n\treturn v0\n.end method"
        ));

        Ok(())
    }

    #[test]
    fn test_patchmethod_v2_hook_and_dir_search() -> Result<()> {
        let tmp = TempDir::new()?;
        let sub_dir = tmp.path().join("smali/com/oplus/gallery");
        fs::create_dir_all(&sub_dir)?;
        let smali_file = sub_dir.join("GalleryUtil.smali");
        write_text_lf(&smali_file, SAMPLE_SMALI)?;

        // 1. Hook mode (port.sh line 1390)
        run_cli(Cli {
            args: vec![
                "-d".into(),
                tmp.path().to_string_lossy().into_owned(),
                "-k".into(),
                r#"const-string.*"ro.product.first_api_level""#.into(),
                "-hook".into(),
                "     const/16 reg, 0x22".into(),
            ],
        })?;
        let text = read_file_mmap_lf(&smali_file)?;
        assert!(text.contains("     const/16 v0, 0x22\n    return v0"));
        assert!(!text.contains("move-result v0"));

        // 2. Directory keyword search with -m body file (port.sh line 1411)
        let body_file = tmp.path().join("custom_body.txt");
        write_text_lf(&body_file, "    .locals 1\n    const/16 v0, 0x64\n    return v0\n")?;

        run_cli(Cli {
            args: vec![
                "-d".into(),
                tmp.path().to_string_lossy().into_owned(),
                "-k".into(),
                "SecurityException".into(),
                "-m".into(),
                body_file.to_string_lossy().into_owned(),
            ],
        })?;
        let text = read_file_mmap_lf(&smali_file)?;
        assert!(text.contains(
            ".method public assertMinSignatureSchemeIsValid(I)V\n.locals 1\n    const/16 v0, 0x64\n    return v0\n.end method"
        ));

        // 3. Directory keyword search with -return false
        run_cli(Cli {
            args: vec![
                "-d".into(),
                tmp.path().to_string_lossy().into_owned(),
                "-k".into(),
                "ro.product.first_api_level".into(),
                "SystemProperties".into(),
                "-return".into(),
                "false".into(),
            ],
        })?;
        let text = read_file_mmap_lf(&smali_file)?;
        assert!(text.contains(
            ".method public final getFirstApiLevel()I\n    .locals 1\n    const/4 v0, 0x0\n    return v0\n.end method"
        ));

        Ok(())
    }

    #[test]
    fn test_specialized_patches_apk_protection_cos17_inspiration_aod() -> Result<()> {
        let tmp = TempDir::new()?;

        // 1. APK Protection
        let apk_dir = tmp.path().join("framework/smali/android/util/apk");
        fs::create_dir_all(&apk_dir)?;
        let verifier = apk_dir.join("ApkSignatureVerifier.smali");
        write_text_lf(
            &verifier,
            ".class public Landroid/util/apk/ApkSignatureVerifier;\n.super Ljava/lang/Object;\n\n.method public static getMinimumSignatureSchemeVersionForTargetSdk(I)I\n    .locals 1\n    const/4 v0, 0x2\n    return v0\n.end method\n\n.method private static verifySignaturesInternal(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;IZ)Landroid/content/pm/parsing/result/ParseResult;\n    .registers 5\n    invoke-static {p0, p1, p2}, Landroid/util/apk/ApkSignatureVerifier;->verifyV1Signature(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;I)Landroid/content/pm/parsing/result/ParseResult;\n    move-result-object v0\n    return-object v0\n.end method\n",
        )?;
        run_cli(Cli {
            args: vec![
                "apk-protection".into(),
                tmp.path().join("framework").to_string_lossy().into_owned(),
            ],
        })?;
        let v_text = read_file_mmap_lf(&verifier)?;
        assert!(v_text.contains("const/4 v0, 0x1"));
        assert!(v_text.contains("    const/4 p3, 0x0\n    invoke-static {p0, p1, p2}, Landroid/util/apk/ApkSignatureVerifier;->verifyV1Signature"));

        // 2. COS17 Engineer
        let eng_dir = tmp.path().join("oplus-services");
        fs::create_dir_all(&eng_dir)?;
        let eng_file = eng_dir.join("OplusEngineerFwService.smali");
        write_text_lf(
            &eng_file,
            ".class public Lcom/android/server/engineer/OplusEngineerFwService;\n.super Ljava/lang/Object;\n.method public onBootPhase(I)V\n    .locals 1\n    const-string v0, \"side-effect\"\n    return-void\n.end method\n.method public keep()V\n    .locals 0\n    return-void\n.end method\n",
        )?;
        run_cli(Cli {
            args: vec![
                "cos17-engineer".into(),
                eng_dir.to_string_lossy().into_owned(),
            ],
        })?;
        let e_text = read_file_mmap_lf(&eng_file)?;
        assert!(!e_text.contains("side-effect"));
        assert!(e_text.contains("onBootPhase(I)V\n    .locals 0\n    return-void\n.end method"));
        // Repeatability
        run_cli(Cli {
            args: vec![
                "cos17-engineer".into(),
                eng_dir.to_string_lossy().into_owned(),
            ],
        })?;
        assert_eq!(read_file_mmap_lf(&eng_file)?, e_text);

        // 3. Inspiration AOD Gate
        let aod_file = tmp.path().join("CommonUtils.smali");
        write_text_lf(
            &aod_file,
            ".class public Lcom/oplus/wallpapers/rely/utils/m$z;\n.super Ljava/lang/Object;\n.method public static check()Z\n    .locals 3\n    const/4 v0, 0x0\n    const-string v1, \"oplus_keyguard_workshop_aod_support\"\n    const/4 v2, 0x0\n    invoke-static {v0, v1, v2}, Landroid/provider/Settings$Secure;->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I\n    move-result v0\n    return v0\n.end method\n",
        )?;
        run_cli(Cli {
            args: vec![
                "inspiration-aod-gate".into(),
                aod_file.to_string_lossy().into_owned(),
            ],
        })?;
        let a_text = read_file_mmap_lf(&aod_file)?;
        assert!(a_text.contains("    move-result v0\n    # romport: make the A16 workshop AOD capability available\n    const/4 v0, 0x1\n    return v0"));
        // Second run is a no-op and returns error just like Python script
        assert!(patch_inspiration_aod_gate(&aod_file).is_err());

        Ok(())
    }

    #[test]
    fn test_clap_cli_parsing_all_flag_styles() -> Result<()> {
        let tmp = TempDir::new()?;
        let smali_file = tmp.path().join("ScanPackageUtils.smali");
        write_text_lf(&smali_file, SAMPLE_SMALI)?;

        // 1. Legacy patchmethod.py with `--method` and `-method` parsed via `Cli::try_parse_from`
        let cli = Cli::try_parse_from([
            "smali-patcher",
            smali_file.to_str().unwrap(),
            "--assertMinSignatureSchemeIsValid",
            "-isGmsRestricted",
            "isSupport",
        ])?;
        run_cli(cli)?;

        let text = read_file_mmap_lf(&smali_file)?;
        assert!(text.contains(
            ".method public assertMinSignatureSchemeIsValid(I)V\n    .locals 0\n    return-void\n.end method"
        ));
        assert!(text.contains(
            ".method public static isGmsRestricted(Ljava/lang/String;)Z\n    .locals 1\n    const/4 v0, 0x0\n    return v0\n.end method"
        ));
        assert!(text.contains(
            ".method public isSupport()Z\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method"
        ));

        // 2. SmaliKit single-dash multi-char flags parsed via `Cli::try_parse_from`
        let cli2 = Cli::try_parse_from([
            "smali-patcher",
            "-p",
            smali_file.to_str().unwrap(),
            "-m",
            "getFirstApiLevel",
            "-remake",
            ".locals 1\\n    const/16 v0, 0x23\\n    return v0",
            "-recursive",
        ])?;
        run_cli(cli2)?;
        let text2 = read_file_mmap_lf(&smali_file)?;
        assert!(text2.contains("const/16 v0, 0x23"));

        Ok(())
    }

    #[test]
    fn test_parallel_rayon_directory_patching() -> Result<()> {
        let tmp = TempDir::new()?;
        for i in 0..50 {
            let sub = tmp.path().join(format!("pkg_{}", i % 5));
            fs::create_dir_all(&sub)?;
            let f = sub.join(format!("Class{}.smali", i));
            write_text_lf(&f, SAMPLE_SMALI)?;
        }

        // Whole-directory parallel regex replacement (like port.sh Build->MODEL spoofing)
        let cli = Cli::try_parse_from([
            "smali-patcher",
            "-p",
            tmp.path().to_str().unwrap(),
            "-reg",
            r#"const-string ([vp]\d+), "ro\.product\.first_api_level""#,
            r#"const-string \1, "ro.product.first_api_level.patched""#,
            "-recursive",
        ])?;
        run_cli(cli)?;

        let all_files = collect_smali_files(tmp.path(), true, None);
        assert_eq!(all_files.len(), 50);
        for f in all_files {
            let content = read_file_mmap_lf(&f)?;
            assert!(content.contains(r#"const-string v0, "ro.product.first_api_level.patched""#));
        }

        Ok(())
    }
}
