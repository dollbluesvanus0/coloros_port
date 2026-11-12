//! Stage 4: Batch `build.prop` and `fstab` processor.
//!
//! Replaces slow line-by-line `sed`/`awk`/`grep` loops in `port.sh` and `functions.sh`
//! with an order-preserving Android `build.prop` parser/mutator and `fstab` cleaner.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use coloros_common::{read_text_lossy, write_text_lf, ToolError};
use regex::Regex;
use walkdir::WalkDir;

/// Properties always forced from the port ROM during `merge` (`add_prop_from_port`).
pub const FORCE_KEYS: &[&str] = &[
    "ro.build.version.oplusrom",
    "ro.build.version.oplusrom.display",
    "ro.build.version.oplusrom.confidential",
    "ro.build.version.realmeui",
];

/// Import directive added to `my_product/build.prop` by `prepare_base_prop`.
pub const BRUCE_IMPORT_LINE: &str = "import /mnt/vendor/my_product/etc/bruce/build.prop";

/// Initial header comment in `bruce/build.prop` created by `prepare_base_prop`.
pub const BRUCE_HEADER_COMMENT: &str = "# Properties added by the port";

#[derive(Debug, Parser)]
#[command(name = "prop-tool", about = "Batch build.prop and fstab processor")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Merge base and port build.prop files
    Merge {
        #[arg(long)]
        base: String,
        #[arg(long)]
        port: String,
        #[arg(long)]
        output: String,
        /// Optional path to write bruce build.prop (splits base + import into --output and port additions into --bruce-output)
        #[arg(long)]
        bruce_output: Option<String>,
        /// Ensure `import /mnt/vendor/my_product/etc/bruce/build.prop` is present in output
        #[arg(long)]
        import_bruce: bool,
    },
    /// Apply batch property modifications
    Batch {
        #[arg(long)]
        file: String,
        /// Optional output path (defaults to modifying --file in-place)
        #[arg(long)]
        output: Option<String>,
        /// Set or update `key=val` in place (or append if missing)
        #[arg(long)]
        set: Vec<String>,
        /// Update `key=val` only if `key` already exists in the file
        #[arg(long)]
        set_existing: Vec<String>,
        /// Delete lines matching key, `key=val`, or regex pattern
        #[arg(long)]
        remove: Vec<String>,
        /// Comment out lines matching `^key([=_.].*)?$` with `#` (`remove_prop_v2`)
        #[arg(long)]
        comment: Vec<String>,
        /// Replace literal substring `old=new` across the file
        #[arg(long)]
        replace: Vec<String>,
        /// Path to a batch operations file (or `-` for stdin)
        #[arg(long)]
        batch_file: Option<String>,
        /// Read batch operations from stdin
        #[arg(long)]
        stdin: bool,
        /// Optional base build.prop path; when set without `--force`, `--comment` skips keys present in base
        #[arg(long)]
        base: Option<String>,
        /// Force commenting even when `--base` contains the property
        #[arg(long)]
        force: bool,
        /// Optional bruce build.prop path for dual-file `add_prop_v2` / `remove_prop_v2` mode
        #[arg(long)]
        bruce_file: Option<String>,
    },
    /// Clean fstab files (disable AVB, remove erofs, remove data encryption)
    CleanFstab {
        #[arg(long)]
        fstab: String,
        /// Optional output path when `--fstab` is a single file
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        disable_avb: bool,
        #[arg(long)]
        remove_erofs: bool,
        #[arg(long)]
        remove_encryption: bool,
        #[arg(long)]
        remove_slotselect: bool,
    },
}

/// A single line in an Android `build.prop` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropLine {
    /// Empty or whitespace-only line.
    Blank(String),
    /// Comment line starting with `#` (possibly preceded by whitespace).
    Comment(String),
    /// Non-property directive line (e.g., `import /mnt/vendor/...`).
    Directive(String),
    /// Active `key=value` property assignment.
    Property {
        raw_prefix: String,
        key: String,
        value: String,
    },
}

impl PropLine {
    /// Parse a single raw line (without trailing `\r` or `\n`).
    pub fn parse(line: &str) -> Self {
        if line.trim().is_empty() {
            return PropLine::Blank(line.to_string());
        }
        let trimmed_start = line.trim_start();
        if trimmed_start.starts_with('#') {
            return PropLine::Comment(line.to_string());
        }
        if let Some((lhs, rhs)) = line.split_once('=') {
            let key_trimmed = lhs.trim();
            if !key_trimmed.is_empty() && !key_trimmed.contains(char::is_whitespace) {
                let prefix_len = lhs.len() - lhs.trim_start().len();
                let raw_prefix = lhs[..prefix_len].to_string();
                return PropLine::Property {
                    raw_prefix,
                    key: key_trimmed.to_string(),
                    value: rhs.to_string(),
                };
            }
        }
        PropLine::Directive(line.to_string())
    }

    /// Format this `PropLine` back into its single-line text representation.
    pub fn to_line_string(&self) -> String {
        match self {
            PropLine::Blank(s) | PropLine::Comment(s) | PropLine::Directive(s) => s.clone(),
            PropLine::Property {
                raw_prefix,
                key,
                value,
            } => format!("{raw_prefix}{key}={value}"),
        }
    }
}

/// Order-preserving representation of an Android `build.prop` file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PropFile {
    pub lines: Vec<PropLine>,
}

impl PropFile {
    /// Parse a `build.prop` string while preserving line order, comments, and blank lines.
    pub fn parse(content: &str) -> Self {
        let normalized = content.replace("\r\n", "\n");
        let lines = normalized
            .lines()
            .map(|l| l.trim_end_matches('\r'))
            .map(PropLine::parse)
            .collect();
        Self { lines }
    }

    /// Load a `PropFile` from disk.
    pub fn load(path: impl AsRef<Path>) -> coloros_common::Result<Self> {
        let text = read_text_lossy(path)?;
        Ok(Self::parse(&text))
    }

    /// Save the `PropFile` to disk with Unix LF (`\n`) line endings.
    pub fn save(&self, path: impl AsRef<Path>) -> coloros_common::Result<()> {
        write_text_lf(path, &self.to_string())
    }

    /// Return the value of the first active property matching `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.lines.iter().find_map(|line| match line {
            PropLine::Property { key: k, value, .. } if k == key => Some(value.as_str()),
            _ => None,
        })
    }

    /// Return `true` if an active property with exact `key` exists.
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Return `true` if any non-comment line matches `^(${escaped_prop}([=_\.].*)?$)`
    /// (used by `remove_prop_v2` to check whether the base ROM defines a property or prefix).
    pub fn has_key_or_prefix(&self, prop_prefix: &str) -> bool {
        self.lines
            .iter()
            .any(|line| matches_comment_prefix(line, prop_prefix))
    }

    /// Set `key=value`: updates existing active `key=...` line(s) in-place if present,
    /// otherwise appends `key=value` to the end of the file.
    /// Returns `true` if an existing property was updated in place, or `false` if appended.
    pub fn set(&mut self, key: &str, value: &str) -> bool {
        let mut updated = false;
        for line in &mut self.lines {
            if let PropLine::Property {
                key: k, value: v, ..
            } = line
            {
                if k == key {
                    *v = value.to_string();
                    updated = true;
                }
            }
        }
        if !updated {
            self.lines.push(PropLine::Property {
                raw_prefix: String::new(),
                key: key.to_string(),
                value: value.to_string(),
            });
        }
        updated
    }

    /// Update `key=value` in-place only if `key` already exists in the file.
    /// Returns the number of lines updated.
    pub fn set_existing(&mut self, key: &str, value: &str) -> usize {
        let mut count = 0;
        for line in &mut self.lines {
            if let PropLine::Property {
                key: k, value: v, ..
            } = line
            {
                if k == key {
                    *v = value.to_string();
                    count += 1;
                }
            }
        }
        count
    }

    /// Remove lines matching `pattern`.
    ///
    /// Supports:
    /// - Exact key name (`"ro.build.version.release"`)
    /// - Key with trailing `=` (`"ro.build.version.release="`)
    /// - Exact `key=value` pair (`"ro.zygote=zygote64"`)
    /// - Regex pattern on key or line (`"ro.oplus.audio.*"`, `"^persist\\.sys\\.prophook\\..*"`)
    ///
    /// Returns the number of removed lines.
    pub fn remove(&mut self, pattern: &str) -> coloros_common::Result<usize> {
        let before = self.lines.len();
        let has_regex_meta = pattern.chars().any(|c| {
            matches!(
                c,
                '*' | '+' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
            )
        });

        if has_regex_meta {
            let re = Regex::new(pattern).map_err(|e| {
                ToolError::InvalidArgument(format!("Invalid remove regex '{pattern}': {e}"))
            })?;
            self.lines.retain(|line| match line {
                PropLine::Property { key, .. } => {
                    let raw = line.to_line_string();
                    !(re.is_match(key) || re.is_match(&raw))
                }
                PropLine::Directive(raw) => !re.is_match(raw),
                _ => true,
            });
        } else if let Some((pat_key, pat_val)) = pattern.split_once('=') {
            if pat_val.is_empty() {
                // e.g. "ro.build.version.release=" -> match key
                self.lines.retain(|line| {
                    !matches!(line, PropLine::Property { key, .. } if key == pat_key)
                });
            } else {
                // e.g. "ro.zygote=zygote64" -> match exact key and value
                self.lines.retain(|line| {
                    !matches!(
                        line,
                        PropLine::Property { key, value, .. } if key == pat_key && value == pat_val
                    )
                });
            }
        } else {
            self.lines.retain(|line| {
                !matches!(line, PropLine::Property { key, .. } if key == pattern)
            });
        }

        Ok(before - self.lines.len())
    }

    /// Comment out lines matching `^(${escaped_prop}([=_\.].*)?$)` by prepending `#`,
    /// matching `remove_prop_v2` in `functions.sh`.
    ///
    /// Returns the number of lines commented out.
    pub fn comment(&mut self, prop_prefix: &str) -> usize {
        let mut count = 0;
        for line in &mut self.lines {
            if matches_comment_prefix(line, prop_prefix) {
                let raw = line.to_line_string();
                *line = PropLine::Comment(format!("#{raw}"));
                count += 1;
            }
        }
        count
    }

    /// Replace all occurrences of literal `from` with `to` across non-blank lines.
    /// Re-parses modified lines to keep `PropLine` variants consistent.
    pub fn replace_all(&mut self, from: &str, to: &str) -> usize {
        if from.is_empty() {
            return 0;
        }
        let mut count = 0;
        for line in &mut self.lines {
            let raw = line.to_line_string();
            if raw.contains(from) {
                let replaced = raw.replace(from, to);
                *line = PropLine::parse(&replaced);
                count += 1;
            }
        }
        count
    }

    /// Ensure `import /mnt/vendor/my_product/etc/bruce/build.prop` is present at the end.
    pub fn ensure_bruce_import(&mut self) {
        let already_present = self.lines.iter().any(|line| {
            line.to_line_string()
                .starts_with(BRUCE_IMPORT_LINE)
        });
        if !already_present {
            self.lines.push(PropLine::Blank(String::new()));
            self.lines
                .push(PropLine::Directive(BRUCE_IMPORT_LINE.to_string()));
        }
    }
}

impl fmt::Display for PropFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, line) in self.lines.iter().enumerate() {
            if idx > 0 {
                f.write_str("\n")?;
            }
            f.write_str(&line.to_line_string())?;
        }
        if !self.lines.is_empty() {
            f.write_str("\n")?;
        }
        Ok(())
    }
}

/// Check if a non-comment `PropLine` matches `^(${escaped_prop}([=_\.].*)?$)`.
fn matches_comment_prefix(line: &PropLine, prop_prefix: &str) -> bool {
    if prop_prefix.is_empty() {
        return false;
    }
    match line {
        PropLine::Blank(_) | PropLine::Comment(_) => false,
        PropLine::Directive(_) | PropLine::Property { .. } => {
            let raw = line.to_line_string();
            if let Some(rest) = raw.strip_prefix(prop_prefix) {
                rest.is_empty() || rest.starts_with(['=', '_', '.'])
            } else {
                false
            }
        }
    }
}

/// Compute the properties from `port` that should be added on top of `base`
/// following `add_prop_from_port` in `functions.sh`:
/// 1. Ordinary properties in `port` (excluding `FORCE_KEYS`) whose key does not exist in `base`.
/// 2. `FORCE_KEYS` (`ro.build.version.oplusrom`, `ro.build.version.oplusrom.display`,
///    `ro.build.version.oplusrom.confidential`, `ro.build.version.realmeui`) from `port`
///    whenever `port` has a non-empty value for them.
pub fn compute_port_additions(base: &PropFile, port: &PropFile) -> Vec<(String, String)> {
    let base_keys: HashSet<&str> = base
        .lines
        .iter()
        .filter_map(|line| match line {
            PropLine::Property { key, .. } => Some(key.as_str()),
            _ => None,
        })
        .collect();

    let mut additions: Vec<(String, String)> = Vec::new();

    for line in &port.lines {
        if let PropLine::Property { key, value, .. } = line {
            if FORCE_KEYS.contains(&key.as_str()) {
                continue;
            }
            if !base_keys.contains(key.as_str()) {
                additions.push((key.clone(), value.clone()));
            }
        }
    }

    for &force_key in FORCE_KEYS {
        if let Some(raw_val) = port.get(force_key) {
            let val = raw_val.trim_matches(['\r', '\n']);
            if !val.is_empty() {
                additions.retain(|(k, _)| k != force_key);
                additions.push((force_key.to_string(), val.to_string()));
            }
        }
    }

    additions
}

/// Merge `base` and `port` into a single `PropFile`:
/// - Preserves all comments, blank lines, and line order from `base`.
/// - Optionally ensures `import /mnt/vendor/my_product/etc/bruce/build.prop` is present.
/// - Copies non-existing keys from `port` (in `port` order).
/// - Forces `FORCE_KEYS` from `port` (updating in place if present in `base`, or appending).
pub fn merge_props(base: &PropFile, port: &PropFile, import_bruce: bool) -> PropFile {
    let mut merged = base.clone();
    if import_bruce {
        merged.ensure_bruce_import();
    }

    let additions = compute_port_additions(base, port);
    for (key, value) in additions {
        if FORCE_KEYS.contains(&key.as_str()) && merged.contains_key(&key) {
            merged.set(&key, &value);
        } else {
            merged.lines.push(PropLine::Property {
                raw_prefix: String::new(),
                key,
                value,
            });
        }
    }

    merged
}

/// Execute the two-file `prepare_base_prop` + `add_prop_from_port` workflow from `functions.sh`:
/// - Returns `(target_base_prop, bruce_prop)`.
/// - `target_base_prop` is `base` with `import /mnt/vendor/my_product/etc/bruce/build.prop` appended.
/// - `bruce_prop` starts with `# Properties added by the port` followed by all port-only and forced properties.
pub fn merge_props_with_bruce(base: &PropFile, port: &PropFile) -> (PropFile, PropFile) {
    let mut target_base = base.clone();
    target_base.ensure_bruce_import();

    let additions = compute_port_additions(base, port);
    let mut bruce_lines = vec![PropLine::Comment(BRUCE_HEADER_COMMENT.to_string())];
    for (key, value) in additions {
        bruce_lines.push(PropLine::Property {
            raw_prefix: String::new(),
            key,
            value,
        });
    }

    (target_base, PropFile { lines: bruce_lines })
}

/// A batch property operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchOp {
    /// Set `key=value` (update in-place or append).
    Set { key: String, value: String },
    /// Update `key=value` only if `key` already exists.
    SetExisting { key: String, value: String },
    /// Remove lines matching key, `key=val`, or regex.
    Remove { pattern: String },
    /// Comment out lines matching `^key([=_.].*)?$` with `#`.
    Comment { key: String, force: bool },
    /// Replace literal substring `from` with `to`.
    Replace { from: String, to: String },
}

/// Parse batch operations from a multi-line script/stdin string.
///
/// Supported line formats:
/// - `# comment` or blank line (ignored)
/// - `set key=val` or `add key=val`
/// - `set-existing key=val`
/// - `remove <pattern>` / `del <pattern>` / `delete <pattern>` / `rm <pattern>`
/// - `comment <key> [force]` / `comment-force <key>`
/// - `replace <old>=<new>`
/// - `<key>=<val>` (shorthand for `set <key>=<val>`)
pub fn parse_batch_script(script: &str, default_force: bool) -> coloros_common::Result<Vec<BatchOp>> {
    let mut ops = Vec::new();
    for (idx, raw_line) in script.lines().enumerate() {
        let line_num = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line
            .strip_prefix("set-existing ")
            .or_else(|| line.strip_prefix("SET-EXISTING "))
        {
            let (k, v) = parse_key_val(rest.trim(), line_num)?;
            ops.push(BatchOp::SetExisting { key: k, value: v });
        } else if let Some(rest) = line
            .strip_prefix("set ")
            .or_else(|| line.strip_prefix("SET "))
            .or_else(|| line.strip_prefix("add "))
            .or_else(|| line.strip_prefix("ADD "))
        {
            let (k, v) = parse_key_val(rest.trim(), line_num)?;
            ops.push(BatchOp::Set { key: k, value: v });
        } else if let Some(rest) = line
            .strip_prefix("remove ")
            .or_else(|| line.strip_prefix("REMOVE "))
            .or_else(|| line.strip_prefix("delete "))
            .or_else(|| line.strip_prefix("DELETE "))
            .or_else(|| line.strip_prefix("del "))
            .or_else(|| line.strip_prefix("DEL "))
            .or_else(|| line.strip_prefix("rm "))
            .or_else(|| line.strip_prefix("RM "))
        {
            let pat = rest.trim();
            if pat.is_empty() {
                return Err(ToolError::Parse {
                    file: PathBuf::from("<batch>"),
                    line: line_num,
                    message: "Empty pattern in remove command".to_string(),
                });
            }
            ops.push(BatchOp::Remove {
                pattern: pat.to_string(),
            });
        } else if let Some(rest) = line
            .strip_prefix("comment-force ")
            .or_else(|| line.strip_prefix("COMMENT-FORCE "))
        {
            let key = rest.trim();
            if key.is_empty() {
                return Err(ToolError::Parse {
                    file: PathBuf::from("<batch>"),
                    line: line_num,
                    message: "Empty key in comment-force command".to_string(),
                });
            }
            ops.push(BatchOp::Comment {
                key: key.to_string(),
                force: true,
            });
        } else if let Some(rest) = line
            .strip_prefix("comment ")
            .or_else(|| line.strip_prefix("COMMENT "))
        {
            let rest = rest.trim();
            let (key, force) = if let Some(stripped) = rest.strip_suffix(" force") {
                (stripped.trim(), true)
            } else {
                (rest, default_force)
            };
            if key.is_empty() {
                return Err(ToolError::Parse {
                    file: PathBuf::from("<batch>"),
                    line: line_num,
                    message: "Empty key in comment command".to_string(),
                });
            }
            ops.push(BatchOp::Comment {
                key: key.to_string(),
                force,
            });
        } else if let Some(rest) = line
            .strip_prefix("replace ")
            .or_else(|| line.strip_prefix("REPLACE "))
        {
            let (from, to) = parse_key_val(rest.trim(), line_num)?;
            ops.push(BatchOp::Replace { from, to });
        } else if line.contains('=') {
            let (k, v) = parse_key_val(line, line_num)?;
            ops.push(BatchOp::Set { key: k, value: v });
        } else {
            return Err(ToolError::Parse {
                file: PathBuf::from("<batch>"),
                line: line_num,
                message: format!("Unrecognized batch operation: '{line}'"),
            });
        }
    }
    Ok(ops)
}

fn parse_key_val(arg: &str, line_num: usize) -> coloros_common::Result<(String, String)> {
    let (k, v) = arg.split_once('=').ok_or_else(|| ToolError::Parse {
        file: PathBuf::from("<batch>"),
        line: line_num,
        message: format!("Expected 'key=value', got '{arg}'"),
    })?;
    let key = k.trim();
    if key.is_empty() {
        return Err(ToolError::Parse {
            file: PathBuf::from("<batch>"),
            line: line_num,
            message: format!("Empty key in '{arg}'"),
        });
    }
    Ok((key.to_string(), v.to_string()))
}

/// Apply a sequence of `BatchOp`s to a single `PropFile` (optionally consulting `base` for non-forced `Comment`).
pub fn apply_batch(
    prop: &mut PropFile,
    ops: &[BatchOp],
    base: Option<&PropFile>,
) -> coloros_common::Result<()> {
    for op in ops {
        match op {
            BatchOp::Set { key, value } => {
                prop.set(key, value);
            }
            BatchOp::SetExisting { key, value } => {
                prop.set_existing(key, value);
            }
            BatchOp::Remove { pattern } => {
                prop.remove(pattern)?;
            }
            BatchOp::Comment { key, force } => {
                let should_comment = if *force {
                    true
                } else if let Some(base_prop) = base {
                    !base_prop.has_key_or_prefix(key)
                } else {
                    true
                };
                if should_comment {
                    prop.comment(key);
                }
            }
            BatchOp::Replace { from, to } => {
                prop.replace_all(from, to);
            }
        }
    }
    Ok(())
}

/// Apply a sequence of `BatchOp`s across `(portrom_prop, bruce_prop)` using exact
/// `add_prop_v2` and `remove_prop_v2` dual-file semantics from `functions.sh`:
/// - `Set`: if neither file has `key`, append `key=value` to `bruce_prop`;
///   otherwise update `key=value` in whichever file(s) already define `key`.
/// - `Comment`: if `force` is true, comment matching lines in both `bruce_prop` and `portrom_prop`;
///   if `force` is false and `base` does not have `key`, comment matching lines in `bruce_prop`
///   (and if `base` is `None`, comment in both).
pub fn apply_batch_v2(
    portrom_prop: &mut PropFile,
    bruce_prop: &mut PropFile,
    ops: &[BatchOp],
    base: Option<&PropFile>,
) -> coloros_common::Result<()> {
    for op in ops {
        match op {
            BatchOp::Set { key, value } => {
                let in_bruce = bruce_prop.contains_key(key);
                let in_port = portrom_prop.contains_key(key);
                if !in_bruce && !in_port {
                    bruce_prop.set(key, value);
                } else {
                    if in_bruce {
                        bruce_prop.set(key, value);
                    }
                    if in_port {
                        portrom_prop.set(key, value);
                    }
                }
            }
            BatchOp::SetExisting { key, value } => {
                portrom_prop.set_existing(key, value);
                bruce_prop.set_existing(key, value);
            }
            BatchOp::Remove { pattern } => {
                portrom_prop.remove(pattern)?;
                bruce_prop.remove(pattern)?;
            }
            BatchOp::Comment { key, force } => {
                if *force {
                    bruce_prop.comment(key);
                    portrom_prop.comment(key);
                } else if let Some(base_prop) = base {
                    if !base_prop.has_key_or_prefix(key) {
                        bruce_prop.comment(key);
                    }
                } else {
                    bruce_prop.comment(key);
                    portrom_prop.comment(key);
                }
            }
            BatchOp::Replace { from, to } => {
                portrom_prop.replace_all(from, to);
                bruce_prop.replace_all(from, to);
            }
        }
    }
    Ok(())
}

/// Options for cleaning `fstab` files.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FstabCleanOptions {
    pub disable_avb: bool,
    pub remove_erofs: bool,
    pub remove_encryption: bool,
    pub remove_slotselect: bool,
}

/// Encryption flags stripped in order by `port.sh` lines 2962–2969 before replacing remaining `fileencryption` with `encryptable`.
const ENCRYPTION_TOKENS_TO_STRIP: &[&str] = &[
    ",fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0",
    ",fileencryption=aes-256-xts:aes-256-cts:v2+emmc_optimized+wrappedkey_v0",
    ",fileencryption=aes-256-xts:aes-256-cts:v2",
    ",metadata_encryption=aes-256-xts:wrappedkey_v0",
    ",fileencryption=aes-256-xts:wrappedkey_v0",
    ",metadata_encryption=aes-256-xts",
    ",fileencryption=aes-256-xts",
    ",fileencryption=ice",
];

/// Clean an `fstab` text content according to `options`:
/// - `disable_avb`: matches `disable_avb_verify()` in `functions.sh`:
///   - `s/,avb.*system//g`
///   - `s/,avb,/,/g`
///   - `s/,avb=.*a,/,/g`
///   - `s/,avb_keys.*key//g`
/// - `remove_erofs`: matches `sed -i "/erofs/d"` in `functions.sh`
/// - `remove_encryption`: matches `port.sh` lines 2962–2970
/// - `remove_slotselect`: matches `sed -i "/,slotselect/d"` in `functions.sh`
pub fn clean_fstab_content(content: &str, options: FstabCleanOptions) -> String {
    let normalized = content.replace("\r\n", "\n");
    let re_avb_system = Regex::new(r",avb.*system").expect("valid regex");
    let re_avb_a = Regex::new(r",avb=.*a,").expect("valid regex");
    let re_avb_keys = Regex::new(r",avb_keys.*key").expect("valid regex");

    let mut out_lines: Vec<String> = Vec::new();

    for raw_line in normalized.lines() {
        let mut line = raw_line.trim_end_matches('\r').to_string();

        if options.remove_erofs && line.contains("erofs") {
            continue;
        }
        if options.remove_slotselect && line.contains(",slotselect") {
            continue;
        }

        if options.disable_avb {
            line = re_avb_system.replace_all(&line, "").into_owned();
            line = line.replace(",avb,", ",");
            line = re_avb_a.replace_all(&line, ",").into_owned();
            line = re_avb_keys.replace_all(&line, "").into_owned();
        }

        if options.remove_encryption {
            for token in ENCRYPTION_TOKENS_TO_STRIP {
                line = line.replace(token, "");
            }
            line = line.replace("fileencryption", "encryptable");
        }

        out_lines.push(line);
    }

    if out_lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", out_lines.join("\n"))
    }
}

/// Clean an `fstab` file or directory of `fstab*` files on disk.
/// Returns the list of modified/processed file paths.
pub fn clean_fstab_path(
    fstab_path: impl AsRef<Path>,
    output_path: Option<&Path>,
    options: FstabCleanOptions,
) -> coloros_common::Result<Vec<PathBuf>> {
    let fstab_path = fstab_path.as_ref();
    if fstab_path.is_file() {
        let content = read_text_lossy(fstab_path)?;
        let cleaned = clean_fstab_content(&content, options);
        let dest = output_path.unwrap_or(fstab_path);
        write_text_lf(dest, &cleaned)?;
        return Ok(vec![dest.to_path_buf()]);
    }

    if fstab_path.is_dir() {
        let mut files: Vec<PathBuf> = WalkDir::new(fstab_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|name| name.starts_with("fstab"))
                    .unwrap_or(false)
            })
            .map(|e| e.into_path())
            .collect();
        files.sort();

        for file in &files {
            let content = read_text_lossy(file)?;
            let cleaned = clean_fstab_content(&content, options);
            write_text_lf(file, &cleaned)?;
        }
        return Ok(files);
    }

    Err(ToolError::TargetNotFound(format!(
        "fstab path not found: {}",
        fstab_path.display()
    )))
}

pub fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::Merge {
            base,
            port,
            output,
            bruce_output,
            import_bruce,
        }) => {
            let base_prop = PropFile::load(&base)
                .with_context(|| format!("Failed to read base prop: {base}"))?;
            let port_prop = PropFile::load(&port)
                .with_context(|| format!("Failed to read port prop: {port}"))?;

            if let Some(bruce_path) = bruce_output {
                let (target_base, bruce_prop) = merge_props_with_bruce(&base_prop, &port_prop);
                target_base
                    .save(&output)
                    .with_context(|| format!("Failed to write target base prop: {output}"))?;
                bruce_prop
                    .save(&bruce_path)
                    .with_context(|| format!("Failed to write bruce prop: {bruce_path}"))?;
            } else {
                let merged = merge_props(&base_prop, &port_prop, import_bruce);
                merged
                    .save(&output)
                    .with_context(|| format!("Failed to write merged prop: {output}"))?;
            }
            Ok(())
        }
        Some(Commands::Batch {
            file,
            output,
            set,
            set_existing,
            remove,
            comment,
            replace,
            batch_file,
            stdin,
            base,
            force,
            bruce_file,
        }) => {
            let mut ops: Vec<BatchOp> = Vec::new();

            for pattern in remove {
                ops.push(BatchOp::Remove { pattern });
            }
            for key in comment {
                ops.push(BatchOp::Comment { key, force });
            }
            for item in set_existing {
                let (key, value) = parse_key_val(&item, 0)?;
                ops.push(BatchOp::SetExisting { key, value });
            }
            for item in set {
                let (key, value) = parse_key_val(&item, 0)?;
                ops.push(BatchOp::Set { key, value });
            }
            for item in replace {
                let (from, to) = parse_key_val(&item, 0)?;
                ops.push(BatchOp::Replace { from, to });
            }

            if let Some(bf) = batch_file {
                let script = if bf == "-" {
                    let mut buf = String::new();
                    io::stdin()
                        .read_to_string(&mut buf)
                        .context("Failed to read batch script from stdin")?;
                    buf
                } else {
                    read_text_lossy(&bf)
                        .with_context(|| format!("Failed to read batch file: {bf}"))?
                };
                ops.extend(parse_batch_script(&script, force)?);
            } else if stdin {
                let mut buf = String::new();
                io::stdin()
                    .read_to_string(&mut buf)
                    .context("Failed to read batch script from stdin")?;
                ops.extend(parse_batch_script(&script_or_empty(&buf), force)?);
            }

            let base_prop = match base {
                Some(ref b) => Some(
                    PropFile::load(b).with_context(|| format!("Failed to read base prop: {b}"))?,
                ),
                None => None,
            };

            let mut prop = PropFile::load(&file)
                .with_context(|| format!("Failed to read prop file: {file}"))?;

            if let Some(bruce_path) = bruce_file {
                let mut bruce_prop = if Path::new(&bruce_path).exists() {
                    PropFile::load(&bruce_path)
                        .with_context(|| format!("Failed to read bruce prop: {bruce_path}"))?
                } else {
                    PropFile::default()
                };
                apply_batch_v2(&mut prop, &mut bruce_prop, &ops, base_prop.as_ref())?;
                let out_path = output.as_deref().unwrap_or(&file);
                prop.save(out_path)
                    .with_context(|| format!("Failed to write prop file: {out_path}"))?;
                bruce_prop
                    .save(&bruce_path)
                    .with_context(|| format!("Failed to write bruce prop file: {bruce_path}"))?;
            } else {
                apply_batch(&mut prop, &ops, base_prop.as_ref())?;
                let out_path = output.as_deref().unwrap_or(&file);
                prop.save(out_path)
                    .with_context(|| format!("Failed to write prop file: {out_path}"))?;
            }

            Ok(())
        }
        Some(Commands::CleanFstab {
            fstab,
            output,
            disable_avb,
            remove_erofs,
            remove_encryption,
            remove_slotselect,
        }) => {
            let options = FstabCleanOptions {
                disable_avb,
                remove_erofs,
                remove_encryption,
                remove_slotselect,
            };
            clean_fstab_path(&fstab, output.as_deref().map(Path::new), options)
                .with_context(|| format!("Failed to clean fstab: {fstab}"))?;
            Ok(())
        }
        None => Ok(()),
    }
}

fn script_or_empty(s: &str) -> &str {
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_preserves_order_comments_and_blank_lines() {
        let raw = "\
# begin build properties
# autogenerated by buildinfo.sh

ro.build.id=UKQ1.230924.001
ro.build.display.id=KB2000_14.0.0.600(CN01)

# Some comment with = sign inside
ro.product.model=KB2000
import /mnt/vendor/my_product/etc/bruce/build.prop
";
        let prop = PropFile::parse(raw);
        assert_eq!(prop.to_string(), raw);
        assert_eq!(prop.get("ro.build.id"), Some("UKQ1.230924.001"));
        assert_eq!(prop.get("ro.product.model"), Some("KB2000"));
        assert_eq!(prop.lines.len(), 9);
    }

    #[test]
    fn test_merge_single_file_and_forced_keys() {
        let base_raw = "\
# Base properties
ro.product.device=OnePlus8T
ro.product.model=KB2000
ro.build.version.oplusrom=V14.0.0
ro.build.version.oplusrom.display=14.0.0

# End of base
";
        let port_raw = "\
# Port properties
ro.product.device=OnePlus12
ro.product.model=PJD110
ro.build.version.oplusrom=V16.0.0
ro.build.version.oplusrom.display=16.0.0
ro.build.version.oplusrom.confidential=16.0.0
ro.build.version.realmeui=7.0
ro.oplus.only.feature=true
persist.oplus.new.prop=42
";
        let base = PropFile::parse(base_raw);
        let port = PropFile::parse(port_raw);

        let merged = merge_props(&base, &port, false);
        // Base keys are preserved with base values
        assert_eq!(merged.get("ro.product.device"), Some("OnePlus8T"));
        assert_eq!(merged.get("ro.product.model"), Some("KB2000"));
        // Force keys are overridden with port values
        assert_eq!(merged.get("ro.build.version.oplusrom"), Some("V16.0.0"));
        assert_eq!(
            merged.get("ro.build.version.oplusrom.display"),
            Some("16.0.0")
        );
        assert_eq!(
            merged.get("ro.build.version.oplusrom.confidential"),
            Some("16.0.0")
        );
        assert_eq!(merged.get("ro.build.version.realmeui"), Some("7.0"));
        // Port-only keys are added
        assert_eq!(merged.get("ro.oplus.only.feature"), Some("true"));
        assert_eq!(merged.get("persist.oplus.new.prop"), Some("42"));
        // Comments and blank lines from base are preserved in order
        assert_eq!(
            merged.lines[0],
            PropLine::Comment("# Base properties".to_string())
        );
        assert_eq!(merged.lines[5], PropLine::Blank(String::new()));
        assert_eq!(
            merged.lines[6],
            PropLine::Comment("# End of base".to_string())
        );
    }

    #[test]
    fn test_merge_with_bruce_matches_prepare_base_and_add_prop_from_port() {
        let base_raw = "\
# Base my_product
ro.oplus.image.my_product.type=20809
ro.build.version.oplusrom=V14.0.0
";
        let port_raw = "\
ro.oplus.image.my_product.type=22825
ro.oplus.game.camera.support=1
ro.build.version.oplusrom=V16.0.1
ro.build.version.oplusrom.confidential=16.0.1
";
        let base = PropFile::parse(base_raw);
        let port = PropFile::parse(port_raw);

        let (target_base, bruce) = merge_props_with_bruce(&base, &port);
        let target_base_str = target_base.to_string();
        assert!(target_base_str.contains("ro.oplus.image.my_product.type=20809"));
        assert!(target_base_str.ends_with(
            "\n\nimport /mnt/vendor/my_product/etc/bruce/build.prop\n"
        ));

        // Calling ensure_bruce_import a second time is idempotent
        let mut target_base_again = target_base.clone();
        target_base_again.ensure_bruce_import();
        assert_eq!(target_base_again, target_base);

        let bruce_expected = "\
# Properties added by the port
ro.oplus.game.camera.support=1
ro.build.version.oplusrom=V16.0.1
ro.build.version.oplusrom.confidential=16.0.1
";
        assert_eq!(bruce.to_string(), bruce_expected);
    }

    #[test]
    fn test_batch_set_remove_and_comment() {
        let raw = "\
# Sample prop
ro.build.display.id=OLD_ID
ro.build.version.release=16
ro.zygote=zygote64
ro.oplus.audio.effect.type=dolby
ro.oplus.audio.custom=1
ro.panel.pad=true
ro.panel.pad_ext=1
ro.panel.pad.sub=2
ro.panel.padding=keep_me
";
        let mut prop = PropFile::parse(raw);
        let ops = vec![
            BatchOp::Set {
                key: "ro.build.display.id".to_string(),
                value: "NEW_ID".to_string(),
            },
            BatchOp::Set {
                key: "ro.new.added.key".to_string(),
                value: "123".to_string(),
            },
            BatchOp::Remove {
                pattern: "ro.build.version.release".to_string(),
            },
            BatchOp::Remove {
                pattern: "ro.zygote=zygote64".to_string(),
            },
            BatchOp::Remove {
                pattern: "ro.oplus.audio.*".to_string(),
            },
            BatchOp::Comment {
                key: "ro.panel.pad".to_string(),
                force: true,
            },
        ];

        apply_batch(&mut prop, &ops, None).unwrap();

        assert_eq!(prop.get("ro.build.display.id"), Some("NEW_ID"));
        assert_eq!(prop.get("ro.new.added.key"), Some("123"));
        assert_eq!(prop.get("ro.build.version.release"), None);
        assert_eq!(prop.get("ro.zygote"), None);
        assert_eq!(prop.get("ro.oplus.audio.effect.type"), None);
        assert_eq!(prop.get("ro.oplus.audio.custom"), None);
        assert_eq!(prop.get("ro.panel.pad"), None);
        assert_eq!(prop.get("ro.panel.pad_ext"), None);
        assert_eq!(prop.get("ro.panel.pad.sub"), None);
        // ro.panel.padding must NOT be commented out by `ro.panel.pad`
        assert_eq!(prop.get("ro.panel.padding"), Some("keep_me"));

        let serialized = prop.to_string();
        assert!(serialized.contains("#ro.panel.pad=true\n"));
        assert!(serialized.contains("#ro.panel.pad_ext=1\n"));
        assert!(serialized.contains("#ro.panel.pad.sub=2\n"));
    }

    #[test]
    fn test_batch_v2_and_base_conditional_comment() {
        let base = PropFile::parse("ro.oplus.resolution=1080p\n");
        let mut portrom_prop = PropFile::parse("ro.existing.in.port=old\nro.panel.pad=true\n");
        let mut bruce_prop = PropFile::parse(
            "# Properties added by the port\nro.oplus.resolution=2k\nro.oplus.tablet=1\nro.panel.pad_mode=1\n",
        );

        let ops = vec![
            // Updates in portrom_prop in-place, does not duplicate into bruce_prop
            BatchOp::Set {
                key: "ro.existing.in.port".to_string(),
                value: "new".to_string(),
            },
            // Not in either -> appended to bruce_prop
            BatchOp::Set {
                key: "ro.brand.new".to_string(),
                value: "yes".to_string(),
            },
            // Exists in base -> non-force comment should keep it!
            BatchOp::Comment {
                key: "ro.oplus.resolution".to_string(),
                force: false,
            },
            // Does not exist in base -> non-force comment comments it in bruce_prop
            BatchOp::Comment {
                key: "ro.oplus.tablet".to_string(),
                force: false,
            },
            // Force comment -> comments in both portrom_prop and bruce_prop
            BatchOp::Comment {
                key: "ro.panel.pad".to_string(),
                force: true,
            },
        ];

        apply_batch_v2(&mut portrom_prop, &mut bruce_prop, &ops, Some(&base)).unwrap();

        assert_eq!(portrom_prop.get("ro.existing.in.port"), Some("new"));
        assert_eq!(bruce_prop.get("ro.existing.in.port"), None);
        assert_eq!(bruce_prop.get("ro.brand.new"), Some("yes"));
        // Kept because base has ro.oplus.resolution
        assert_eq!(bruce_prop.get("ro.oplus.resolution"), Some("2k"));
        // Commented because base does not have ro.oplus.tablet
        assert_eq!(bruce_prop.get("ro.oplus.tablet"), None);
        assert!(bruce_prop.to_string().contains("#ro.oplus.tablet=1"));
        // Force commented in both files
        assert!(portrom_prop.to_string().contains("#ro.panel.pad=true"));
        assert!(bruce_prop.to_string().contains("#ro.panel.pad_mode=1"));
    }

    #[test]
    fn test_parse_batch_script() {
        let script = "\
# Batch script test
set ro.debuggable=1
ro.secure=0
set-existing ro.build.user=Bruce
remove ro.build.version.release
comment ro.oplus.tablet
comment ro.panel.pad force
comment-force ro.build.characteristics
replace PJD110=KB2000
";
        let ops = parse_batch_script(script, false).unwrap();
        assert_eq!(
            ops,
            vec![
                BatchOp::Set {
                    key: "ro.debuggable".to_string(),
                    value: "1".to_string()
                },
                BatchOp::Set {
                    key: "ro.secure".to_string(),
                    value: "0".to_string()
                },
                BatchOp::SetExisting {
                    key: "ro.build.user".to_string(),
                    value: "Bruce".to_string()
                },
                BatchOp::Remove {
                    pattern: "ro.build.version.release".to_string()
                },
                BatchOp::Comment {
                    key: "ro.oplus.tablet".to_string(),
                    force: false
                },
                BatchOp::Comment {
                    key: "ro.panel.pad".to_string(),
                    force: true
                },
                BatchOp::Comment {
                    key: "ro.build.characteristics".to_string(),
                    force: true
                },
                BatchOp::Replace {
                    from: "PJD110".to_string(),
                    to: "KB2000".to_string()
                },
            ]
        );
    }

    #[test]
    fn test_clean_fstab_avb_erofs_encryption_slotselect() {
        let fstab = "\
# Android fstab file.
system /system erofs ro wait,slotselect,avb=vbmeta_system,logical,first_stage_mount,avb_keys=/avb/q-gsi.avbpubkey:/avb/r-gsi.avbpubkey:/avb/s-gsi.avbpubkey
system /system ext4 ro,barrier=1,discard wait,slotselect,avb=vbmeta_system,logical,first_stage_mount,avb_keys=/avb/q-gsi.avbpubkey:/avb/r-gsi.avbpubkey:/avb/s-gsi.avbpubkey
vendor /vendor ext4 ro,barrier=1,discard wait,avb,logical,first_stage_mount
odm /odm ext4 ro,barrier=1,discard wait,avb=vbmeta_a,logical,first_stage_mount
/dev/block/bootdevice/by-name/userdata /data f2fs noatime,nosuid,nodev,discard wait,check,fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0,metadata_encryption=aes-256-xts:wrappedkey_v0,keydirectory=/metadata/vold/metadata_encryption,quota
/dev/block/bootdevice/by-name/userdata2 /data2 ext4 noatime wait,fileencryption=ice,fileencryption=unknown_mode
";

        let cleaned = clean_fstab_content(
            fstab,
            FstabCleanOptions {
                disable_avb: true,
                remove_erofs: true,
                remove_encryption: true,
                remove_slotselect: false,
            },
        );

        let lines: Vec<&str> = cleaned.lines().collect();
        // erofs line removed
        assert!(!cleaned.contains("erofs"));
        // system ext4 has `,avb.*system` and `,avb_keys.*key` stripped
        assert_eq!(
            lines[1],
            "system /system ext4 ro,barrier=1,discard wait,slotselect,logical,first_stage_mount"
        );
        // vendor has `,avb,` -> `,`
        assert_eq!(
            lines[2],
            "vendor /vendor ext4 ro,barrier=1,discard wait,logical,first_stage_mount"
        );
        // odm has `,avb=vbmeta_a,` -> `,`
        assert_eq!(
            lines[3],
            "odm /odm ext4 ro,barrier=1,discard wait,logical,first_stage_mount"
        );
        // userdata has encryption tokens stripped
        assert_eq!(
            lines[4],
            "/dev/block/bootdevice/by-name/userdata /data f2fs noatime,nosuid,nodev,discard wait,check,keydirectory=/metadata/vold/metadata_encryption,quota"
        );
        // userdata2 has `,fileencryption=ice` stripped and remaining `fileencryption` replaced with `encryptable`
        assert_eq!(
            lines[5],
            "/dev/block/bootdevice/by-name/userdata2 /data2 ext4 noatime wait,encryptable=unknown_mode"
        );

        // Now test remove_slotselect
        let cleaned_aonly = clean_fstab_content(
            &cleaned,
            FstabCleanOptions {
                disable_avb: false,
                remove_erofs: false,
                remove_encryption: false,
                remove_slotselect: true,
            },
        );
        assert!(!cleaned_aonly.contains(",slotselect"));
    }

    #[test]
    fn test_cli_end_to_end() {
        let dir = TempDir::new().unwrap();
        let base_path = dir.path().join("base.prop");
        let port_path = dir.path().join("port.prop");
        let merged_path = dir.path().join("merged.prop");
        let fstab_path = dir.path().join("fstab.qcom");

        write_text_lf(
            &base_path,
            "# Base\nro.product.model=KB2000\nro.build.version.oplusrom=V14.0.0\n",
        )
        .unwrap();
        write_text_lf(
            &port_path,
            "ro.product.model=PJD110\nro.build.version.oplusrom=V16.0.0\nro.port.extra=1\nro.panel.pad=true\n",
        )
        .unwrap();

        // 1. CLI Merge
        run_cli(Cli {
            command: Some(Commands::Merge {
                base: base_path.to_string_lossy().into_owned(),
                port: port_path.to_string_lossy().into_owned(),
                output: merged_path.to_string_lossy().into_owned(),
                bruce_output: None,
                import_bruce: false,
            }),
        })
        .unwrap();

        // 2. CLI Batch
        run_cli(Cli {
            command: Some(Commands::Batch {
                file: merged_path.to_string_lossy().into_owned(),
                output: None,
                set: vec!["ro.custom.key=hello".to_string()],
                set_existing: vec![],
                remove: vec!["ro.port.extra".to_string()],
                comment: vec!["ro.panel.pad".to_string()],
                replace: vec![],
                batch_file: None,
                stdin: false,
                base: None,
                force: false,
                bruce_file: None,
            }),
        })
        .unwrap();

        let final_prop = PropFile::load(&merged_path).unwrap();
        assert_eq!(final_prop.get("ro.product.model"), Some("KB2000"));
        assert_eq!(final_prop.get("ro.build.version.oplusrom"), Some("V16.0.0"));
        assert_eq!(final_prop.get("ro.custom.key"), Some("hello"));
        assert_eq!(final_prop.get("ro.port.extra"), None);
        assert_eq!(final_prop.get("ro.panel.pad"), None);
        assert!(final_prop.to_string().contains("#ro.panel.pad=true"));

        // 3. CLI CleanFstab
        write_text_lf(
            &fstab_path,
            "system /system erofs ro wait,avb=vbmeta_system\nvendor /vendor ext4 ro wait,avb,logical\n",
        )
        .unwrap();

        run_cli(Cli {
            command: Some(Commands::CleanFstab {
                fstab: fstab_path.to_string_lossy().into_owned(),
                output: None,
                disable_avb: true,
                remove_erofs: true,
                remove_encryption: false,
                remove_slotselect: false,
            }),
        })
        .unwrap();

        let cleaned_fstab = read_text_lossy(&fstab_path).unwrap();
        assert_eq!(cleaned_fstab, "vendor /vendor ext4 ro wait,logical\n");
    }

    #[test]
    fn test_cli_batch_file_and_directory_fstab() {
        let dir = TempDir::new().unwrap();
        let prop_path = dir.path().join("build.prop");
        let batch_path = dir.path().join("ops.batch");
        let fstab_dir = dir.path().join("ramdisk");
        std::fs::create_dir_all(&fstab_dir).unwrap();

        write_text_lf(
            &prop_path,
            "# Header\r\nro.product.model=PJD110\r\nro.oplus.audio.effect=dolby\r\nro.panel.pad=1\r\n",
        )
        .unwrap();
        write_text_lf(
            &batch_path,
            "# Batch ops\nreplace PJD110=KB2000\nremove ro.oplus.audio.*\ncomment ro.panel.pad\nset ro.display.brightness.hbm_xs=\n",
        )
        .unwrap();

        run_cli(Cli {
            command: Some(Commands::Batch {
                file: prop_path.to_string_lossy().into_owned(),
                output: None,
                set: vec![],
                set_existing: vec![],
                remove: vec![],
                comment: vec![],
                replace: vec![],
                batch_file: Some(batch_path.to_string_lossy().into_owned()),
                stdin: false,
                base: None,
                force: false,
                bruce_file: None,
            }),
        })
        .unwrap();

        let prop = PropFile::load(&prop_path).unwrap();
        assert_eq!(prop.get("ro.product.model"), Some("KB2000"));
        assert_eq!(prop.get("ro.oplus.audio.effect"), None);
        assert_eq!(prop.get("ro.panel.pad"), None);
        assert_eq!(prop.get("ro.display.brightness.hbm_xs"), Some(""));
        assert!(prop.to_string().contains("#ro.panel.pad=1\n"));

        let fstab_qcom = fstab_dir.join("fstab.qcom");
        let fstab_emmc = fstab_dir.join("fstab.emmc");
        write_text_lf(&fstab_qcom, "system /system erofs ro wait,slotselect\nvendor /vendor ext4 ro wait,avb,logical\n").unwrap();
        write_text_lf(&fstab_emmc, "odm /odm ext4 ro wait,slotselect,avb=vbmeta_a,logical\n").unwrap();

        run_cli(Cli {
            command: Some(Commands::CleanFstab {
                fstab: fstab_dir.to_string_lossy().into_owned(),
                output: None,
                disable_avb: true,
                remove_erofs: true,
                remove_encryption: false,
                remove_slotselect: true,
            }),
        })
        .unwrap();

        assert_eq!(
            read_text_lossy(&fstab_qcom).unwrap(),
            "vendor /vendor ext4 ro wait,logical\n"
        );
        assert_eq!(read_text_lossy(&fstab_emmc).unwrap(), "");
    }
}
