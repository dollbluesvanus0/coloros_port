//! High-speed batch XML feature and configuration processor for ColorOS/OxygenOS ROM porting.
//!
//! Replaces sequential `add_feature`, `add_feature_v2`, `remove_feature`, `xmlstarlet`, and XML `sed`
//! invocations in `port.sh` and `functions.sh` with an order-preserving, comment-aware XML scanner/mutator.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::ops::Range;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use coloros_common::{collect_files_with_ext, read_text_lossy, write_text_lf};
use rayon::prelude::*;

#[derive(Debug, Parser)]
#[command(name = "xml-tool", about = "Batch XML feature and config processor")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
pub enum FeatureType {
    #[value(name = "oplus_feature", alias = "oplus-feature")]
    OplusFeature,
    #[value(name = "app_feature", alias = "app-feature")]
    AppFeature,
    #[value(name = "permission_feature", alias = "permission-feature")]
    PermissionFeature,
    #[value(name = "permission_oplus_feature", alias = "permission-oplus-feature")]
    PermissionOplusFeature,
}

impl FeatureType {
    /// Parse a feature type name from batch/stdin lines.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.trim() {
            "oplus_feature" | "oplus-feature" => Some(Self::OplusFeature),
            "app_feature" | "app-feature" => Some(Self::AppFeature),
            "permission_feature" | "permission-feature" => Some(Self::PermissionFeature),
            "permission_oplus_feature" | "permission-oplus-feature" => {
                Some(Self::PermissionOplusFeature)
            }
            _ => None,
        }
    }

    /// Relative path under `my_product/etc`, root tag, and child node tag matching `functions.sh`.
    pub fn spec(self) -> FeatureFileSpec {
        match self {
            Self::OplusFeature => FeatureFileSpec {
                rel_path: "extension/com.oplus.oplus-feature-ext-bruce.xml",
                root_tag: "oplus-config",
                node_tag: "oplus-feature",
            },
            Self::AppFeature => FeatureFileSpec {
                rel_path: "extension/com.oplus.app-features-ext-bruce.xml",
                root_tag: "extend_features",
                node_tag: "app_feature",
            },
            Self::PermissionFeature => FeatureFileSpec {
                rel_path: "permissions/com.oplus.android-features-ext-bruce.xml",
                root_tag: "permissions",
                node_tag: "feature",
            },
            Self::PermissionOplusFeature => FeatureFileSpec {
                rel_path: "permissions/oplus.feature-android-ext-bruce.xml",
                root_tag: "oplus-config",
                node_tag: "oplus-feature",
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureFileSpec {
    pub rel_path: &'static str,
    pub root_tag: &'static str,
    pub node_tag: &'static str,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Batch-add features (`add_feature` / `add_feature_v2` semantics with idempotent deduplication)
    AddFeatures {
        /// Port `my_product/etc` directory (resolves `*-ext-bruce.xml` targets and scans `*.xml`)
        #[arg(long, visible_alias = "etc-dir")]
        port_dir: Option<PathBuf>,

        /// Explicit target XML file (single-file `add_feature` mode)
        #[arg(long)]
        file: Option<PathBuf>,

        /// Directory to scan for existing features (defaults to `--port-dir` or parent of `--file`)
        #[arg(long)]
        scan_dir: Option<PathBuf>,

        /// Feature type when using `--port-dir`
        #[arg(long = "type", value_enum)]
        feature_type: Option<FeatureType>,

        /// Feature entry (`name`, `name^comment`, or `name^comment^args="..."`), repeatable
        #[arg(long = "feature")]
        features: Vec<String>,

        /// Read feature entries from a batch file (supports `<entry>` or `<type> <entry>`)
        #[arg(long)]
        batch_file: Option<String>,

        /// Read feature entries from stdin
        #[arg(long)]
        stdin: bool,

        /// Positional feature entries
        #[arg(value_name = "ENTRIES")]
        entries: Vec<String>,
    },

    /// Batch-remove named features across XML files (`remove_feature` semantics)
    RemoveFeatures {
        /// Port `my_product/etc` directory to scan recursively for `*.xml`
        #[arg(long, visible_alias = "etc-dir")]
        port_dir: Option<PathBuf>,

        /// Explicit target XML file(s)
        #[arg(long = "file")]
        files: Vec<PathBuf>,

        /// Optional base ROM `my_product/etc` dir; non-force removals skip features present uncommented in base
        #[arg(long)]
        base_dir: Option<PathBuf>,

        /// Feature name to remove (respects `--base-dir` unless `--force`), repeatable
        #[arg(long = "feature")]
        features: Vec<String>,

        /// Feature name to force-remove regardless of `--base-dir`, repeatable
        #[arg(long = "force-feature")]
        force_features: Vec<String>,

        /// Force-remove all specified `--feature` / positional entries
        #[arg(long)]
        force: bool,

        /// Read feature names from batch file (`<name>` or `<name> force`)
        #[arg(long)]
        batch_file: Option<String>,

        /// Read feature names from stdin
        #[arg(long)]
        stdin: bool,

        /// Positional feature names
        #[arg(value_name = "NAMES")]
        names: Vec<String>,
    },

    /// Delete XML elements matching tag/attribute predicates
    DeleteElements {
        /// Target XML file(s)
        #[arg(long = "file")]
        files: Vec<PathBuf>,

        /// Directory to scan recursively for `*.xml`
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Optional element tag filter (any tag if omitted)
        #[arg(long)]
        tag: Option<String>,

        /// Attribute name to match (default: `name`)
        #[arg(long, default_value = "name")]
        attr: String,

        /// Exact attribute value(s) to delete
        #[arg(long = "value")]
        values: Vec<String>,

        /// Delete elements whose attribute value (or full raw element text if `--attr` is empty) contains substring
        #[arg(long = "contains")]
        contains: Vec<String>,
    },

    /// Idempotently insert (or update) an XML element inside a parent element
    UpsertElement {
        /// Target XML file
        #[arg(long)]
        file: PathBuf,

        /// Parent element tag name (defaults to root element if omitted)
        #[arg(long)]
        parent: Option<String>,

        /// Element tag name (e.g. `enable`, `app_feature`)
        #[arg(long)]
        tag: String,

        /// Attribute used to detect whether the element already exists (e.g. `pkg`, `name`)
        #[arg(long)]
        key_attr: String,

        /// Uniqueness attribute value (e.g. `com.oplus.aimemory`)
        #[arg(long)]
        key_value: String,

        /// Attribute string for new element (e.g. `pkg="com.oplus.aimemory" priority="7"`)
        #[arg(long)]
        attrs: Option<String>,

        /// Optional inner child XML (e.g. `<StringList args="true"/>`)
        #[arg(long)]
        child: Option<String>,

        /// Optional raw XML element snippet to insert verbatim
        #[arg(long)]
        raw: Option<String>,

        /// Replace existing matching element instead of skipping
        #[arg(long)]
        update: bool,
    },

    /// Update text content of a sibling/child XML element (e.g. `Multimedia_Daemon_List.xml`)
    UpdateText {
        /// Input XML file
        #[arg(long)]
        file: PathBuf,

        /// Optional output path (defaults to modifying `--file` in-place)
        #[arg(long)]
        output: Option<PathBuf>,

        /// Enclosing parent element tag (e.g. `wechat-livephoto`)
        #[arg(long)]
        parent: String,

        /// Sibling/child tag to match by text (e.g. `name`)
        #[arg(long)]
        match_tag: String,

        /// Exact trimmed text content required on `--match-tag` (e.g. `com.tencent.mm`)
        #[arg(long)]
        match_text: String,

        /// Following sibling tag inside `--parent` whose text to replace (e.g. `attribute`)
        #[arg(long)]
        target_tag: String,

        /// New text value (e.g. `all`)
        #[arg(long)]
        value: String,

        /// 1-based index of matching `--target-tag` after `--match-tag` (default: 1)
        #[arg(long, default_value_t = 1)]
        index: usize,

        /// Fail with non-zero exit if zero elements matched
        #[arg(long)]
        require: bool,
    },
}

/// Parsed `name[^comment[^extra_attrs]]` feature entry used by `add_feature_v2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureEntry {
    pub name: String,
    pub comment: String,
    pub extra: String,
}

impl FeatureEntry {
    /// Parse `name`, `name^comment`, or `name^comment^extra` (matching `IFS='^' read -r` in `functions.sh`).
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            bail!("Empty feature entry");
        }
        let mut parts = trimmed.splitn(3, '^');
        let name = parts.next().unwrap_or("").trim();
        if name.is_empty() {
            bail!("Missing feature name in entry: '{raw}'");
        }
        let comment = parts.next().unwrap_or("").trim();
        let extra = parts.next().unwrap_or("").trim();
        Ok(Self {
            name: name.to_string(),
            comment: comment.to_string(),
            extra: extra.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum XmlToken {
    Comment(Range<usize>),
    PiOrDecl(Range<usize>),
    StartTag {
        range: Range<usize>,
        name: String,
        attrs_raw: String,
        self_closing: bool,
    },
    EndTag {
        range: Range<usize>,
        name: String,
    },
}

/// Scan an XML string into structural tokens with exact byte offsets.
fn scan_xml_tokens(src: &str) -> Vec<XmlToken> {
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < len {
        let Some(rel_lt) = bytes[i..].iter().position(|&b| b == b'<') else {
            break;
        };
        let lt = i + rel_lt;
        if lt + 1 >= len {
            break;
        }

        // Comment: <!-- ... -->
        if bytes[lt..].starts_with(b"<!--") {
            if let Some(rel_end) = src[lt + 4..].find("-->") {
                let end = lt + 4 + rel_end + 3;
                tokens.push(XmlToken::Comment(lt..end));
                i = end;
                continue;
            } else {
                tokens.push(XmlToken::Comment(lt..len));
                break;
            }
        }

        // CDATA: <![CDATA[ ... ]]>
        if bytes[lt..].starts_with(b"<![CDATA[") {
            if let Some(rel_end) = src[lt + 9..].find("]]>") {
                let end = lt + 9 + rel_end + 3;
                tokens.push(XmlToken::PiOrDecl(lt..end));
                i = end;
                continue;
            } else {
                tokens.push(XmlToken::PiOrDecl(lt..len));
                break;
            }
        }

        // Processing instruction <?...?> or declaration <!...>
        if bytes[lt + 1] == b'?' || bytes[lt + 1] == b'!' {
            let end = find_tag_end(bytes, lt + 2).unwrap_or(len);
            tokens.push(XmlToken::PiOrDecl(lt..end));
            i = end;
            continue;
        }

        // End tag </name>
        if bytes[lt + 1] == b'/' {
            let Some(end) = find_tag_end(bytes, lt + 2) else {
                break;
            };
            let inner = src[lt + 2..end - 1].trim();
            let name = inner.split_whitespace().next().unwrap_or("").to_string();
            tokens.push(XmlToken::EndTag {
                range: lt..end,
                name,
            });
            i = end;
            continue;
        }

        // Start or self-closing tag <name ...> / <name .../>
        let Some(end) = find_tag_end(bytes, lt + 1) else {
            break;
        };
        let raw_inner = &src[lt + 1..end - 1];
        let trimmed_end = raw_inner.trim_end();
        let (self_closing, body) = if let Some(stripped) = trimmed_end.strip_suffix('/') {
            (true, stripped)
        } else {
            (false, raw_inner)
        };
        let body_trimmed = body.trim_start();
        let name_end = body_trimmed
            .find(|c: char| c.is_whitespace())
            .unwrap_or(body_trimmed.len());
        let name = body_trimmed[..name_end].to_string();
        let attrs_raw = body_trimmed[name_end..].trim().to_string();
        if !name.is_empty() {
            tokens.push(XmlToken::StartTag {
                range: lt..end,
                name,
                attrs_raw,
                self_closing,
            });
        }
        i = end;
    }

    tokens
}

/// Find the byte offset right after the closing `>` of a tag, respecting single/double quotes.
fn find_tag_end(bytes: &[u8], mut pos: usize) -> Option<usize> {
    let mut quote: Option<u8> = None;
    while pos < bytes.len() {
        let b = bytes[pos];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            quote = Some(b);
        } else if b == b'>' {
            return Some(pos + 1);
        }
        pos += 1;
    }
    None
}

/// Parse XML attributes (`key="val"` or `key='val'`) and unescape basic XML entities.
fn parse_attrs(attrs_raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = attrs_raw.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }
        let key_start = i;
        while i < len && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = attrs_raw[key_start..i].trim();
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }
        let quote = bytes[i];
        if quote == b'"' || quote == b'\'' {
            i += 1;
            let val_start = i;
            while i < len && bytes[i] != quote {
                i += 1;
            }
            let raw_val = &attrs_raw[val_start..i];
            if i < len {
                i += 1;
            }
            if !key.is_empty() {
                out.push((key.to_string(), unescape_xml(raw_val)));
            }
        } else {
            let val_start = i;
            while i < len && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if !key.is_empty() {
                out.push((key.to_string(), attrs_raw[val_start..i].to_string()));
            }
        }
    }

    out
}

fn get_attr<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn unescape_xml(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Extract all uncommented feature `name` attributes (plus standalone text lines) from an XML document.
pub fn collect_active_features(xml: &str) -> HashSet<String> {
    let mut found = HashSet::new();
    let tokens = scan_xml_tokens(xml);
    let mut prev_end = 0usize;

    for tok in &tokens {
        let tok_start = match tok {
            XmlToken::Comment(r)
            | XmlToken::PiOrDecl(r)
            | XmlToken::StartTag { range: r, .. }
            | XmlToken::EndTag { range: r, .. } => r.start,
        };
        if tok_start > prev_end {
            let text = xml[prev_end..tok_start].trim();
            if !text.is_empty() {
                found.insert(unescape_xml(text));
            }
        }
        prev_end = match tok {
            XmlToken::Comment(r)
            | XmlToken::PiOrDecl(r)
            | XmlToken::StartTag { range: r, .. }
            | XmlToken::EndTag { range: r, .. } => r.end,
        };

        if let XmlToken::StartTag { attrs_raw, .. } = tok {
            let attrs = parse_attrs(attrs_raw);
            if let Some(name) = get_attr(&attrs, "name") {
                found.insert(name.to_string());
            }
        }
    }

    found
}

/// Check if `feature` is present as an active (non-commented) feature in `xml`.
pub fn has_active_feature(xml: &str, feature: &str) -> bool {
    let tokens = scan_xml_tokens(xml);
    let mut prev_end = 0usize;
    for tok in &tokens {
        let tok_range = match tok {
            XmlToken::Comment(r)
            | XmlToken::PiOrDecl(r)
            | XmlToken::StartTag { range: r, .. }
            | XmlToken::EndTag { range: r, .. } => r,
        };
        if tok_range.start > prev_end && xml[prev_end..tok_range.start].trim() == feature {
            return true;
        }
        prev_end = tok_range.end;

        if let XmlToken::StartTag { attrs_raw, .. } = tok {
            let attrs = parse_attrs(attrs_raw);
            if get_attr(&attrs, "name") == Some(feature) {
                return true;
            }
        }
    }
    false
}

/// Scan all `*.xml` files under `scan_dir` (in parallel) and collect active feature names.
pub fn scan_dir_active_features(scan_dir: &Path) -> Result<HashSet<String>> {
    if !scan_dir.exists() {
        return Ok(HashSet::new());
    }
    let xml_files = collect_files_with_ext(scan_dir, "xml", true);
    let sets: Vec<HashSet<String>> = xml_files
        .par_iter()
        .map(|p| {
            let content = read_text_lossy(p)?;
            Ok(collect_active_features(&content))
        })
        .collect::<coloros_common::Result<Vec<_>>>()?;

    let mut combined = HashSet::new();
    for s in sets {
        combined.extend(s);
    }
    Ok(combined)
}

/// Detect `(root_tag, first_child_tag)` from an XML document.
pub fn detect_root_and_child_tags(xml: &str) -> Result<(String, String)> {
    let tokens = scan_xml_tokens(xml);
    let mut tags = tokens.iter().filter_map(|t| match t {
        XmlToken::StartTag { name, .. } => Some(name.as_str()),
        _ => None,
    });
    let root = tags
        .next()
        .context("No root XML element found")?
        .to_string();
    let child = tags
        .next()
        .map(|s| s.to_string())
        .unwrap_or_else(|| match root.as_str() {
            "oplus-config" => "oplus-feature".to_string(),
            "extend_features" => "app_feature".to_string(),
            "permissions" => "feature".to_string(),
            _ => "feature".to_string(),
        });
    Ok((root, child))
}

/// Insert formatted lines right before the closing `</parent_tag>` (preserving line breaks).
fn insert_before_closing_tag(xml: &str, parent_tag: &str, block: &str) -> Result<String> {
    let tokens = scan_xml_tokens(xml);
    let end_range = tokens
        .iter()
        .rev()
        .find_map(|t| match t {
            XmlToken::EndTag { range, name } if name == parent_tag => Some(range.clone()),
            _ => None,
        })
        .with_context(|| format!("Closing </{parent_tag}> tag not found"))?;

    // Back up over horizontal whitespace before `</parent_tag>` so we insert cleanly on its own line.
    let before = &xml[..end_range.start];
    let line_start = before.rfind('\n').map(|p| p + 1).unwrap_or(0);
    let leading_ws = &xml[line_start..end_range.start];
    let insert_at = if leading_ws.chars().all(|c| c == ' ' || c == '\t') {
        line_start
    } else {
        end_range.start
    };

    let mut out = String::with_capacity(xml.len() + block.len() + 4);
    out.push_str(&xml[..insert_at]);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(block);
    if !block.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&xml[insert_at..]);
    Ok(out)
}

fn format_feature_block(node_tag: &str, entries: &[FeatureEntry], indent: &str) -> String {
    let mut buf = String::new();
    for entry in entries {
        if !entry.comment.is_empty() {
            let safe_comment = entry.comment.replace("--", "- -");
            buf.push_str(&format!("{indent}<!-- {safe_comment} -->\n"));
        }
        let escaped_name = entry.name.replace('"', "&quot;");
        if entry.extra.is_empty() {
            buf.push_str(&format!("{indent}<{node_tag} name=\"{escaped_name}\"/>\n"));
        } else {
            buf.push_str(&format!(
                "{indent}<{node_tag} name=\"{escaped_name}\" {}/>\n",
                entry.extra
            ));
        }
    }
    buf
}

/// Add a batch of `FeatureEntry` items to `target_file`, creating it with `root_tag` if missing,
/// and skipping any feature already present in `existing_features`.
/// Updates `existing_features` in-place with newly added feature names.
/// Returns the number of newly added features.
pub fn add_features_to_file(
    target_file: &Path,
    root_tag: Option<&str>,
    node_tag: Option<&str>,
    entries: &[FeatureEntry],
    existing_features: &mut HashSet<String>,
    indent: &str,
) -> Result<usize> {
    let mut xml = if target_file.exists() {
        read_text_lossy(target_file)?
    } else {
        let rt = root_tag.context("root_tag required when creating a new XML file")?;
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<{rt}>\n</{rt}>\n")
    };

    // Also include any features from `target_file` itself in case it sits outside `scan_dir`.
    existing_features.extend(collect_active_features(&xml));

    let (detected_root, detected_child) = detect_root_and_child_tags(&xml)?;
    let effective_root = root_tag.unwrap_or(&detected_root);
    let effective_node = node_tag.unwrap_or(&detected_child);

    let mut to_add = Vec::new();
    for entry in entries {
        if existing_features.contains(&entry.name) {
            continue;
        }
        existing_features.insert(entry.name.clone());
        to_add.push(entry.clone());
    }

    if to_add.is_empty() {
        if !target_file.exists() {
            write_text_lf(target_file, &xml)?;
        }
        return Ok(0);
    }

    let block = format_feature_block(effective_node, &to_add, indent);
    xml = insert_before_closing_tag(&xml, effective_root, &block)?;
    write_text_lf(target_file, &xml)?;
    Ok(to_add.len())
}

/// Expand a matched element byte range `[start..end]` to include its whole line(s) if no other
/// non-whitespace content shares the start/end lines.
fn expand_to_full_lines(src: &str, start: usize, end: usize) -> Range<usize> {
    let line_start = src[..start].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let prefix_ws = src[line_start..start].chars().all(|c| c == ' ' || c == '\t');

    let line_end_no_nl = src[end..]
        .find('\n')
        .map(|p| end + p)
        .unwrap_or(src.len());
    let suffix_ws = src[end..line_end_no_nl]
        .chars()
        .all(|c| c == ' ' || c == '\t' || c == '\r');

    if prefix_ws && suffix_ws {
        let del_end = if line_end_no_nl < src.len() && src.as_bytes()[line_end_no_nl] == b'\n' {
            line_end_no_nl + 1
        } else {
            line_end_no_nl
        };
        line_start..del_end
    } else {
        start..end
    }
}

/// Collect byte ranges of elements matching `pred(tag_name, attrs, raw_element)` (outermost match wins).
fn find_matching_element_ranges<F>(xml: &str, mut pred: F) -> Vec<Range<usize>>
where
    F: FnMut(&str, &[(String, String)], &str) -> bool,
{
    let tokens = scan_xml_tokens(xml);
    let mut stack: Vec<(String, usize, String)> = Vec::new();
    let mut delete_ranges: Vec<Range<usize>> = Vec::new();
    let mut skip_depth: Option<usize> = None;

    for tok in tokens {
        match tok {
            XmlToken::StartTag {
                range,
                name,
                attrs_raw,
                self_closing,
            } => {
                if self_closing {
                    if skip_depth.is_none() {
                        let attrs = parse_attrs(&attrs_raw);
                        let raw_el = &xml[range.start..range.end];
                        if pred(&name, &attrs, raw_el) {
                            delete_ranges.push(expand_to_full_lines(xml, range.start, range.end));
                        }
                    }
                } else {
                    if skip_depth.is_none() {
                        let attrs = parse_attrs(&attrs_raw);
                        if pred(&name, &attrs, &xml[range.start..range.end]) {
                            skip_depth = Some(stack.len());
                        }
                    }
                    stack.push((name, range.start, attrs_raw));
                }
            }
            XmlToken::EndTag { range, name } => {
                if let Some(pos) = stack.iter().rposition(|(n, _, _)| n == &name) {
                    let (_, start_byte, _) = stack.remove(pos);
                    stack.truncate(pos);
                    if let Some(sd) = skip_depth {
                        if pos <= sd {
                            skip_depth = None;
                            delete_ranges.push(expand_to_full_lines(xml, start_byte, range.end));
                        }
                    }
                }
            }
            XmlToken::Comment(_) | XmlToken::PiOrDecl(_) => {}
        }
    }

    // Merge overlapping or adjacent ranges.
    delete_ranges.sort_by_key(|r| (r.start, r.end));
    let mut merged: Vec<Range<usize>> = Vec::new();
    for r in delete_ranges {
        if let Some(last) = merged.last_mut() {
            if r.start <= last.end {
                last.end = last.end.max(r.end);
                continue;
            }
        }
        merged.push(r);
    }
    merged
}

/// Remove elements matched by `pred` from `xml`, returning `(new_xml, deleted_count)`.
pub fn remove_elements_matching<F>(xml: &str, pred: F) -> (String, usize)
where
    F: FnMut(&str, &[(String, String)], &str) -> bool,
{
    let ranges = find_matching_element_ranges(xml, pred);
    if ranges.is_empty() {
        return (xml.to_string(), 0);
    }
    let count = ranges.len();
    let mut out = String::with_capacity(xml.len());
    let mut cursor = 0usize;
    for r in ranges {
        if r.start > cursor {
            out.push_str(&xml[cursor..r.start]);
        }
        cursor = r.end;
    }
    if cursor < xml.len() {
        out.push_str(&xml[cursor..]);
    }
    (out, count)
}

/// Idempotently upsert an XML element inside `parent_tag` (or root tag if `parent_tag` is `None`).
pub fn upsert_element_in_xml(
    xml: &str,
    parent_tag: Option<&str>,
    tag: &str,
    key_attr: &str,
    key_value: &str,
    element_snippet: &str,
    update: bool,
) -> Result<(String, bool)> {
    let tokens = scan_xml_tokens(xml);
    let target_parent = match parent_tag {
        Some(p) => p.to_string(),
        None => {
            let (root, _) = detect_root_and_child_tags(xml)?;
            root
        }
    };

    // Find existing element span(s) matching tag + key_attr=key_value.
    let mut stack: Vec<(String, usize, bool)> = Vec::new();
    let mut found_span: Option<Range<usize>> = None;

    for tok in &tokens {
        match tok {
            XmlToken::StartTag {
                range,
                name,
                attrs_raw,
                self_closing,
            } => {
                let attrs = parse_attrs(attrs_raw);
                let matched = name == tag && get_attr(&attrs, key_attr) == Some(key_value);
                if *self_closing {
                    if matched && found_span.is_none() {
                        found_span = Some(range.clone());
                    }
                } else {
                    stack.push((name.clone(), range.start, matched));
                }
            }
            XmlToken::EndTag { range, name } => {
                if let Some(pos) = stack.iter().rposition(|(n, _, _)| n == name) {
                    let (_, start_byte, matched) = stack.remove(pos);
                    stack.truncate(pos);
                    if matched && found_span.is_none() {
                        found_span = Some(start_byte..range.end);
                    }
                }
            }
            XmlToken::Comment(_) | XmlToken::PiOrDecl(_) => {}
        }
    }

    if let Some(span) = found_span {
        if !update {
            return Ok((xml.to_string(), false));
        }
        let mut out = String::with_capacity(xml.len() + element_snippet.len());
        out.push_str(&xml[..span.start]);
        out.push_str(element_snippet.trim());
        out.push_str(&xml[span.end..]);
        return Ok((out, true));
    }

    let formatted = if element_snippet.ends_with('\n') {
        element_snippet.to_string()
    } else {
        format!("{element_snippet}\n")
    };
    let updated = insert_before_closing_tag(xml, &target_parent, &formatted)?;
    Ok((updated, true))
}

/// Update the text of the `index`-th (1-based) `<target_tag>` following `<match_tag>match_text</match_tag>`
/// inside `<parent_tag>...</parent_tag>`.
pub fn update_sibling_text_in_xml(
    xml: &str,
    parent_tag: &str,
    match_tag: &str,
    match_text: &str,
    target_tag: &str,
    new_value: &str,
    index: usize,
) -> Result<(String, usize)> {
    if index == 0 {
        bail!("--index must be >= 1");
    }
    let tokens = scan_xml_tokens(xml);

    struct OpenFrame {
        name: String,
        inner_start: usize,
        self_depth: usize,
        matched_in_parent: bool,
        target_seen_count: usize,
    }

    let mut stack: Vec<OpenFrame> = Vec::new();
    let mut replacements: Vec<(Range<usize>, String)> = Vec::new();

    for tok in &tokens {
        match tok {
            XmlToken::StartTag {
                range,
                name,
                self_closing,
                ..
            } => {
                if *self_closing {
                    // Handle self-closing <target_tag/> if it is a direct child of an already-matched parent
                    if let Some(parent_frame) = stack.last_mut() {
                        if parent_frame.name == parent_tag
                            && parent_frame.matched_in_parent
                            && name == target_tag
                        {
                            parent_frame.target_seen_count += 1;
                            if parent_frame.target_seen_count == index {
                                let replacement = format!("<{target_tag}>{new_value}</{target_tag}>");
                                replacements.push((range.clone(), replacement));
                            }
                        }
                    }
                } else {
                    let depth = stack.len();
                    stack.push(OpenFrame {
                        name: name.clone(),
                        inner_start: range.end,
                        self_depth: depth,
                        matched_in_parent: false,
                        target_seen_count: 0,
                    });
                }
            }
            XmlToken::EndTag { range, name } => {
                let Some(pos) = stack.iter().rposition(|f| &f.name == name) else {
                    continue;
                };
                let frame = stack.remove(pos);
                stack.truncate(pos);
                let inner_end = range.start;

                if let Some(parent_frame) = stack.last_mut() {
                    if parent_frame.name == parent_tag
                        && frame.self_depth == parent_frame.self_depth + 1
                    {
                        if frame.name == match_tag {
                            let inner_txt = xml[frame.inner_start..inner_end].trim();
                            if unescape_xml(inner_txt) == match_text {
                                parent_frame.matched_in_parent = true;
                                parent_frame.target_seen_count = 0;
                            }
                        } else if parent_frame.matched_in_parent && frame.name == target_tag {
                            parent_frame.target_seen_count += 1;
                            if parent_frame.target_seen_count == index {
                                replacements
                                    .push((frame.inner_start..inner_end, new_value.to_string()));
                            }
                        }
                    }
                }
            }
            XmlToken::Comment(_) | XmlToken::PiOrDecl(_) => {}
        }
    }

    if replacements.is_empty() {
        return Ok((xml.to_string(), 0));
    }

    let count = replacements.len();
    let mut out = xml.to_string();
    for (range, rep) in replacements.into_iter().rev() {
        out.replace_range(range, &rep);
    }
    Ok((out, count))
}

fn read_script_source(batch_file: Option<&str>, stdin: bool) -> Result<Option<String>> {
    if let Some(bf) = batch_file {
        if bf == "-" {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("Failed to read batch input from stdin")?;
            return Ok(Some(buf));
        }
        return Ok(Some(
            read_text_lossy(bf).with_context(|| format!("Failed to read batch file: {bf}"))?,
        ));
    }
    if stdin {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("Failed to read batch input from stdin")?;
        return Ok(Some(buf));
    }
    Ok(None)
}

pub fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::AddFeatures {
            port_dir,
            file,
            scan_dir,
            feature_type,
            features,
            batch_file,
            stdin,
            entries,
        } => {
            let mut all_raw: Vec<String> = features;
            all_raw.extend(entries);
            let script_opt = read_script_source(batch_file.as_deref(), stdin)?;

            let effective_scan_dir = scan_dir.or_else(|| {
                port_dir
                    .clone()
                    .or_else(|| file.as_ref().and_then(|f| f.parent().map(Path::to_path_buf)))
            });

            let mut existing = match effective_scan_dir.as_deref() {
                Some(sd) => scan_dir_active_features(sd)?,
                None => HashSet::new(),
            };

            if let Some(target_file) = file {
                let mut parsed_entries = Vec::new();
                for raw in all_raw {
                    parsed_entries.push(FeatureEntry::parse(&raw)?);
                }
                if let Some(script) = script_opt {
                    for line in script.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            continue;
                        }
                        parsed_entries.push(FeatureEntry::parse(trimmed)?);
                    }
                }
                let added = add_features_to_file(
                    &target_file,
                    None,
                    None,
                    &parsed_entries,
                    &mut existing,
                    "\t",
                )?;
                println!(
                    "[+] xml-tool add-features: added {added} feature(s) to {}",
                    target_file.display()
                );
                return Ok(());
            }

            let port_etc = port_dir.context("Missing --port-dir or --file for add-features")?;
            let mut grouped: HashMap<FeatureType, Vec<FeatureEntry>> = HashMap::new();
            let mut type_order: Vec<FeatureType> = Vec::new();

            let mut push_entry = |ft: FeatureType, entry: FeatureEntry| {
                if !grouped.contains_key(&ft) {
                    type_order.push(ft);
                }
                grouped.entry(ft).or_default().push(entry);
            };

            if !all_raw.is_empty() {
                let ft = feature_type.context(
                    "Missing --type <oplus_feature|app_feature|permission_feature|permission_oplus_feature> for inline entries",
                )?;
                for raw in all_raw {
                    push_entry(ft, FeatureEntry::parse(&raw)?);
                }
            }

            if let Some(script) = script_opt {
                for line in script.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    // Allow `<type>\t<entry>` or `<type> <entry>` when batching across types.
                    if let Some((first, rest)) = trimmed.split_once(['\t', ' ']) {
                        if let Some(ft) = FeatureType::parse_str(first) {
                            push_entry(ft, FeatureEntry::parse(rest)?);
                            continue;
                        }
                    }
                    let ft = feature_type.context(
                        "Batch line has no feature-type prefix and --type was not provided",
                    )?;
                    push_entry(ft, FeatureEntry::parse(trimmed)?);
                }
            }

            let mut total_added = 0usize;
            for ft in type_order {
                let spec = ft.spec();
                let target_file = port_etc.join(spec.rel_path);
                let entries_for_type = &grouped[&ft];
                total_added += add_features_to_file(
                    &target_file,
                    Some(spec.root_tag),
                    Some(spec.node_tag),
                    entries_for_type,
                    &mut existing,
                    "    ",
                )?;
            }

            println!(
                "[+] xml-tool add-features: added {total_added} feature(s) under {}",
                port_etc.display()
            );
            Ok(())
        }

        Commands::RemoveFeatures {
            port_dir,
            files,
            base_dir,
            features,
            force_features,
            force,
            batch_file,
            stdin,
            names,
        } => {
            let mut non_force: Vec<String> = Vec::new();
            let mut forced: Vec<String> = force_features;

            for f in features.into_iter().chain(names) {
                if force {
                    forced.push(f);
                } else {
                    non_force.push(f);
                }
            }

            if let Some(script) = read_script_source(batch_file.as_deref(), stdin)? {
                for line in script.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if let Some(rest) = trimmed.strip_prefix("force ") {
                        forced.push(rest.trim().to_string());
                    } else if let Some(rest) = trimmed.strip_suffix(" force") {
                        forced.push(rest.trim().to_string());
                    } else if force {
                        forced.push(trimmed.to_string());
                    } else {
                        non_force.push(trimmed.to_string());
                    }
                }
            }

            let base_active = match base_dir.as_deref() {
                Some(bd) if !non_force.is_empty() => scan_dir_active_features(bd)?,
                _ => HashSet::new(),
            };

            let mut to_remove: HashSet<String> = forced.into_iter().collect();
            for f in non_force {
                if !base_active.contains(&f) {
                    to_remove.insert(f);
                }
            }

            if to_remove.is_empty() {
                return Ok(());
            }

            let mut target_files = files;
            if let Some(pd) = port_dir {
                if pd.exists() {
                    target_files.extend(collect_files_with_ext(&pd, "xml", true));
                }
            }
            target_files.sort();
            target_files.dedup();

            let total_removed: usize = target_files
                .par_iter()
                .map(|path| -> Result<usize> {
                    let xml = read_text_lossy(path)?;
                    // Quick substring pre-filter before full token scan.
                    if !to_remove.iter().any(|f| xml.contains(f.as_str())) {
                        return Ok(0);
                    }
                    let (updated, count) = remove_elements_matching(&xml, |_tag, attrs, _raw| {
                        get_attr(attrs, "name")
                            .map(|n| to_remove.contains(n))
                            .unwrap_or(false)
                    });
                    if count > 0 {
                        write_text_lf(path, &updated)?;
                    }
                    Ok(count)
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .sum();

            println!("[+] xml-tool remove-features: removed {total_removed} element(s)");
            Ok(())
        }

        Commands::DeleteElements {
            files,
            dir,
            tag,
            attr,
            values,
            contains,
        } => {
            if values.is_empty() && contains.is_empty() {
                bail!("Specify at least one --value or --contains filter");
            }
            let mut target_files = files;
            if let Some(d) = dir {
                if d.exists() {
                    target_files.extend(collect_files_with_ext(&d, "xml", true));
                }
            }
            target_files.sort();
            target_files.dedup();

            let value_set: HashSet<&str> = values.iter().map(|s| s.as_str()).collect();
            let mut total_deleted = 0usize;

            for path in target_files {
                let xml = read_text_lossy(&path)?;
                let (updated, count) = remove_elements_matching(&xml, |el_tag, attrs, raw_el| {
                    if let Some(ref t) = tag {
                        if el_tag != t {
                            return false;
                        }
                    }
                    if !attr.is_empty() {
                        if let Some(val) = get_attr(attrs, &attr) {
                            if value_set.contains(val)
                                || contains.iter().any(|sub| val.contains(sub.as_str()))
                            {
                                return true;
                            }
                        }
                    }
                    if attr.is_empty() && contains.iter().any(|sub| raw_el.contains(sub.as_str())) {
                        return true;
                    }
                    false
                });
                if count > 0 {
                    write_text_lf(&path, &updated)?;
                    total_deleted += count;
                }
            }

            println!("[+] xml-tool delete-elements: deleted {total_deleted} element(s)");
            Ok(())
        }

        Commands::UpsertElement {
            file,
            parent,
            tag,
            key_attr,
            key_value,
            attrs,
            child,
            raw,
            update,
        } => {
            let xml = read_text_lossy(&file)?;
            let snippet = if let Some(r) = raw {
                r
            } else {
                let attr_str = attrs.unwrap_or_else(|| format!("{key_attr}=\"{key_value}\""));
                if let Some(c) = child {
                    format!("    <{tag} {attr_str}>\n        {c}\n    </{tag}>")
                } else {
                    format!("  <{tag} {attr_str}/>")
                }
            };
            let (updated, changed) = upsert_element_in_xml(
                &xml,
                parent.as_deref(),
                &tag,
                &key_attr,
                &key_value,
                &snippet,
                update,
            )?;
            if changed {
                write_text_lf(&file, &updated)?;
            }
            Ok(())
        }

        Commands::UpdateText {
            file,
            output,
            parent,
            match_tag,
            match_text,
            target_tag,
            value,
            index,
            require,
        } => {
            let xml = read_text_lossy(&file)?;
            let (updated, count) = update_sibling_text_in_xml(
                &xml,
                &parent,
                &match_tag,
                &match_text,
                &target_tag,
                &value,
                index,
            )?;
            if require && count == 0 {
                bail!(
                    "update-text --require: no <{parent}>/<{match_tag}>{match_text}</{match_tag}> -> <{target_tag}> found in {}",
                    file.display()
                );
            }
            let out_path = output.as_deref().unwrap_or(&file);
            if count > 0 || out_path != file {
                write_text_lf(out_path, &updated)?;
            }
            println!(
                "[+] xml-tool update-text: updated {count} element(s) in {}",
                out_path.display()
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_add_features_v2_all_types_dedup_and_comments() {
        let dir = TempDir::new().unwrap();
        let base_etc = dir.path().join("base/my_product/etc");
        let port_etc = dir.path().join("port/my_product/etc");
        fs::create_dir_all(port_etc.join("extension")).unwrap();
        fs::create_dir_all(port_etc.join("permissions")).unwrap();
        fs::create_dir_all(base_etc.join("extension")).unwrap();

        // Pre-existing feature in another XML file + a commented-out feature
        write_text_lf(
            port_etc.join("extension/com.oplus.oplus-feature.xml"),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<oplus-config>\n    <oplus-feature name=\"already.present\"/>\n    <!--\n    <oplus-feature name=\"commented.out.feature\"/>\n    -->\n</oplus-config>\n",
        )
        .unwrap();

        let batch = "\
# Comment line
oplus_feature already.present
oplus_feature commented.out.feature^注释
oplus_feature oplus.software.systemui.navbar_pick_color^15.0.2.201新增
oplus_feature oplus.software.systemui.navbar_pick_color^duplicate_in_batch
app_feature os.graphic.gallery.os15_secrecy^^args=\"boolean:true\"
app_feature com.oplus.screenrecorder.area_record^区域截图^args=\"boolean:true\"
permission_feature oplus.software.ai_key_multi_enable
permission_oplus_feature oplus.software.game.cold.start.speedup.enable
";
        let batch_file = dir.path().join("features.txt");
        write_text_lf(&batch_file, batch).unwrap();

        run_cli(Cli {
            command: Commands::AddFeatures {
                port_dir: Some(port_etc.clone()),
                file: None,
                scan_dir: None,
                feature_type: None,
                features: vec![],
                batch_file: Some(batch_file.to_string_lossy().into_owned()),
                stdin: false,
                entries: vec![],
            },
        })
        .unwrap();

        let oplus_ext = read_text_lossy(port_etc.join("extension/com.oplus.oplus-feature-ext-bruce.xml")).unwrap();
        assert!(!oplus_ext.contains("already.present"));
        assert!(oplus_ext.contains("<!-- 注释 -->\n    <oplus-feature name=\"commented.out.feature\"/>"));
        assert!(oplus_ext.contains("<!-- 15.0.2.201新增 -->\n    <oplus-feature name=\"oplus.software.systemui.navbar_pick_color\"/>"));
        assert!(!oplus_ext.contains("duplicate_in_batch"));

        let app_ext = read_text_lossy(port_etc.join("extension/com.oplus.app-features-ext-bruce.xml")).unwrap();
        assert!(app_ext.contains("<app_feature name=\"os.graphic.gallery.os15_secrecy\" args=\"boolean:true\"/>"));
        assert!(app_ext.contains("<!-- 区域截图 -->\n    <app_feature name=\"com.oplus.screenrecorder.area_record\" args=\"boolean:true\"/>"));

        let perm_ext = read_text_lossy(port_etc.join("permissions/com.oplus.android-features-ext-bruce.xml")).unwrap();
        assert!(perm_ext.contains("<feature name=\"oplus.software.ai_key_multi_enable\"/>"));

        let perm_oplus_ext = read_text_lossy(port_etc.join("permissions/oplus.feature-android-ext-bruce.xml")).unwrap();
        assert!(perm_oplus_ext.contains("<oplus-feature name=\"oplus.software.game.cold.start.speedup.enable\"/>"));

        // Running a second time must be idempotent
        run_cli(Cli {
            command: Commands::AddFeatures {
                port_dir: Some(port_etc.clone()),
                file: None,
                scan_dir: None,
                feature_type: None,
                features: vec![],
                batch_file: Some(batch_file.to_string_lossy().into_owned()),
                stdin: false,
                entries: vec![],
            },
        })
        .unwrap();
        let oplus_ext_2 = read_text_lossy(port_etc.join("extension/com.oplus.oplus-feature-ext-bruce.xml")).unwrap();
        assert_eq!(oplus_ext, oplus_ext_2);
    }

    #[test]
    fn test_remove_features_respects_base_and_force_and_multiline() {
        let dir = TempDir::new().unwrap();
        let base_etc = dir.path().join("base/my_product/etc");
        let port_etc = dir.path().join("port/my_product/etc");
        fs::create_dir_all(base_etc.join("permissions")).unwrap();
        fs::create_dir_all(port_etc.join("extension")).unwrap();

        write_text_lf(
            base_etc.join("permissions/base.xml"),
            "<permissions>\n    <feature name=\"keep.from.base\"/>\n    <!-- <feature name=\"commented.in.base\"/> -->\n</permissions>\n",
        )
        .unwrap();

        let port_xml = port_etc.join("extension/com.oplus.app-features.xml");
        write_text_lf(
            &port_xml,
            "<extend_features>\n    <app_feature name=\"keep.from.base\"/>\n    <app_feature name=\"commented.in.base\">\n        <StringList args=\"1\"/>\n    </app_feature>\n    <app_feature name=\"force.delete.me\"/>\n    <app_feature name=\"delete.absent.in.base\"/>\n</extend_features>\n",
        )
        .unwrap();

        run_cli(Cli {
            command: Commands::RemoveFeatures {
                port_dir: Some(port_etc),
                files: vec![],
                base_dir: Some(base_etc),
                features: vec![
                    "keep.from.base".to_string(),
                    "commented.in.base".to_string(),
                    "delete.absent.in.base".to_string(),
                ],
                force_features: vec!["force.delete.me".to_string()],
                force: false,
                batch_file: None,
                stdin: false,
                names: vec![],
            },
        })
        .unwrap();

        let after = read_text_lossy(&port_xml).unwrap();
        assert!(after.contains("keep.from.base"));
        assert!(!after.contains("commented.in.base"));
        assert!(!after.contains("<StringList args=\"1\"/>"));
        assert!(!after.contains("force.delete.me"));
        assert!(!after.contains("delete.absent.in.base"));
        assert!(after.contains("</extend_features>"));
    }

    #[test]
    fn test_delete_elements_upsert_and_update_text() {
        let dir = TempDir::new().unwrap();

        // 1. DeleteElements on com.oplus.app-features.xml (MCC) and app_v2.xml
        let mcc_xml = dir.path().join("com.oplus.app-features.xml");
        write_text_lf(
            &mcc_xml,
            "<extend_features>\n    <app_feature name=\"com.android.incallui.support_call_record_prompt_mcc\">\n        <StringList args=\"460\"/>\n    </app_feature>\n    <app_feature name=\"com.android.incallui.hide_call_record_mcc\"/>\n    <app_feature name=\"other.keep\"/>\n</extend_features>\n",
        )
        .unwrap();

        run_cli(Cli {
            command: Commands::DeleteElements {
                files: vec![mcc_xml.clone()],
                dir: None,
                tag: Some("app_feature".to_string()),
                attr: "name".to_string(),
                values: vec![
                    "com.android.incallui.support_call_record_prompt_mcc".to_string(),
                    "com.android.incallui.hide_call_record_mcc".to_string(),
                ],
                contains: vec![],
            },
        })
        .unwrap();
        let mcc_after = read_text_lossy(&mcc_xml).unwrap();
        assert_eq!(
            mcc_after,
            "<extend_features>\n    <app_feature name=\"other.keep\"/>\n</extend_features>\n"
        );

        // 2. UpsertElement on app_v2.xml (idempotent)
        let app_v2 = dir.path().join("app_v2.xml");
        write_text_lf(
            &app_v2,
            "<app>\n  <enable pkg=\"com.existing\" priority=\"7\"/>\n</app>\n",
        )
        .unwrap();
        for _ in 0..2 {
            run_cli(Cli {
                command: Commands::UpsertElement {
                    file: app_v2.clone(),
                    parent: Some("app".to_string()),
                    tag: "enable".to_string(),
                    key_attr: "pkg".to_string(),
                    key_value: "com.oplus.aimemory".to_string(),
                    attrs: Some("pkg=\"com.oplus.aimemory\" priority=\"7\"".to_string()),
                    child: None,
                    raw: None,
                    update: false,
                },
            })
            .unwrap();
        }
        let app_v2_after = read_text_lossy(&app_v2).unwrap();
        assert_eq!(app_v2_after.matches("com.oplus.aimemory").count(), 1);
        assert!(app_v2_after.contains("<enable pkg=\"com.oplus.aimemory\" priority=\"7\"/>"));

        // 3. UpdateText on Multimedia_Daemon_List.xml
        let mm_xml = dir.path().join("Multimedia_Daemon_List.xml");
        write_text_lf(
            &mm_xml,
            "<filter-conf>\n    <wechat-livephoto>\n        <name>com.other.app</name>\n        <attribute>none</attribute>\n    </wechat-livephoto>\n    <wechat-livephoto>\n        <name>com.tencent.mm</name>\n        <attribute>restricted</attribute>\n    </wechat-livephoto>\n</filter-conf>\n",
        )
        .unwrap();

        run_cli(Cli {
            command: Commands::UpdateText {
                file: mm_xml.clone(),
                output: None,
                parent: "wechat-livephoto".to_string(),
                match_tag: "name".to_string(),
                match_text: "com.tencent.mm".to_string(),
                target_tag: "attribute".to_string(),
                value: "all".to_string(),
                index: 1,
                require: true,
            },
        })
        .unwrap();

        let mm_after = read_text_lossy(&mm_xml).unwrap();
        assert!(mm_after.contains("<name>com.other.app</name>\n        <attribute>none</attribute>"));
        assert!(mm_after.contains("<name>com.tencent.mm</name>\n        <attribute>all</attribute>"));
    }

    #[test]
    fn test_add_features_single_file_mode() {
        let dir = TempDir::new().unwrap();
        let perm_file = dir.path().join("android.hardware.fingerprint.xml");
        write_text_lf(
            &perm_file,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<permissions>\n\t<feature name=\"android.hardware.fingerprint\" />\n</permissions>\n",
        )
        .unwrap();

        run_cli(Cli {
            command: Commands::AddFeatures {
                port_dir: None,
                file: Some(perm_file.clone()),
                scan_dir: None,
                feature_type: None,
                features: vec!["android.hardware.biometrics.face".to_string()],
                batch_file: None,
                stdin: false,
                entries: vec![],
            },
        })
        .unwrap();

        let after = read_text_lossy(&perm_file).unwrap();
        assert!(after.contains("<feature name=\"android.hardware.biometrics.face\"/>"));
    }
}
