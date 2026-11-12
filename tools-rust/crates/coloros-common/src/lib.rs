//! Common utilities, error handling, logging, and file helpers for `coloros-tools`.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

/// Unified error type for `coloros-tools` crates.
#[derive(Debug, Error)]
pub enum ToolError {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Parse error in {file} (line {line}): {message}")]
    Parse {
        file: PathBuf,
        line: usize,
        message: String,
    },

    #[error("Patch target not found: {0}")]
    TargetNotFound(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ToolError>;

/// ANSI terminal color codes matching the Python/Bash scripts in `bin/` and `functions.sh`.
pub mod color {
    pub const HEADER: &str = "\x1b[95m";
    pub const OKBLUE: &str = "\x1b[94m";
    pub const OKGREEN: &str = "\x1b[92m";
    pub const WARNING: &str = "\x1b[93m";
    pub const FAIL: &str = "\x1b[91m";
    pub const BOLD_BLUE: &str = "\x1b[1;34m";
    pub const BOLD_GREEN: &str = "\x1b[1;32m";
    pub const BOLD_YELLOW: &str = "\x1b[1;33m";
    pub const BOLD_RED: &str = "\x1b[1;31m";
    pub const ENDC: &str = "\x1b[0m";
}

/// Log an informational message with optional ANSI color.
pub fn log_colored(msg: &str, ansi_color: &str) {
    println!("{}{}{}", ansi_color, msg, color::ENDC);
}

pub fn log_info(msg: &str) {
    log_colored(msg, color::OKBLUE);
}

pub fn log_success(msg: &str) {
    log_colored(msg, color::OKGREEN);
}

pub fn log_warn(msg: &str) {
    log_colored(msg, color::WARNING);
}

pub fn log_error(msg: &str) {
    eprintln!("{}{}{}", color::FAIL, msg, color::ENDC);
}

/// Read a UTF-8 file (lossy fallback if non-UTF8 bytes exist) with detailed path context.
pub fn read_text_lossy(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Atomically write text content with Unix LF (`\n`) line endings.
pub fn write_text_lf(path: impl AsRef<Path>, content: &str) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|source| ToolError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    let normalized = content.replace("\r\n", "\n");
    let mut file = fs::File::create(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(normalized.as_bytes())
        .map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

/// Normalize path separators to forward slashes (`/`).
pub fn to_forward_slashes(path: &str) -> String {
    path.replace('\\', "/")
}

/// Collect files matching an extension under `root` (recursively or single-directory).
pub fn collect_files_with_ext(
    root: impl AsRef<Path>,
    ext: &str,
    recursive: bool,
) -> Vec<PathBuf> {
    let root = root.as_ref();
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let max_depth = if recursive { usize::MAX } else { 1 };
    let mut out: Vec<PathBuf> = WalkDir::new(root)
        .max_depth(max_depth)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case(ext))
                .unwrap_or(false)
        })
        .map(|e| e.into_path())
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_forward_slashes() {
        assert_eq!(to_forward_slashes(r"a\b\c"), "a/b/c");
    }
}
