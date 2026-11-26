use crate::error::CoreError;

/// Validates and normalizes a repo-relative POSIX file path.
///
/// Rejects empty paths, leading `/` (absolute paths), trailing `/`, backslashes (`\`),
/// Windows drive prefixes, NUL/control characters, empty segments (`//`), and `.` or `..`
/// traversal segments. Leading `./` prefixes are stripped when followed by a valid path.
pub fn normalize_repo_path(raw: &str) -> Result<String, CoreError> {
    if raw.is_empty() {
        return Err(CoreError::InvalidPath {
            path: raw.to_owned(),
            reason: "path must not be empty",
        });
    }
    if raw.chars().any(char::is_control) {
        return Err(CoreError::InvalidPath {
            path: raw.to_owned(),
            reason: "path must not contain NUL or control characters",
        });
    }
    if raw.contains('\\') {
        return Err(CoreError::InvalidPath {
            path: raw.to_owned(),
            reason: "backslashes are forbidden; use POSIX '/' separators",
        });
    }
    if raw.starts_with('/') {
        return Err(CoreError::InvalidPath {
            path: raw.to_owned(),
            reason: "absolute paths are forbidden",
        });
    }
    if raw.ends_with('/') {
        return Err(CoreError::InvalidPath {
            path: raw.to_owned(),
            reason: "trailing slash is forbidden",
        });
    }
    let mut stripped = raw;
    while let Some(rest) = stripped.strip_prefix("./") {
        stripped = rest;
    }
    if stripped.is_empty() {
        return Err(CoreError::InvalidPath {
            path: raw.to_owned(),
            reason: "path resolves to empty",
        });
    }

    let stripped_bytes = stripped.as_bytes();
    if stripped_bytes.len() >= 2
        && stripped_bytes[0].is_ascii_alphabetic()
        && stripped_bytes[1] == b':'
    {
        return Err(CoreError::InvalidPath {
            path: raw.to_owned(),
            reason: "drive-prefixed paths are forbidden",
        });
    }

    for segment in stripped.split('/') {
        if segment.is_empty() {
            return Err(CoreError::InvalidPath {
                path: raw.to_owned(),
                reason: "empty path segment ('//') is forbidden",
            });
        }
        if segment == "." || segment == ".." {
            return Err(CoreError::InvalidPath {
                path: raw.to_owned(),
                reason: "'.' and '..' traversal segments are forbidden",
            });
        }
    }

    Ok(stripped.to_owned())
}

/// Validates, normalizes, lexicographically sorts, and deduplicates a non-empty list of paths.
pub fn normalize_repo_paths<I, S>(paths: I) -> Result<Vec<String>, CoreError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = Vec::new();
    for path in paths {
        out.push(normalize_repo_path(path.as_ref())?);
    }
    if out.is_empty() {
        return Err(CoreError::EmptyFiles);
    }
    out.sort();
    out.dedup();
    Ok(out)
}
