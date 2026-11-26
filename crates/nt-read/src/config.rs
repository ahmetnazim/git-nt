use crate::error::ReadError;

/// Default mainline ref for Layer 1 Trusted Tree hydration.
pub const DEFAULT_TRUSTED_REF: &str = "refs/heads/main";

/// Repository Layer 1 Trust Gate configuration loaded from local Git config (`nt.*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustConfig {
    /// Trusted mainline ref whose Git tree supplies `.nt/ns/` tombstones.
    pub trusted_ref: String,
    /// When `true`, every hydrated tombstone's introducing/last-modifying commit on
    /// `trusted_ref` MUST carry a valid GPG/SSH signature.
    pub require_signed: bool,
    /// When `true`, GPG good signatures with unknown trust (`%G? == 'U'`) are accepted
    /// alongside `'G'`. Defaults to `false` (`'G'` only).
    pub allow_untrusted_gpg_trust: bool,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            trusted_ref: DEFAULT_TRUSTED_REF.to_owned(),
            require_signed: false,
            allow_untrusted_gpg_trust: false,
        }
    }
}

/// Validates a Git ref name (or full commit OID) per `git-check-ref-format(1)` rules,
/// rejecting option prefixes, revision ranges (`..`), revlog/ancestry expressions (`~`, `^`,
/// `@{`, `:`), globs (`?`, `*`, `[`), backslashes, and whitespace/control characters.
pub fn validate_ref_name(ref_name: &str) -> Result<(), ReadError> {
    if ref_name.is_empty() {
        return Err(ReadError::InvalidRef {
            ref_name: ref_name.to_owned(),
            reason: "ref name must not be empty",
        });
    }
    if ref_name.starts_with('-') {
        return Err(ReadError::InvalidRef {
            ref_name: ref_name.to_owned(),
            reason: "ref name must not start with '-'",
        });
    }
    if ref_name == "@" {
        return Err(ReadError::InvalidRef {
            ref_name: ref_name.to_owned(),
            reason: "standalone '@' is not a valid ref name",
        });
    }
    if ref_name.starts_with('/') || ref_name.ends_with('/') || ref_name.ends_with('.') {
        return Err(ReadError::InvalidRef {
            ref_name: ref_name.to_owned(),
            reason: "ref name must not start/end with '/' or end with '.'",
        });
    }
    if ref_name.contains("..") || ref_name.contains("@{") || ref_name.contains("//") {
        return Err(ReadError::InvalidRef {
            ref_name: ref_name.to_owned(),
            reason: "ref name must not contain '..', '@{', or '//'",
        });
    }
    if ref_name.chars().any(|c| {
        c.is_control() || c.is_whitespace() || matches!(c, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
    }) {
        return Err(ReadError::InvalidRef {
            ref_name: ref_name.to_owned(),
            reason: "ref name contains forbidden Git revision or control characters",
        });
    }
    for component in ref_name.split('/') {
        if component.is_empty() || component.starts_with('.') || component.ends_with(".lock") {
            return Err(ReadError::InvalidRef {
                ref_name: ref_name.to_owned(),
                reason: "ref component must not be empty, start with '.', or end with '.lock'",
            });
        }
    }
    Ok(())
}

/// Validates a full 40-char (SHA-1) or 64-char (SHA-256) lowercase hexadecimal commit OID.
pub fn validate_commit_oid(oid: &str) -> Result<(), ReadError> {
    if !matches!(oid.len(), 40 | 64) || !oid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ReadError::InvalidRef {
            ref_name: oid.to_owned(),
            reason: "expected a full lowercase hexadecimal Git commit OID (40 or 64 chars)",
        });
    }
    Ok(())
}
