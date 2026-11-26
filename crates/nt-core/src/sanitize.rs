use std::sync::OnceLock;

use regex_lite::Regex;

/// Maximum Unicode scalar values permitted per sanitized free-text field.
pub const MAX_FIELD_SCALARS: usize = 240;

fn re_triple_backticks() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"`{3,}").expect("valid regex"))
}

/// Unconditional XML boundary tags:
/// 1. Any closing boundary tag `</...>` (case-insensitive)
/// 2. Any opening boundary tag with attributes (`\s[^>]*`) or self-closing (`/`) (case-insensitive)
/// 3. Any non-generic harness tag (`tool_result`, `tool_output`, `function_results`, `antml:*`, `nt_data`)
///    in any case, bare or attributed
fn re_unconditional_boundary_tag() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)</(?:system|assistant|user|instructions?|prompt|tool_result|tool_output|function_results?|antml:[a-z_]+|nt_data)(?:\s[^>]*)?>|(?i)<(?:system|assistant|user|instructions?|prompt|tool_result|tool_output|function_results?|antml:[a-z_]+|nt_data)(?:/|\s[^>]*)>|(?i)<(?:tool_result|tool_output|function_results?|antml:[a-z_]+|nt_data)>",
        )
        .expect("valid regex")
    })
}

/// Bare single-word boundary tags (`<system>`, `<USER>`, `<Assistant>`, etc.).
/// Checked against the immediately preceding byte so PascalCase Rust generics
/// (`Option<User>`, `Arc<System>`) stay intact while `x<SYSTEM>`, `<SYSTEM><SYSTEM>`,
/// `x<system>`, and standalone `<User>` are all redacted.
fn re_bare_generic_named_tag() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)<(?:system|assistant|user|instructions?|prompt)>").expect("valid regex")
    })
}

fn re_spotlight_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:<<<\s*NT_DATA_|>>>\s*END_NT_DATA_)").expect("valid regex")
    })
}

fn re_private_key() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").expect("valid regex"))
}

fn re_secret() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bglpat-[A-Za-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}\b|\bBearer\s+[A-Za-z0-9._~+/=-]{16,}|(?i:\bAuthorization:\s*Basic\s+[A-Za-z0-9+/=]{8,})",
        )
        .expect("valid regex")
    })
}

fn re_url() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)https?://\S+").expect("valid regex"))
}

fn re_download_cmd() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(?:curl|wget)\b").expect("valid regex"))
}

fn re_shell_pipe() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\|\s*(?:sh|bash|zsh|dash|python3?|perl|ruby|node)\b").expect("valid regex")
    })
}

fn is_stealth_or_control(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{034F}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{E0000}'..='\u{E007F}'
                | '\u{E0100}'..='\u{E01EF}'
        )
}

fn strip_control_and_stealth(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut collapsed_ws = false;
    for ch in input.chars() {
        if matches!(ch, '\r' | '\n' | '\t' | '\u{2028}' | '\u{2029}') {
            if !collapsed_ws && !out.ends_with(' ') {
                out.push(' ');
            }
            collapsed_ws = true;
        } else if ch == ' ' && collapsed_ws {
            // Avoid emitting duplicate spaces around collapsed line breaks/tabs.
        } else if !is_stealth_or_control(ch) {
            out.push(ch);
            collapsed_ws = false;
        }
    }
    out
}

fn is_pascal_case_type_tag(tag: &str) -> bool {
    matches!(
        tag,
        "<System>" | "<Assistant>" | "<User>" | "<Instruction>" | "<Instructions>" | "<Prompt>"
    )
}

fn redact_bare_boundary_tags(input: &str) -> String {
    let re = re_bare_generic_named_tag();
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last_end = 0;

    for m in re.find_iter(input) {
        let preceded_by_ident = m.start() > 0 && {
            let prev = bytes[m.start() - 1];
            prev.is_ascii_alphanumeric() || prev == b'_' || prev == b':'
        };

        out.push_str(&input[last_end..m.start()]);
        if preceded_by_ident && is_pascal_case_type_tag(m.as_str()) {
            // Preserve legitimate PascalCase generic type parameter (e.g., Option<User>, Arc<System>).
            out.push_str(m.as_str());
        } else {
            out.push_str("[REDACTED_TAG]");
        }
        last_end = m.end();
    }

    out.push_str(&input[last_end..]);
    out
}

/// Returns `true` if `input` matches any anchored credential or private-key pattern
/// (after stripping invisible stealth/control characters so split-token smuggling is caught).
pub fn contains_secret(input: &str) -> bool {
    let cleaned = strip_control_and_stealth(input);
    re_private_key().is_match(&cleaned) || re_secret().is_match(&cleaned)
}

fn sanitize_pass(input: &str) -> String {
    let step1 = strip_control_and_stealth(input);
    let step2 = re_triple_backticks().replace_all(&step1, "'''");
    let step3 = re_unconditional_boundary_tag().replace_all(&step2, "[REDACTED_TAG]");
    let step4 = redact_bare_boundary_tags(&step3);
    let step5 = re_spotlight_marker().replace_all(&step4, "[REDACTED_MARKER]");
    let step6 = re_private_key().replace_all(&step5, "[REDACTED_SECRET]");
    let step7 = re_secret().replace_all(&step6, "[REDACTED_SECRET]");
    let step8 = re_url().replace_all(&step7, "[REDACTED_URL]");
    let step9 = re_download_cmd().replace_all(&step8, "[REDACTED_CMD]");
    let step10 = re_shell_pipe().replace_all(&step9, "[REDACTED_PIPE]");
    step10.trim().to_owned()
}

/// Deterministically sanitizes a free-text field for Layer 2 defense-in-depth.
///
/// Guarantees:
/// - Strips ASCII/Unicode control chars, Bidi overrides/isolates, zero-width chars,
///   Unicode Tag smuggling (`U+E0000..=U+E007F`), and Variation Selectors (`U+FE00..=U+FE0F`,
///   `U+E0100..=U+E01EF`), collapsing line/paragraph separators and tabs to single spaces.
/// - Preserves benign code syntax (`<`, `>`, single backticks, generics like `Vec<u8>` /
///   `Option<User>`, operators `->`, `=>`, `<=`, and hyphenated words like `task-queue`).
/// - Neutralizes triple backticks, outer LLM/tool XML boundary tags, and spotlight marker prefixes.
/// - Redacts URLs, shell download/exec chains, and anchored credential patterns via `regex-lite`.
/// - Caps output to `<= 240` Unicode scalar values and is strictly idempotent:
///   `sanitize_field(&sanitize_field(s)) == sanitize_field(s)`.
pub fn sanitize_field(input: &str) -> String {
    let mut current = sanitize_pass(input);

    // Truncate to <= MAX_FIELD_SCALARS Unicode scalar values, then iterate to fixed point
    // in case truncation exposes a new boundary match (e.g., cutting a token at scalar 240).
    for _ in 0..4 {
        let truncated: String = current.chars().take(MAX_FIELD_SCALARS).collect();
        let trimmed = truncated.trim_end().to_owned();
        let next = sanitize_pass(&trimmed);
        let next_truncated: String = next.chars().take(MAX_FIELD_SCALARS).collect();
        let next_trimmed = next_truncated.trim_end().to_owned();
        if next_trimmed == trimmed {
            return trimmed;
        }
        current = next_trimmed;
    }

    current
}
