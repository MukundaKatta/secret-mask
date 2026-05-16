//! # secret-mask
//!
//! Mask known secret patterns in log lines before they reach a sink.
//!
//! Detects:
//!
//! - `sk-…`, `sk_live_…`, `sk_test_…`, `rk_live_…` — Stripe-style /
//!   Anthropic-style API keys
//! - `ghp_…`, `github_pat_…` — GitHub PATs
//! - `xoxb-…`, `xoxp-…` — Slack tokens
//! - `AKIA…` + `[A-Z0-9]{16}` — AWS access key IDs
//! - JWTs (`eyJ…<base64.base64.base64>`) — generic
//!
//! Each secret is replaced with the literal `[REDACTED]`. Bring the
//! input bytes; get the masked string back.
//!
//! ## Example
//!
//! ```
//! use secret_mask::mask;
//! let masked = mask("authorization: Bearer sk-live-AAAABBBBCCCCDDDD1234");
//! assert!(!masked.contains("sk-live-AAAABBBBCCCCDDDD1234"));
//! assert!(masked.contains("[REDACTED]"));
//! ```

#![deny(missing_docs)]

/// Token written into the masked positions.
pub const REPLACEMENT: &str = "[REDACTED]";

/// Mask any secrets found in `s`.
pub fn mask(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(end) = match_secret(s, i) {
            out.push_str(REPLACEMENT);
            i = end;
        } else {
            let c = s[i..].chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

/// True when `s` contains any secret pattern.
pub fn has_secret(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if match_secret(s, i).is_some() {
            return true;
        }
        i += 1;
    }
    false
}

fn match_secret(s: &str, i: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let rest = &s[i..];

    // Prefixed API keys (sk-, sk_live_, etc.) — greedy alnum/_/-
    let prefixes: &[&str] = &[
        "sk-", "sk_live_", "sk_test_", "rk_live_", "ghp_", "github_pat_", "xoxb-", "xoxp-",
    ];
    for p in prefixes {
        if rest.starts_with(p) {
            let mut end = i + p.len();
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
            {
                end += 1;
            }
            if end - (i + p.len()) >= 16 {
                return Some(end);
            }
        }
    }

    // AWS access key: "AKIA" + 16 uppercase alnum
    if rest.starts_with("AKIA") {
        let after = i + 4;
        if after + 16 <= bytes.len() {
            let tail = &bytes[after..after + 16];
            if tail.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
                return Some(after + 16);
            }
        }
    }

    // JWT: "eyJ" + base64ish.base64ish.base64ish
    if rest.starts_with("eyJ") {
        let mut end = i;
        let mut dots = 0;
        while end < bytes.len() {
            let c = bytes[end];
            if c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-') {
                if c == b'.' {
                    dots += 1;
                }
                end += 1;
            } else {
                break;
            }
        }
        if dots >= 2 && end - i >= 20 {
            return Some(end);
        }
    }

    None
}
