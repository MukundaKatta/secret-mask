use secret_mask::{has_secret, mask, REPLACEMENT};

#[test]
fn masks_anthropic_style_key() {
    let s = "Authorization: Bearer sk-live-AAAABBBBCCCCDDDDEEEEFFFF";
    let out = mask(s);
    assert!(out.contains(REPLACEMENT));
    assert!(!out.contains("sk-live-AAAA"));
}

#[test]
fn masks_github_pat() {
    let s = "token=ghp_aaaabbbbccccddddeeeeFFFFGGGGHHHHIIII";
    let out = mask(s);
    assert!(out.contains(REPLACEMENT));
}

#[test]
fn masks_aws_access_key() {
    let s = "id=AKIAIOSFODNN7EXAMPLE";
    let out = mask(s);
    assert!(out.contains(REPLACEMENT));
}

#[test]
fn masks_jwt() {
    let s =
        "auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let out = mask(s);
    assert!(out.contains(REPLACEMENT));
}

#[test]
fn clean_text_unchanged() {
    let s = "no secrets here at all";
    assert_eq!(mask(s), s);
    assert!(!has_secret(s));
}

#[test]
fn has_secret_flags_dirty_string() {
    assert!(has_secret("ghp_aaaabbbbccccddddeeeeFFFFGGGG"));
}

#[test]
fn has_secret_handles_multibyte_utf8() {
    // Non-ASCII characters must not cause a panic (slicing on a
    // non-char-boundary) and a trailing secret must still be detected.
    assert!(has_secret("héllo wörld ghp_aaaabbbbccccddddeeeeFFFFGGGG"));
    assert!(!has_secret("héllo wörld — no secrets ☃"));
}

#[test]
fn mask_handles_multibyte_utf8() {
    let masked = mask("café ghp_aaaabbbbccccddddeeeeFFFFGGGG ☃");
    assert!(masked.contains(REPLACEMENT));
    assert!(masked.starts_with("café "));
    assert!(masked.ends_with(" ☃"));
    // Clean unicode is returned unchanged.
    assert_eq!(mask("naïve résumé ☕"), "naïve résumé ☕");
}
