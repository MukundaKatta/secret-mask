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
    let s = "auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
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
