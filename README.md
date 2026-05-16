# secret-mask

[![crates.io](https://img.shields.io/crates/v/secret-mask.svg)](https://crates.io/crates/secret-mask)

Mask known secret patterns in log lines before they hit stdout. Catches
Stripe/Anthropic API keys, GitHub PATs, Slack tokens, AWS access keys,
JWTs.

```rust
use secret_mask::mask;
let s = mask("authorization: Bearer sk-live-AAAABBBBCCCCDDDDEEEE");
```

Zero deps. MIT or Apache-2.0.
