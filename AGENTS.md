## Project Context

apicli is a curl-compatible Rust CLI for coding agents. It adds per-host API credentials the agent never sees, enforces method and path rules, and rate limits per host. The binary lives in `bin/cli`. `bin/cli/skill/SKILL.md` is compiled into it and must match its behavior.

## Code

Keep code simple and direct. Do not write comments.

Never use `pub(crate)`. Manage visibility through module declarations and `pub use` re-exports in the parent module.

Import types and functions with `use` and refer to their short names.

## Test

Write tests only for security-critical code: refused flags, the one-URL rule, URL normalization, host binding, redirects, redaction, method overrides, proxies and rate limits. Do not add other tests unless asked.

The bypass suite is `bin/cli/src/bypass.rs`. It runs the request pipeline against local servers with test vaults and `Store::at` temp directories. Tests must never touch apicli's data directory.

## Docs

`README.md` is the only documentation file. Keep it short, and update it when commands change.
