## Project Context

apicli is a curl-compatible Rust CLI for coding agents. It adds per-host API credentials the agent never sees, enforces method and path rules, and rate limits per host. dbcli is its psql-compatible sibling for PostgreSQL: named connections with stored passwords, read-only transactions by default, and per-connection rate limits.

Both binaries come from the package in `bin/cli`: `src/bin/apicli`, `src/bin/dbcli`, and shared code in `src/lib.rs`. Rules, connections and redaction live in `crates/policy`, storage in `crates/vault`. `bin/cli/skill/apicli/SKILL.md` and `bin/cli/skill/dbcli/SKILL.md` are compiled into the binaries and must match their behavior.

## Code

Keep code simple and direct. Do not write comments.

Never use `pub(crate)`. Manage visibility through module declarations and `pub use` re-exports in the parent module.

Import types and functions with `use` and refer to their short names.

## Test

Write tests only for security-critical code: refused flags, the one-URL rule, URL normalization, host binding, redirects, redaction, method overrides, proxies and rate limits, and for dbcli refused flags and backslash commands, connection URLs, the one-statement rule and read-only transactions. Do not add other tests unless asked.

The bypass suites are `bin/cli/src/bin/apicli/bypass.rs` and `bin/cli/src/bin/dbcli/bypass.rs`. They run each pipeline with test vaults and `Store::at` temp directories, apicli against local servers and dbcli against the Postgres in `DBCLI_TEST_POSTGRES`, a URL with the password in it. Without it the dbcli server tests skip. Tests must never touch apicli's data directory.

## Docs

`README.md` is the only documentation file. Keep it short, and update it when commands change.
