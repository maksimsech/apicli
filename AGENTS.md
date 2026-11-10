## Project Context

apicli is a curl-compatible Rust CLI for coding agents. It adds per-host API credentials the agent never sees, enforces method and path rules, and rate limits per host. dbcli is its sibling for databases, compatible with psql, redis-cli, mongosh, cqlsh and clickhouse-client: named connections with stored passwords, read-only by default with per-command allow rules for Redis, MongoDB and Cassandra, and per-connection rate limits. dbcli is layered, and imports only point down: `shared` (context, messages, URL helpers, glob, statement splitting, TLS) has no dbcli imports, each engine module (`postgres`, `redis`, `mongo`, `cassandra`, `clickhouse`) owns its URL format and allow rules and imports only `shared`, `call` holds the `Engine` enum and dispatches to the engines, `commands` holds the subcommands, and `main` sits on top. Engines never import each other.

Both binaries come from the package in `bin/cli`: `src/bin/apicli`, `src/bin/dbcli`, and shared code in `src/lib.rs`. `crates/policy` holds the stored model and apicli's rules. `crates/vault` encrypts and stores whatever type the caller names, and does not depend on policy. Neither crate knows about database engines: policy keeps a connection as its URL text, write flag and allow rules. Inside policy, `api` and `db` hold the per-kind types, `vault` (the stored model and its lookups) sits above them, and `access` (authorize) sits on top. `bin/cli/skill/apicli/SKILL.md` and `bin/cli/skill/dbcli/SKILL.md` are compiled into the binaries and must match their behavior.

## Code

Keep code simple and direct. Do not write comments.

Never use `pub(crate)`. Manage visibility through module declarations and `pub use` re-exports in the parent module.

Import types and functions with `use` and refer to their short names.

## Test

Write tests only for security-critical code: refused flags, the one-URL rule, URL normalization, host binding, redirects, redaction, method overrides, proxies and rate limits, and for dbcli refused flags, backslash commands and Redis commands, connection URLs, the one-statement rule, read-only transactions, command classification and allow rules, refusing JavaScript in MongoDB expressions, and statement splitting. Do not add other tests unless asked.

The bypass suites are `bin/cli/src/bin/apicli/bypass.rs` and `bin/cli/src/bin/dbcli/bypass/`, one file per engine. They run each pipeline with test vaults and `Store::at` temp directories, apicli against local servers and dbcli against the servers in `DBCLI_TEST_POSTGRES`, `DBCLI_TEST_REDIS`, `DBCLI_TEST_MONGO`, `DBCLI_TEST_CASSANDRA` and `DBCLI_TEST_CLICKHOUSE`, URLs with the password in them. Without one, that engine's server tests skip. Tests must never touch apicli's data directory.

## Docs

`README.md` is the only documentation file. Keep it short, and update it when commands change.
