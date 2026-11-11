## Project Context

fieldkit holds two Rust CLIs for coding agents that share one encrypted vault. apicli is curl-compatible. It adds per-host API credentials the agent never sees, enforces method and path rules, and rate limits per host. dbcli is its sibling for databases, compatible with psql, redis-cli, mongosh, cqlsh and clickhouse-client: named connections with stored passwords, read-only by default with per-command allow rules for Redis, MongoDB and Cassandra, and per-connection rate limits. dbcli is layered, and imports only point down: `shared` (config, context, messages, URL helpers, glob, statement splitting, TLS) has no dbcli imports, each engine module (`postgres`, `redis`, `mongo`, `cassandra`, `clickhouse`) owns its URL format and allow rules and imports only `shared`, `call` holds the `Engine` enum and dispatches to the engines, `commands` holds the subcommands, and `main` sits on top. Engines never import each other.

Each binary is its own package, `bin/apicli` and `bin/dbcli`, and lists only the dependencies it uses. `crates/common` holds what both share: the vault layout, admin password, audit log, rate limits, redaction, skill install and exit handling. The vault keeps the admin password, the log limit and every tool's secrets in a shared part, and one section per tool that only that tool parses; common keeps sections as raw JSON and knows no tool's types. Each binary owns its section in `config.rs` (dbcli's in `shared/config.rs`): its types load with secrets filled in by name, and saving writes the section without them and rebuilds that tool's secrets. Redaction uses every tool's secrets. apicli's `access` module and dbcli's engines decide what is allowed. `crates/vault` encrypts and stores whatever type the caller names. `bin/apicli/SKILL.md` and `bin/dbcli/SKILL.md` are compiled into the binaries and must match their behavior.

## Code

Keep code simple and direct. Do not write comments.

Never use `pub(crate)`. Manage visibility through module declarations and `pub use` re-exports in the parent module.

Import types and functions with `use` and refer to their short names.

## Test

Write tests only for security-critical code: refused flags, the one-URL rule, URL normalization, host binding, redirects, redaction, method overrides, proxies and rate limits, and for dbcli refused flags, backslash commands and Redis commands, connection URLs, the one-statement rule, read-only transactions, command classification and allow rules, refusing JavaScript in MongoDB expressions, and statement splitting. Do not add other tests unless asked.

The bypass suites are `bin/apicli/src/bypass.rs` and `bin/dbcli/src/bypass/`, one file per engine. They run each pipeline with test vaults and `Store::at` temp directories, apicli against local servers and dbcli against the servers in `DBCLI_TEST_POSTGRES`, `DBCLI_TEST_REDIS`, `DBCLI_TEST_MONGO`, `DBCLI_TEST_CASSANDRA` and `DBCLI_TEST_CLICKHOUSE`, URLs with the password in them. Without one, that engine's server tests skip. Tests must never touch fieldkit's data directory.

## Docs

`README.md` is the only documentation file. Keep it short, and update it when commands change.
