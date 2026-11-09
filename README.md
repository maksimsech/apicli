# apicli

curl for APIs that need credentials, built for coding agents.

apicli adds the API key for each host itself, so your agent can call real APIs without ever seeing the key. Requests are read-only by default, writes are allowed per path, and each host can have a rate limit.

The same install gives you [dbcli](#dbcli), which does the same for PostgreSQL.

## Install

Needs Rust 1.89 or newer. Run the same command again to upgrade.

```sh
cargo install --locked --git https://github.com/maksimsech/apicli
```

## Set up

```sh
apicli secret add github --host api.github.com --header 'Authorization: Bearer {secret}'
apicli password set                  # needed to change secrets, rules and limits
apicli skill install --agent claude  # or codex, opencode, or --path DIR
```

You type the secret at a prompt. It never goes on the command line.

If some endpoints take a different credential, add it for those paths only:

```sh
apicli secret add example     --host api.example.com --header 'Authorization: Bearer {secret}'
apicli secret add example-key --host api.example.com --path '/v1/reports/**' --header 'X-API-Key: {secret}'
```

A request gets the first secret whose `--path` matches, or the host's secret without `--path`. Each redirect is matched again. `apicli explain GET URL` shows which secret a request gets.

## Use

```sh
apicli https://api.github.com/user
apicli hosts
```

Configured hosts allow GET, HEAD and OPTIONS. Everything else is opt-in:

```sh
apicli allow add api.github.com POST '/repos/*/*/issues/*/comments'
apicli limit set api.github.com 60/min
apicli log
```

`apicli --help` lists every command.

## dbcli

psql for databases that need credentials. It works with PostgreSQL for now, and shares apicli's vault, admin password and log.

```sh
dbcli secret add prod-pg --url 'postgres://agent@db.example.com:5432/app?sslmode=require'
dbcli skill install --agent claude
dbcli prod-pg -c 'select id, email from users limit 5' -c '\d users'
dbcli connections
```

You type the password at a prompt. TLS certificates are always verified, add `sslrootcert=PATH` to the URL for a private CA.

Connections are read-only: each statement runs in its own read-only transaction, so Postgres itself rejects writes. Writes and limits are opt-in:

```sh
dbcli allow add prod-pg write
dbcli limit set prod-pg 30/min
```

For limits on tables, give the connection a database user with only the grants it needs. `dbcli --help` lists every command.

## What it protects

- Each key is sent only to the host it was added for, redirects included. It's masked in `-v` output and in responses that echo it back. Database passwords go only to the connection's host and are masked the same way.
- Changing secrets, rules or limits through apicli or dbcli needs a terminal and the admin password. Set one: without it, an agent can open a terminal of its own (with `script`, for example) and change them.
- Keys and rules are stored encrypted, but the encryption key is a file in apicli's data folder. An agent that goes looking for it can read the keys and rewrite the rules, so apicli and dbcli protect against mistakes and prompt injection, not against a determined agent.
