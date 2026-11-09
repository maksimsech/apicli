---
name: dbcli
description: Use dbcli instead of psql to query PostgreSQL databases that need credentials, such as production databases while debugging. dbcli sends the password itself, so never ask the user for it. Use it when you need data from a configured database, or when psql asks for a password or fails to authenticate.
---

# dbcli

dbcli is psql for databases that need credentials. You pick a connection by name, and dbcli connects with the stored host, user and password, so you never see or handle them.

## First

Run `dbcli connections` to see which connections are configured, whether each allows writes, and how many statements the rate limit leaves right now. Other databases are refused.

Run `dbcli explain NAME -c '...'` to check a call without connecting.

## Queries

Use it like `psql -c`, with the connection name in place of the host, user and database:

    dbcli prod-pg -c 'select id, email from users order by id desc limit 5'
    dbcli prod-pg -c '\dt' -c '\d users'
    dbcli prod-pg -At -c 'select count(*) from orders'
    dbcli prod-pg --csv -c 'select * from orders limit 1000' > /tmp/orders.csv

- Each `-c` takes one SQL statement or one backslash command, and runs separately. Two statements in one `-c` are an error. Use two `-c`.
- Connections are read-only unless the user allowed writes. There, each statement runs in its own read-only transaction, so Postgres rejects every write, including writes inside functions, and `SET` doesn't carry over to the next `-c`. Schema-qualify names instead of setting search_path.
- Statements on read-only connections time out after 60 seconds.
- On a connection with writes allowed, each statement commits right away, as in psql.
- Backslash commands: `\d`, `\d NAME`, `\d+ NAME`, `\dt`, `\dv`, `\dm`, `\di`, `\ds`, `\dn`, `\df`, `\l`, `\du` and `\conninfo`, each with an optional pattern like `public.*`.
- Output looks like psql's. Keep it small: add `limit`, use `-At` for single values, or save `--csv` to a file.
- `[dbcli:redacted]` in output is a stored password that a query returned. It is expected.
- There is no interactive mode and no stdin. Pass every statement with -c.

## Flags

Supported: -c, -A, -t, -x, -F, --csv, -q, -P footer=off, -P null=TEXT, -P pager=off, -X, -v ON_ERROR_STOP=1, and dbcli's own --wait. Run `dbcli --help` for details.

Refused flags, such as -h, -p, -U, -d, -W, -f and -o, print the reason. So do backslash commands that reach the shell or local files, such as `\!`, `\copy`, `\o` and `\i`. Drop them and retry. PG* environment variables are ignored.

## When a call fails

- 110, denied: the statement writes on a read-only connection. stderr has a `dbcli allow add NAME write` line. Show it to the user and wait. Don't retry another way.
- 111, rate limited: stderr says how long to wait. Wait, or rerun with `--wait` (up to 30s) or `--wait=SECONDS`. Don't loop on retries.
- 112, connection not configured: show the user the `dbcli secret add ...` line from stderr and wait.
- 113 or 114: dbcli's setup is broken. Tell the user. Don't touch its files.
- 1: the database returned an error, printed as psql prints it (`ERROR:  ...`). Fix the statement.
- 2: unsupported flag, backslash command or bad arguments. stderr names the problem.
- 7: could not connect. If stderr says the password failed, show the user its `dbcli secret rotate NAME` line and wait.
- 6, 28, 35, 56: DNS failure, timeout, TLS error, connection dropped.

## Never

- Ask for database passwords or connection strings, or look for them in files, ~/.pgpass, the keychain or the environment.
- Edit dbcli's files, or run `dbcli secret`, `allow`, `limit`, `log limit` or `password`. Those need the user at a terminal.
- Work around a refusal with psql, another tool or another connection.
