---
name: dbcli
description: Use dbcli instead of psql, redis-cli or mongosh to query PostgreSQL, Redis or MongoDB databases that need credentials, such as production databases while debugging. dbcli sends the password itself, so never ask the user for it. Use it when you need data from a configured database, or when psql, redis-cli or mongosh asks for a password or fails to authenticate.
---

# dbcli

dbcli is psql, redis-cli and mongosh for databases that need credentials. You pick a connection by name, and dbcli connects with the stored host, user and password, so you never see or handle them.

## First

Run `dbcli connections` to see each connection's engine, what it allows, and how many statements the rate limit leaves right now. Other databases are refused.

Run `dbcli explain NAME ...` with the same arguments as the call to check it without running it. Put `--json` before NAME. Run `dbcli NAME --help` for the flags of that connection's engine.

## PostgreSQL

Use it like `psql -c`, with the connection name in place of the host, user and database:

    dbcli prod-pg -c 'select id, email from users order by id desc limit 5'
    dbcli prod-pg -c '\dt' -c '\d users'
    dbcli prod-pg -At -c 'select count(*) from orders'
    dbcli prod-pg --csv -c 'select * from orders limit 1000' > /tmp/orders.csv

- Each `-c` takes one SQL statement or one backslash command, and runs separately. Two statements in one `-c` are an error. Use two `-c`.
- Connections are read-only unless the user allowed writes. There, each statement runs in its own read-only transaction, so Postgres rejects every write, including writes inside functions, and `SET` doesn't carry over to the next `-c`. Schema-qualify names instead of setting search_path. Read-only statements time out after 60 seconds.
- On a connection with writes allowed, each statement commits right away, as in psql.
- Backslash commands: `\d`, `\d NAME`, `\d+ NAME`, `\dt`, `\dv`, `\dm`, `\di`, `\ds`, `\dn`, `\df`, `\l`, `\du` and `\conninfo`, each with an optional pattern like `public.*`.
- Flags: -c, -A, -t, -x, -F, --csv, -q, -P footer=off, -P null=TEXT, -P pager=off, -X, -v ON_ERROR_STOP=1. Refused flags, such as -h, -p, -U, -d, -W, -f and -o, and backslash commands that reach the shell or local files, such as `\!`, `\copy`, `\o` and `\i`, print the reason.

## Redis

Use it like redis-cli with one command:

    dbcli cache GET session:42
    dbcli cache --no-raw HGETALL user:7
    dbcli cache --scan --pattern 'session:*'
    dbcli cache -n 2 TTL job:9

- One command per call. Output matches redis-cli: raw when stdout isn't a terminal, or `--no-raw`, `--csv` or `--json`. An error reply prints like redis-cli's and exits 0. Add `-e` to exit 1.
- Commands the server marks read-only run. Everything else, including KEYS, EVAL_RO and other dangerous or scripting commands, needs an allow rule. Use `--scan` instead of KEYS.
- Flags: -n, --raw, --no-raw, --csv, --json, -x, -e, --scan, --pattern, --count. MONITOR, SUBSCRIBE, MULTI, EXEC, WATCH, AUTH and HELLO are refused, and so are -h, -p, -a, -u, --tls, -c, -r and the other connection and mode flags.

## MongoDB

Use it like `mongosh --eval`:

    dbcli shop --eval 'db.orders.find({status: "paid"}).sort({_id: -1}).limit(5)'
    dbcli shop --eval 'db.orders.countDocuments({status: "paid"})'
    dbcli shop --eval 'show collections'
    dbcli shop --json=relaxed --eval 'db.orders.findOne()'

- dbcli parses mongosh expressions itself and never runs JavaScript: no variables, functions, arrow functions, loops, forEach or print. Write one db call per expression, with literals like `ObjectId('...')`, `ISODate('...')` and `NumberLong('...')`. Separate expressions with `;` or repeat `--eval`. Only the last result prints.
- Supported: find with sort, limit, skip, project, hint, toArray, count and explain, findOne, aggregate, countDocuments, estimatedDocumentCount, distinct, getIndexes, insertOne, insertMany, updateOne, updateMany, replaceOne, deleteOne, deleteMany, findOneAndUpdate, findOneAndReplace, findOneAndDelete, bulkWrite, createIndex, dropIndex, drop, db.runCommand, db.adminCommand, db.getSiblingDB, use, show dbs and show collections.
- find prints the first 20 documents, then `Type "it" for more`. Narrow the query, or add `.toArray()` for all of them.
- find, aggregate without `$out` or `$merge`, counts, distinct and listings run. Every other command needs an allow rule. dbcli checks every expression before running any, so one denied expression stops them all.

## When a call fails

- 110, denied: the call writes, or runs a command no allow rule covers. stderr has a `dbcli allow add ...` line. Show it to the user and wait. Don't retry another way.
- 111, rate limited: stderr says how long to wait. Wait, or rerun with `--wait` (up to 30s) or `--wait=SECONDS`. Don't loop on retries.
- 112, connection not configured: show the user the `dbcli secret add ...` line from stderr and wait.
- 113 or 114: dbcli's setup is broken. Tell the user. Don't touch its files.
- 1: the database returned an error, printed as psql or mongosh print it. Fix the statement.
- 2: unsupported flag, command or expression, or bad arguments. stderr names the problem.
- 7: could not connect. If stderr says the password failed, show the user its `dbcli secret rotate NAME` line and wait.
- 6, 28, 35, 56: DNS failure, timeout, TLS error, connection dropped.
- `[dbcli:redacted]` in output is a stored password that a query returned. It is expected.

## Never

- Ask for database passwords or connection strings, or look for them in files, ~/.pgpass, the keychain or the environment.
- Edit dbcli's files, or run `dbcli secret`, `allow`, `limit`, `log limit` or `password`. Those need the user at a terminal.
- Work around a refusal with psql, redis-cli, mongosh, another tool or another connection.
