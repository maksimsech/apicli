# fieldkit

Command-line tools that let coding agents use real APIs and databases without ever seeing the credentials.

- [apicli](#apicli) is curl for APIs that need credentials.
- [dbcli](#dbcli) is psql, redis-cli, mongosh, cqlsh and clickhouse-client for databases that need credentials.

Both share one encrypted vault, admin password and log.

## Install

Needs Rust 1.89 or newer. Run the same command again to upgrade.

```sh
cargo install --locked --git https://github.com/maksimsech/fieldkit
```

## apicli

apicli adds the API key for each host itself, so your agent can call real APIs without ever seeing the key. Requests are read-only by default, writes are allowed per path, and each host can have a rate limit.

### Set up

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

### Use

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

dbcli keeps the password for each named connection, so your agent can query real databases without ever seeing it.

```sh
dbcli secret add prod-pg --url 'postgres://agent@db.example.com:5432/app?sslmode=require'
dbcli secret add cache --url 'rediss://agent@cache.example.com:6380/0'
dbcli secret add shop --url 'mongodb://agent@db.example.com:27017/shop?authSource=admin'
dbcli secret add events --url 'cassandra://agent@10.0.0.1,10.0.0.2:9042/shop?tls=true'
dbcli secret add metrics --url 'clickhouse://agent@ch.example.com:8443/default?secure=true'
dbcli skill install --agent claude
dbcli connections
```

You type the password at a prompt. ClickHouse URLs take the HTTP port. TLS certificates are always verified. For a private CA, add `sslrootcert=PATH`, `tlsCAFile=PATH` or `cacert=PATH` to the URL.

After the connection name come the engine's own flags. `dbcli NAME --help` lists them.

```sh
dbcli prod-pg -c 'select id, email from users limit 5' -c '\d users'
dbcli cache GET session:42
dbcli shop --eval 'db.orders.find({status: "paid"}).limit(5)'
dbcli events -e 'SELECT * FROM shop.orders WHERE id = 42'
dbcli metrics -q 'SELECT count() FROM events'
```

Connections are read-only by default:

- Postgres runs each statement in its own read-only transaction, so Postgres itself rejects writes.
- Redis runs the commands the server marks read-only, except dangerous and scripting ones like KEYS and EVAL_RO.
- MongoDB runs finds, counts, listings and aggregations without `$out` or `$merge`. dbcli parses mongosh expressions itself and never runs JavaScript.
- Cassandra runs SELECT, LIST, DESCRIBE and USE.
- ClickHouse runs each statement with `readonly=1`, so the server rejects writes.

Writes and limits are opt-in:

```sh
dbcli allow add prod-pg write
dbcli allow add cache SET 'cache:*'     # every key the command touches must match
dbcli allow add cache 'CONFIG|GET'      # a command without keys takes no glob
dbcli allow add shop insert 'shop.*'    # a command and a namespace glob
dbcli allow add events INSERT 'shop.*'  # a statement keyword and a table glob
dbcli allow add metrics write
dbcli limit set prod-pg 30/min
```

For limits on Postgres and ClickHouse tables, give the connection a database user with only the grants it needs. `dbcli --help` lists every command.

## What it protects

- Each key is sent only to the host it was added for, redirects included. It's masked in `-v` output and in responses that echo it back. Database passwords go only to the connection's host and are masked the same way.
- Changing secrets, rules or limits through apicli or dbcli needs a terminal and the admin password. Set one: without it, an agent can open a terminal of its own (with `script`, for example) and change them.
- Keys and rules are stored encrypted, but the encryption key is a file in fieldkit's data folder. An agent that goes looking for it can read the keys and rewrite the rules, so apicli and dbcli protect against mistakes and prompt injection, not against a determined agent.
