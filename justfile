[positional-arguments]
d *args:
    cargo run --locked -p apicli --bin apicli -- "$@"

[positional-arguments]
db *args:
    cargo run --locked -p apicli --bin dbcli -- "$@"

install:
    cargo install --locked --path bin/cli
