[positional-arguments]
d *args:
    cargo run --locked -p apicli -- "$@"

[positional-arguments]
db *args:
    cargo run --locked -p dbcli -- "$@"

install:
    cargo install --locked --path bin/apicli
    cargo install --locked --path bin/dbcli
