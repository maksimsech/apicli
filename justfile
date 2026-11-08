[positional-arguments]
d *args:
    cargo run --locked -p apicli -- "$@"

install:
    cargo install --locked --path bin/cli
