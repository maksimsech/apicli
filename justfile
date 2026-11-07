identity := env("APICLI_SIGN_IDENTITY", "apicli local")

[positional-arguments]
d *args:
    cargo run --locked -p cli -- "$@"

install:
    cargo install --locked --path bin/cli
    codesign --force --options runtime --identifier dev.apicli --sign "{{identity}}" ~/.cargo/bin/apicli
