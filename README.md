# apicli

curl for APIs that need credentials, built for coding agents.

apicli adds the API key for each host itself, so your agent can call real APIs without ever seeing the key. Requests are read-only by default, writes are allowed per path, and each host can have a rate limit.

## Install

Needs Rust 1.89 or newer. Run the same command again to upgrade.

```sh
cargo install --locked --git https://github.com/maksimsech/apicli
```

On macOS, sign the binary so the Keychain keeps trusting it after upgrades. Create a certificate once (Keychain Access → Certificate Assistant → Create a Certificate, name `apicli local`, type Code Signing), then run this after each install:

```sh
codesign --force --options runtime --identifier dev.apicli --sign "apicli local" ~/.cargo/bin/apicli
```

## Set up

```sh
apicli secret add github --host api.github.com --header 'Authorization: Bearer {secret}'
apicli password set                  # protects secrets, rules and limits from the agent
apicli skill install --agent claude  # or codex, opencode, or --path DIR
```

You type the secret at a prompt. It never goes on the command line.

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

## What it protects

- Each key is sent only to the host it was added for, redirects included. It's masked in `-v` output and in responses that echo it back.
- Changing secrets, rules or limits needs a terminal and the admin password. Set one: without it, an agent can open a terminal of its own (with `script`, for example) and change them.
- Keys live in an encrypted vault. On macOS its master key is in the Keychain. On Linux and Windows it's a file in apicli's data folder, so a determined agent could read it.
- If macOS asks whether anything other than apicli may read `dev.apicli`, click Deny.
