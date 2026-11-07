---
name: apicli
description: Use apicli instead of curl to call HTTP APIs that need credentials (API keys, bearer tokens), such as production APIs while debugging. apicli adds the credentials itself, so never ask the user for keys. Use it when you need data from an authenticated API, or when curl gets 401 or 403 from one.
---

# apicli

apicli is curl for APIs that need credentials. It adds the right key for each host itself, so you never see or handle it.

## First

Run `apicli hosts` to see which hosts are configured and what is allowed on each. Requests to other hosts are refused.

## Requests

Use it like curl, with one URL per call:

    apicli https://api.example.com/v1/users/42
    apicli 'https://api.example.com/v1/orders?status=failed&limit=20'
    apicli -i https://api.example.com/v1/orders/123
    apicli -L https://api.example.com/v1/exports/latest

- Don't add the credential header. apicli adds it and refuses a request that sets it.
- Only GET, HEAD and OPTIONS are allowed for now.
- You don't need -s or -S. apicli never prints progress, and errors always go to stderr.
- -L follows redirects only while they stay on configured hosts.
- Brackets and braces in URLs are sent as they are. There is no URL globbing.
- Keep output small: `apicli URL | jq '.items[] | {id, status}'`. For large responses, save with `-o /tmp/resp.json` and query the file with jq.
- `[apicli:redacted]` in a response is a credential the API echoed back. It is expected.
- `apicli curl ...` also works, so a curl command copied from API docs only needs the `apicli` prefix.

## Flags

Supported: -X, -H, -d, --data-raw, --data-binary, --data-urlencode, --json, -G, -I, -i, -L, --max-redirs, -f, --fail-with-body, -o, -w, -m, --connect-timeout, --compressed, -A, -e, -v. Run `apicli --help` for details.

Refused flags, such as -k, -x, --resolve, -u and -b, print the reason. Drop the flag and retry.

## When a call fails

- 110, denied: the method is not allowed on that host. Tell the user what you tried. Don't retry another way.
- 112, host not configured: show the user the `apicli secret add ...` line from stderr and wait. Use plain curl only if the API needs no credentials.
- 113 or 114: apicli's setup is broken or the keychain is unavailable. Tell the user. Don't touch apicli's files.
- 2: unsupported flag or bad arguments. stderr names the problem.
- 3: bad URL. Include the scheme, like https://.
- 6, 7, 28, 35: DNS failure, connection failure, timeout, TLS error.
- 22: HTTP 4xx or 5xx with -f or --fail-with-body.
- 47: too many redirects.
- 0 with `apicli: HTTP <status>` on stderr: the API answered with an error. stdout has its error body.

## Never

- Ask for API keys or tokens, or look for them in the keychain, files or environment.
- Edit apicli's files, or run `apicli secret ...`. Those commands need the user at a terminal.
- Work around a refusal with curl, another tool or a different URL.
