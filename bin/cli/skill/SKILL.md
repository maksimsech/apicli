---
name: apicli
description: Use apicli instead of curl to call HTTP APIs that need credentials (API keys, bearer tokens), such as production APIs while debugging. apicli adds the credentials itself, so never ask the user for keys. Use it when you need data from an authenticated API, or when curl gets 401 or 403 from one.
---

# apicli

apicli is curl for APIs that need credentials. It adds the right key for each host itself, so you never see or handle it.

## First

Run `apicli hosts` to see which hosts are configured, what is allowed on each, and how many requests the rate limit leaves right now. Requests to other hosts are refused.

Before a write, run `apicli explain POST URL` to check whether it's allowed without sending anything.

## Requests

Use it like curl, with one URL per call:

    apicli https://api.example.com/v1/users/42
    apicli 'https://api.example.com/v1/orders?status=failed&limit=20'
    apicli -i https://api.example.com/v1/orders/123
    apicli -L https://api.example.com/v1/exports/latest

- Don't add the credential header. apicli adds it and refuses a request that sets it.
- GET, HEAD and OPTIONS are allowed by default. Other methods only work on paths the user allowed, and some paths may be denied.
- Method-override headers (X-HTTP-Method-Override and similar) and `_method` parameters are refused. Use -X.
- You don't need -s or -S. apicli never prints progress, and errors always go to stderr.
- -L follows redirects only while they stay on configured hosts.
- Brackets and braces in URLs are sent as they are. There is no URL globbing.
- Keep output small: `apicli URL | jq '.items[] | {id, status}'`. For large responses, save with `-o /tmp/resp.json` and query the file with jq.
- `[apicli:redacted]` in a response is a credential the API echoed back. It is expected.
- `apicli curl ...` also works, so a curl command copied from API docs only needs the `apicli` prefix.

## Flags

Supported: -X, -H, -d, --data-raw, --data-binary, --data-urlencode, --json, -G, -I, -i, -L, --max-redirs, -f, --fail-with-body, -o, -w, -m, --connect-timeout, --compressed, -A, -e, -v, and apicli's own --wait. Run `apicli --help` for details.

Refused flags, such as -k, -x, --resolve, -u and -b, print the reason. Drop the flag and retry.

## When a call fails

- 110, denied: the method or path is not allowed. stderr has an `apicli allow add ...` line when the user can allow it. Show it to the user and wait. Don't retry another way.
- 111, rate limited: stderr says how long to wait. Wait, or rerun with `--wait` (up to 30s) or `--wait=SECONDS`. Don't loop on retries.
- 112, host not configured: show the user the `apicli secret add ...` line from stderr and wait. Use plain curl only if the API needs no credentials.
- 113 or 114: apicli's setup is broken or the keychain is unavailable. Tell the user. Don't touch apicli's files.
- 2: unsupported flag or bad arguments. stderr names the problem.
- 1 or 3: unsupported scheme or bad URL. Use https://.
- 6, 7, 28, 35, 56: DNS failure, connection failure, timeout, TLS error, connection dropped.
- 23 or 26: apicli couldn't write the output or read a file you passed with @.
- 22: HTTP 4xx or 5xx with -f or --fail-with-body.
- 47: too many redirects.
- 0 with `apicli: HTTP <status>` on stderr: the API answered with an error. stdout has its error body.

## Never

- Ask for API keys or tokens, or look for them in the keychain, files or environment.
- Edit apicli's files, or run `apicli secret`, `allow`, `deny`, `limit`, `log limit`, `policy edit` or `password`. Those need the user at a terminal.
- Work around a refusal with curl, another tool or a different URL.
