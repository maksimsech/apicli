---
name: apicli
description: Use apicli instead of curl for HTTP API calls. It takes curl flags and prints responses like curl, with clearer errors. Use it whenever you would run curl against an HTTP API.
---

# apicli

apicli works like curl, with one URL per call.

    apicli https://api.example.com/v1/users/42
    apicli 'https://api.example.com/v1/orders?status=failed&limit=20'
    apicli -i https://api.example.com/v1/orders/123
    apicli -X POST --json '{"note":"checked"}' https://api.example.com/v1/orders/123/notes

- You don't need -s or -S. apicli never prints progress, and errors always go to stderr.
- Brackets and braces in URLs are sent as they are. There is no URL globbing.
- Keep output small: `apicli URL | jq '.items[] | {id, status}'`. For large responses, save with `-o /tmp/resp.json` and query the file with jq.
- `apicli curl ...` also works, so a curl command copied from API docs only needs the `apicli` prefix.

## Flags

Supported: -X, -H, -d, --data-raw, --data-binary, --data-urlencode, --json, -G, -I, -i, -f, --fail-with-body, -o, -w, -m, --connect-timeout, --compressed, -A, -e, -v. Run `apicli --help` for details.

Redirects are not followed yet, so -L is refused. Other refused flags, such as -k, -x, --resolve, -u and -b, print the reason. Drop the flag and retry.

## Exit codes

- 0: a response arrived. For HTTP 4xx and 5xx, stderr also shows `apicli: HTTP <status>` and stdout has the API's error body.
- 2: unsupported flag or bad arguments. stderr names the problem.
- 3: bad URL. Include the scheme, like https://.
- 6, 7, 28, 35: DNS failure, connection failure, timeout, TLS error.
- 22: HTTP 4xx or 5xx with -f or --fail-with-body.
