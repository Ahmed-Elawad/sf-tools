# sf tools

Operational scripts for Salesforce orgs. No npm dependencies; Node 20.12+ and the `sf` CLI.

## sync-named-credential-token.mjs

Fetches an OAuth access token from an external identity provider and writes it into the
`authorizationCode` custom header of one or more Salesforce **named credentials** (the Connect REST API
`named-credential-setup` resource; the names in `NAMED_CREDENTIALS` are named credential developer names).

Each cycle, in order:

1. `POST TOKEN_URL` with an `application/x-www-form-urlencoded` body built from
   `CLIENT_ID`, `CLIENT_SECRET`, `SCOPE`, `GRANT_TYPE`, and parses `access_token`.
2. Verifies the token's JWT signature against the issuer's JWKS (found via `JWKS_URI`, or
   OpenID discovery from the `iss` claim) and checks `exp` / `nbf`. Set `TOKEN_VALIDATION=off`
   for opaque tokens.
3. Authorizes to the Salesforce org: an `sf` CLI alias (`SF_TARGET_ORG`), a raw session
   (`SF_ACCESS_TOKEN` + `SF_INSTANCE_URL`), or a connected-app client-credentials flow
   (`SF_CLIENT_ID` + `SF_CLIENT_SECRET`). This happens every cycle, so CLI sessions are refreshed.
4. For each name in `NAMED_CREDENTIALS`: `GET` the named credential, set the custom header
   `HEADER_NAME` (default `authorizationCode`) to the token, `PUT` it back, re-read to confirm.

### Setup

```bash
cp .env.example .env               # fill in the values
sf org login web -a my-org-alias   # if using the CLI auth option
```

### Run

```bash
npm run sync-nc-token:dry-run   # one cycle, no PUT; prints the redacted request bodies
npm run sync-nc-token:once      # one real cycle, then exit
npm run sync-nc-token           # keep running: supervised, every RUN_INTERVAL_MINUTES
node sync-named-credential-token.mjs --env /path/to/other.env --every 45 --supervise
```

### Scheduling

`RUN_INTERVAL_MINUTES=45` in `.env` (or `--every 45`) makes the process stay up and repeat the whole
cycle, new token included, every 45 minutes measured from the start of the previous cycle. A failed
cycle is retried after `RETRY_INTERVAL_MINUTES` (default 5) instead of waiting the full interval. If
the token's lifetime is shorter than the interval, the log warns so you can tighten the interval.

If you prefer an external scheduler, run `--once` from it. Note that cron's `*/45 * * * *` fires at
:00 and :45 of every hour, which is not a 45-minute cadence; a systemd timer with
`OnUnitActiveSec=45min` is, and so is the built-in loop.

### Logging

Console output stays human-readable. Every line is also appended to `LOG_FILE`
(default `logs/sync-named-credential-token.log` next to the script) as
`<ISO time> <role>[pid] <LEVEL> <message>`, written synchronously so the file is complete even after
a hard crash. The file rotates to `.1` above `LOG_MAX_MB` (default 10). Process start, each cycle's
duration and memory, signals, fatal errors with stack traces, and the exit code are all recorded.
Secrets are never written in full; tokens appear as the first 8 characters plus the length.

### Shutdown and faults

- `SIGINT` / `SIGTERM` / `SIGHUP`: the loop stops after the current cycle. A cycle in flight gets
  `STOP_GRACE_SECONDS` (default 20) to finish, then its HTTP and CLI calls are aborted. A second
  signal aborts immediately. Exit code 130.
- Uncaught exceptions and unhandled promise rejections are logged with their stack and exit with
  code 70.
- A segmentation fault or an OOM kill ends a Node process before any JavaScript can run, so nothing
  inside the worker can catch it. `--supervise` starts a small parent process that watches the
  worker: if the worker dies by signal or with code 70, the supervisor logs it and restarts the
  worker after 5 s, doubling up to 5 min between repeated crashes, and resetting once a worker has
  run for 10 minutes. Ordinary failures (config, token, Salesforce) are not restarted; the worker's
  own retry loop handles those. Signals sent to the supervisor are forwarded to the worker.

A `PUT` is applied atomically by Salesforce, so an abort mid-request leaves the named credential
either fully old or fully new; the next cycle sets it again.

### Running as a service (systemd example)

```ini
[Unit]
Description=Sync IdP access token into Salesforce named credentials
After=network-online.target

[Service]
WorkingDirectory=/home/whippledipple/projects/software/sf/tools
ExecStart=/usr/bin/node sync-named-credential-token.mjs --supervise
Restart=always
RestartSec=10
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

`Restart=always` covers the case where the supervisor itself is killed.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | success, or clean stop after a signal while idle |
| 1 | configuration error |
| 2 | token request failed |
| 3 | token signature / claims rejected |
| 4 | Salesforce authorization failed |
| 5 | one or more named credentials failed (the others are still updated) |
| 70 | fatal error (uncaught exception / unhandled rejection) |
| 130 | interrupted by a signal during a cycle |

### A note on the PUT body

Salesforce's doc pages were not reachable while this was written, so the PUT body is built from the
GET response by removing the output-only `id` and `url` keys and reducing external credential and
network connection entries to developer-name references. Run `--dry-run --verbose` against one named
credential first and check the printed body. If Salesforce rejects an extra field, add it to
`SF_NC_STRIP_KEYS` in `.env`.
