# Operating Forcefield

Forcefield has one long-running command, a small control-plane CLI, and guest
capability-discovery commands:

```text
ff serve    --config FILE
ff check    --config FILE
ff mint     --config FILE --role ROLE --workload ID [--ttl 1h]
ff delegate --config FILE --caller-workload ID --workload CHILD [options] < parent-token
ff revoke   --config FILE --token-id TOKEN_ID
ff identity --ip ADDRESS | --cert CLIENT_CERT
ff capabilities --url ORIGIN --token-file FILE [connection options]
ff mcp      --url ORIGIN --token-file FILE [connection options]
ff version
```

All administrative commands load and validate the config to discover the Unix
admin socket. They must run as the same trusted host user as `ff serve`. Do not
expose that socket into a VM or run untrusted agents under that host account.
`capabilities` and `mcp` are guest-side data-plane clients: they do not load the
server config or use the admin socket.

## Prepare the host

Build and install the binary:

```sh
go test ./...
go build -trimpath -o ff ./cmd/ff
install -m 0755 ff /usr/local/bin/ff
```

Choose a canonical, non-symlink private state directory owned by the service
user, replace `/REPLACE/WITH/PRIVATE/FORCEFIELD` throughout the production
template, and create it before startup. For example:

```sh
install -d -m 0700 /canonical/private/path/forcefield
```

On macOS, `/tmp` and `/var` traverse symlinks into `/private`; use the canonical
`/private/...` path or a canonical private directory below the service user's
home. The token store intentionally rejects symlink components in its path.

Install and populate the credential helper before starting. For the
`agent-secret` example:

```sh
agent-secret set GITHUB_READ_TOKEN
agent-secret set OPENAI_API_KEY
agent-secret set ANTHROPIC_API_KEY

/usr/local/bin/agent-secret get GITHUB_READ_TOKEN >/dev/null
```

That final lookup is a deliberate readiness test and may trigger a macOS
Keychain approval. Do not print a real value into a terminal or log.

Validate configuration without fetching credentials:

```sh
ff check --config /etc/forcefield/forcefield.yaml
```

`check` verifies config-file type/ownership/mode, schema, object references,
route uniqueness/canonicalization, header and SPKI-pin syntax, upstream
URL/CIDR inputs, policy compilation, and configured bounds. It does not stat
the exec helper, open state, bind a socket, resolve an upstream, perform TLS, or
retrieve a secret; `serve` can still fail those runtime checks.

## Start and stop

Run in the foreground under a process supervisor:

```sh
exec ff serve --config /etc/forcefield/forcefield.yaml
```

SIGINT or SIGTERM initiates a shutdown with a 10-second deadline. Startup logs
the data and admin listeners and warns about insecure ingress or the env secret
backend. Log output intentionally avoids bearer and credential values.

There is no hot reload. A restart loads a new immutable config. On Linux and
macOS, the token store holds an exclusive lock for the server lifetime, so a
second process pointed at the same file fails startup. Restart resets rate and
byte budget accounting and the in-memory secret cache. On open and before token
mutations, the store durably removes expired/revoked records and their inactive
descendant subtrees; other active token/revocation records remain persisted.

The control server has `GET /v1/health` on its private Unix socket, but the CLI
does not currently expose a health command. Process/listener checks and audit
filesystem monitoring should be provided by the supervisor.

## Choose workload identity

The identity in `ff mint --workload` must exactly equal what the data plane will
derive for that request. It is not an arbitrary tenant label: the control plane
accepts only `ip:<canonical-address>` or
`mtls-spki:<64-lowercase-hex-SPKI-digest>`. Always generate it with
`ff identity` rather than constructing it by hand. The same restriction applies
to delegate's `--caller-workload` and child `--workload`.

For an isolated IP-bound workload:

```sh
workload=$(ff identity --ip 192.0.2.10)
```

For a verified mTLS client (recommended):

```sh
workload=$(ff identity --cert /secure/provisioning/agent-client.crt)
```

`identity --cert` hashes the leaf certificate's SubjectPublicKeyInfo. Configure
the issuing CA in `server.client_ca`, provision the matching certificate/key to
the workload, and ensure the client connects with them. If certificate
verification is not active, Forcefield falls back to source IP and the mTLS
identity will never match.

## Mint

Use JSON output so the only copy of the bearer and its public token ID can be
handled separately:

```sh
issued=$(ff mint --config /etc/forcefield/forcefield.yaml \
  --role github-reader \
  --workload "$workload" \
  --ttl 30m \
  --json)

token=$(printf '%s' "$issued" | jq -r .bearer)
token_id=$(printf '%s' "$issued" | jq -r .claims.token_id)
```

Required flags are `--role`, `--workload`, and a positive `--ttl` (default
`1h`). TTL cannot exceed `server.max_token_ttl`. Add `--allow-delegation` only
when this root is intended to create children.

Without `--json`, stdout contains only the bearer and stderr contains token ID
and expiry. Forcefield never returns the bearer again and persists only its
digest. If delivery fails, revoke the public token ID and mint another.

Deliver the token through the VM's authenticated provisioning channel. A 0600
guest file or process environment can be practical, but the agent can read its
own token by design. Do not put it in an image, shared filesystem, audit log, or
host command-line argument. The provider credential must never accompany it.

For automatic agent discovery, use a regular, non-symlink token file with no
group/world permissions, normally `/run/forcefield/token` at mode `0600`.
Provision it atomically along with the Forcefield server CA and, for an mTLS
workload, its client certificate and 0600 private key. Do not expose the admin
socket, server token store, configuration, secret-helper state, or provider
credential to the guest.

## Make agents capability-aware

The guest can fetch a fresh, secret-free projection of its revision-current
configured concrete grants:

```sh
ff capabilities \
  --url https://forcefield.internal:7902 \
  --token-file /run/forcefield/token \
  --ca-cert /run/forcefield/ca.crt \
  --client-cert /run/forcefield/client.crt \
  --client-key /run/forcefield/client.key
```

The command calls `GET /.well-known/forcefield/capabilities` with the scoped
bearer, validates TLS and the bounded response, and prints agent-readable text.
Use `--json` for the machine-readable manifest. The endpoint validates the
current workload/token and omits stale policy or binding revisions; it does not
look up a provider secret, call an upstream, or consume service request/byte
budgets. Discovery has its own per-workload limit of 2 requests per second with
a burst of 16 after authentication. Configured ceilings are not remaining
quota, and a listed grant may already be exhausted. Failures remain opaque, so
a generic 404 can mean invalid, revoked,
misbound, outside the grant, or nonexistent.

For Claude Code, install managed `SessionStart` and `SubagentStart` hooks that
run the same command with `--format claude-hook`, plus the local `ff mcp` server
for on-demand refresh. Large MCP results are cursor-paginated; follow the
returned cursor until complete. See [Automatic agent capability
awareness](agent-awareness.md) and the safe examples under
[`deploy/claude`](../deploy/claude/). The injected text is advisory and can
become stale immediately after revocation or rollout; Forcefield remains
authoritative on every real request.

## Use

The caller sends the broker token through the service's `client_auth` header and
prefix. For a bearer-configured path route:

```sh
curl -sS \
  -H "Authorization: Bearer $token" \
  -H 'Accept: application/json' \
  https://forcefield.internal/github/repos/OWNER/REPO
```

For mTLS add the client certificate/key:

```sh
curl -sS \
  --cert /run/forcefield/client.crt \
  --key /run/forcefield/client.key \
  -H "Authorization: Bearer $token" \
  https://forcefield.internal/github/repos/OWNER/REPO
```

The command line above is readable to processes with sufficient access to the
caller's argv. When that matters, supply the header through a protected curl
config on stdin or an already-scoped agent environment rather than a literal
command argument. This protects the `ff_` capability; the real provider secret
never appears in the client command.

Expected data-plane failures intentionally reveal little:

- Unknown route/auth/token/workload/grant commonly returns generic 404.
- Policy or bounded-body denial returns the same generic 404.
- Rate exhaustion returns generic 429.
- Fail-closed pre-authority audit failure returns generic 503.
- Secret lookup, upstream transport, or response guard failure returns generic
  502 when a response has not already begun.

Forcefield accepts only a final upstream status from 200 through 599. A 1xx
informational/protocol-switch result (including 101), or an invalid status above
599, is treated as an upstream failure rather than relayed to the workload.

Use metadata audit records, not client errors, to investigate. Avoid adding
request/response payloads to surrounding reverse-proxy logs.

## Delegate

The root must have been minted with `--allow-delegation`. The parent bearer is
read from stdin (maximum 1024 bytes), not a flag:

```sh
child_workload=$(ff identity --cert /secure/provisioning/child.crt)

child=$(printf '%s\n' "$token" | \
  ff delegate --config /etc/forcefield/forcefield.yaml \
    --caller-workload "$workload" \
    --workload "$child_workload" \
    --services github \
    --ttl 15m \
    --json)

child_token=$(printf '%s' "$child" | jq -r .bearer)
child_id=$(printf '%s' "$child" | jq -r .claims.token_id)
```

`--caller-workload` is the parent token's exact binding; `--workload` is the
new child binding. Omitting `--services` retains all parent grants. Otherwise it
is a comma-separated exact subset. The child cannot outlive its parent. Add
`--allow-delegation` to the child only if another generation is necessary.

The store limits delegation depth, direct children, and total descendants with
conservative internal defaults. Revoking an ancestor revokes every descendant.
The v1 CLI does not accept tighter per-grant numeric limits; create a narrower
root role when a child needs lower ceilings than service-subsetting provides.

## Revoke

Revoke by the public lowercase 64-character hex token ID, never by bearer:

```sh
ff revoke --config /etc/forcefield/forcefield.yaml --token-id "$token_id"
```

Revocation is persisted atomically and cascades through all descendants.
Repeating revocation of an existing token is idempotent. An unknown/malformed
ID is reported as a rejected control request.

Revocation stops future Forcefield validation. It does not cancel an upstream
request already in progress, revoke the provider credential, remove a token
copy from a guest, or terminate the workload. For an incident, also stop the
workload, rotate the provider credential, and review Forcefield and provider
audit logs.

## Audit records

The audit file is JSON Lines with metadata fields such as:

```json
{"timestamp":"2026-07-15T00:00:00Z","request_id":"<request-id>","token_id":"<public-token-id>","root_token_id":"<public-root-id>","policy_revision":"sha256:...","rule_id":"allow-repo-read","reason":"allowed","method":"GET","path_sha256":"<sha256-of-canonical-path>","workload_id":"mtls-spki:...","grant_id":"...","service":"github","decision":"allow","status":200,"latency_us":42000,"bytes_in":0,"bytes_out":1234}
```

An allowed request normally has a pre-authority record (`status: 0`) before the
secret fetch and a completion or error record afterward; both share the same
request, token, and root IDs. The path is a digest rather than request target
text. A denied request has a deny record when the service can be identified.

Once a mint, delegate, or revoke request passes structural and authority
validation, its audit records use `service: "control"`, put the operation in
`rule_id`, and write `reason: "authorized"` before mutation followed by
`completed` or `failed`. Earlier malformed/unauthorized control requests do not
reach this mutation-audit boundary. With fail-closed auditing, failure of the
authorized record prevents mutation. If the completion record fails after mint
or delegate, Forcefield revokes the just-issued token. A revoke completion
failure cannot reverse a revocation that already committed. Audit failures on
a data-plane denial or final completion likewise cannot retroactively change
the request result.

Keep the file on a monitored filesystem. For lossless rotation, stop
Forcefield, move/archive the closed file, and restart so it opens a new path.
V1 does not reopen the audit path on signal and does not expose the logger's
health state; replacing the pathname while it runs leaves the process writing
the old descriptor.

## Policy rollout and shadow guidance

Forcefield intentionally has no observe mode. A mode that logs a deny but sends
the request with the real credential is fail-open and exercises precisely the
authority the policy was supposed to prevent.

V1 also has no runtime shadow evaluator. Do not add a candidate policy to an
active role and call it “shadow”; tokens minted from that role enforce it.

Use this rollout instead:

1. Add the candidate under a new policy name while retaining the current policy
   revision in the file. Do not reference the candidate from production roles.
2. Run `ff check`, policy unit tests, and sanitized request-corpus replay in a
   test process backed by mock credentials/upstreams. Include expected denies,
   malformed bodies, duplicates, encoding variants, and matcher-error cases.
3. Create a separate candidate role and mint a short-lived token for a canary
   workload using disposable or tightly scoped credentials. Candidate policy is
   enforced for this canary; it is not permissive observation.
4. Compare Forcefield audit decisions with provider-side logs and expected
   behavior. Revoke the canary token after the test.
5. Point the production role at the candidate, restart, and mint new tokens.
   Keep the old policy in config during a bounded migration if old tokens must
   continue; otherwise revoke them. Remove the old revision only after all old
   tokens are expired or revoked.

A future real shadow feature should always have one active policy that alone
gates forwarding and one candidate evaluated only for labeled audit comparison.
Candidate allow must never override active deny; candidate evaluation must not
fetch a secret or trigger an upstream request; candidate errors must be recorded
without changing the active decision. No current config field implements this,
and strict decoding rejects invented `mode` or `shadow_policy` fields.

## Backup, rotation, and recovery

- Back up the token file only to storage with equivalent confidentiality and
  integrity. It has no raw bearer but does contain identities and authority
  metadata.
- Treat the audit log as sensitive metadata.
- Rotate provider credentials in the credential helper. Account for
  `secrets.cache_ttl`; restart or wait before assuming old material is gone.
- Rotate mTLS workload keys, mint for the new SPKI identity, then revoke the old
  token tree.
- Changing `server.audience` invalidates all existing tokens after restart.
- Changing a policy produces a new revision. Existing tokens fail closed if the
  old revision is absent.
- Changing security-relevant service, credential, forwarded/static headers,
  response controls, upstream confinement, secret-backend mapping, global body
  ceiling, or request-read timeout inputs produces a new binding revision and
  invalidates old grants after restart. Rotating only the value behind an
  unchanged secret reference does not.
- Changing a role affects only future mint operations.
