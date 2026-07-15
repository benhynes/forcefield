# Configuration and policy reference

`ff serve` and every administrative CLI command load the same YAML file.
`ff check --config FILE` parses, validates, compiles, and hashes it without
starting listeners or opening the credential helper.

The decoder is strict: unknown fields, aliases/anchors in JSON comparison
values, multiple YAML documents, an unsupported version, and files over 4 MiB
are rejected. The configuration path itself must be a regular, non-symlink
file owned by root or the running user and must not be group- or world-writable.
Configuration stores secret references only, never secret values.

```sh
ff check --config /etc/forcefield/forcefield.yaml
```

## Top-level structure

```yaml
version: 1
server: {}
state: {}
secrets: {}
services: {}
credentials: {}
policies: {}
roles: {}
```

At least one service, credential, policy, and non-empty role is required. Their
names and `server.audience` must start with a lowercase letter or digit and
contain only lowercase letters, digits, `-`, or `_` (maximum 128 characters).

## `server`

| Field | Required/default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:7902` | TCP data-plane address, including host and port. |
| `audience` | `forcefield` | Exact audience embedded in and checked on all tokens. |
| `advertised_base_url` | empty | Canonical HTTP(S) origin (at most 512 bytes) advertised to authenticated capability clients, for example `https://forcefield.internal:7902`. It is not an upstream URL. |
| `admin_socket` | required, absolute | Private Unix control-socket path. Its parent must be a non-symlink private directory. |
| `tls_cert` | optional pair | PEM server certificate chain. Requires `tls_key`. |
| `tls_key` | optional pair | PEM server private key. Requires `tls_cert`. |
| `client_ca` | optional | PEM CA pool for required verified client certificates; requires server TLS. |
| `allow_insecure_ingress` | `false` | Allows plaintext on a non-loopback listener. Development/isolated networks only. |
| `read_header_timeout` | `5s` | Inbound HTTP header timeout. |
| `read_timeout` | `30s` | Inbound request-read deadline; an authorized SSH stream replaces it with the exact earlier-of-token/policy session deadline. |
| `idle_timeout` | `60s` | Inbound idle connection timeout. |
| `max_token_ttl` | `24h` | Maximum TTL accepted by mint and delegate; must be from 1 second through 168 hours. |
| `max_request_bytes` | 16 MiB | Enforced global HTTP/Git request-body ceiling and SSH counted-input ceiling, and upper bound for policy/grant ceilings; from 1 byte through 1 GiB. |

TLS minimum version is 1.2. When `client_ca` is set, clients must present a
certificate chaining to that pool. When it is absent, the workload identity is
the direct peer IP even if ordinary server TLS is enabled.

`advertised_base_url` must contain only a scheme and authority: no userinfo,
path, query, or fragment. HTTPS is required except for a loopback development
origin. Set it to the data-plane origin the guest actually uses, not `listen`
and never a provider upstream. It supplies complete public service URLs in the
live capability manifest; when omitted, the manifest still reports each
path/host route. It does not redirect requests or weaken routing. Host-routed
services require an HTTPS advertised origin. The advertised origin is included
in each credential binding revision, so changing it requires re-minting tokens
under the new binding.

Mint/delegate workload IDs are deliberately not free-form. The control plane
accepts only `ip:<canonical-unmapped-IP>` or
`mtls-spki:<lowercase-64-hex-SPKI-SHA-256>`, matching values produced by
`ff identity --ip` and `ff identity --cert`.

## `state`

| Field | Required/default | Meaning |
|---|---|---|
| `token_file` | required, absolute | Persistent 0600 JSON token-digest/claims store. Raw bearers are not stored. |
| `audit_file` | required, absolute | Append-only metadata JSONL audit file, tightened to 0600. |
| `audit_failure` | `closed` | `closed` denies before credential access when the pre-authority write fails; `open` continues. |

The two paths must differ. Immediate parents are created private when possible
and must not themselves be symlinks; token-store validation additionally
rejects a symlink anywhere in its directory path. Use a canonical path such as
`/private/...` rather than `/tmp` on macOS. On Linux and macOS the store holds
an exclusive cross-process lock in `token_file + ".lock"` for its lifetime, so
a second process fails closed instead of sharing the file; platforms without
the required locking primitive are unsupported. The store durably prunes
expired or revoked records and their inactive descendant subtrees on open and
before mutation. In-memory request/rate/byte accounting is not restored after
restart.

## `secrets`

### Exec backend (production default)

```yaml
secrets:
  type: exec
  command: /usr/local/bin/agent-secret
  args: [get]
  timeout: 5s
  max_output_bytes: 16384
  cache_ttl: 30s
  max_cache_entries: 128
```

| Field | Required/default | Meaning |
|---|---|---|
| `type` | `exec` | `exec` or development-only `env`. |
| `command` | required for exec | Absolute path to an executable regular file. Symlinks are resolved at startup. |
| `args` | omitted means `[get]` | Arguments placed before the secret reference. Prefer explicit `[get]` in operator configs. |
| `timeout` | `5s` | Per-lookup helper deadline. |
| `max_output_bytes` | 16384 | Maximum credential stdout after removing one LF or CRLF; valid range is 1 through 16384 bytes. |
| `cache_ttl` | `0s` | Non-positive disables storage; positive values retain bounded in-memory copies. |
| `max_cache_entries` | `128` | LRU entry bound. `0` receives the default; a negative value is invalid. |

The helper is invoked without a shell as:

```text
command args... secret_ref
```

It receives no stdin; stderr is discarded; nonzero exit, timeout, or excessive
output becomes an opaque lookup error. The minimal environment contains a
fixed `PATH`, `LANG`, and `LC_ALL`, plus available `HOME`, `USER`, and `LOGNAME`.
There is no configuration field for adding helper environment variables.

For the existing `agent-secret` CLI, install it at the configured absolute path
and use `args: [get]`. Store the names referenced by credentials:

```sh
agent-secret set GITHUB_READ_TOKEN
agent-secret set OPENAI_API_KEY
agent-secret set ANTHROPIC_API_KEY
```

The first unattended lookup may require the macOS Keychain approval associated
with the helper/security binary. Exercise each reference interactively before
starting Forcefield as a service. Secret rotation can remain cached for up to
`cache_ttl`; restart the process or wait out that TTL because v1 has no cache
invalidation control endpoint.

### Environment backend (development only)

```yaml
secrets:
  type: env
  env_prefix: FF_SECRET_
  cache_ttl: 0s
```

For `secret_ref: OPENAI_API_KEY`, Forcefield reads
`FF_SECRET_OPENAI_API_KEY` from its own process environment. `ff serve` logs a
warning for this backend. Do not use it to claim that credentials are isolated
from same-user host processes.

## `services`

```yaml
services:
  github:
    adapter: http
    upstream: https://api.github.com
    path_prefix: /github
    client_auth:
      header: Authorization
      prefix: "Bearer "
    forward_headers: [Accept, Content-Type, User-Agent]
    static_headers:
      X-GitHub-Api-Version: "2022-11-28"
    allowed_cidrs: []
    pinned_spki_sha256: []
    response:
      strip_headers: [X-OAuth-Scopes, X-Accepted-OAuth-Scopes]
      require_identity: true
```

| Field | Required/default | Meaning |
|---|---|---|
| `adapter` | `http` | Request/policy adapter: `http`, `git-smart-http`, or `ssh-session`. |
| `git.repository_case` | required for Git | Repository URL identity mode: `sensitive` or `ascii-insensitive`. Invalid on the HTTP adapter. |
| `ssh.user` | required for SSH | Fixed upstream SSH username; never selected by the guest. |
| `ssh.host_key_sha256` | required for SSH | One to eight exact OpenSSH `SHA256:` host-key fingerprints, allowing overlap during rotation. |
| `ssh.connect_timeout` | `5s` | SSH-only TCP and upstream-handshake timeout, from 1 through 30 seconds. |
| `upstream` | required | Fixed absolute HTTP(S) base, or `ssh://host:port` for SSH. No userinfo, query, or fragment; SSH also forbids a path and requires an explicit port. |
| `path_prefix` | exactly one route | Public path route such as `/github`; at most 4096 bytes and not `/`, trailing `/`, repeated slash, unsafe display controls, or embedded bearer material. Longest matching prefix wins. When an advertised origin is configured, the derived service URL must also fit the 4096-byte manifest field. |
| `host` | exactly one route | Exact lowercase DNS hostname route instead of a path prefix. IP literals and trailing dots are invalid. |
| `allow_insecure_upstream` | `false` | Allows a configured `http` upstream. Never use for production credentials. |
| `allowed_cidrs` | empty | Explicit private/special address exceptions for this configured upstream's DNS results. |
| `pinned_spki_sha256` | empty | Standard-base64 SHA-256 SPKI pins, additive to normal TLS verification. |
| `client_auth.header` | required | Header from which exactly one `ff_` bearer is extracted; at most 256 bytes. |
| `client_auth.prefix` | empty | Exact prefix removed before validating the `ff_` token. |
| `forward_headers` | empty | Agent-controlled inbound headers rebuilt upstream. Known credential/key/token/session/signature names and unsafe/hop-by-hop names are rejected. |
| `static_headers` | empty | Non-secret operator-controlled values installed after forwarding and before credential injection. The same credential-bearing names are rejected; use this map to pin semantic/version headers. |
| `response.strip_headers` | empty | Extra upstream response headers to remove in addition to built-in risky names. |
| `response.require_identity` | `true` | Reject a response whose `Content-Encoding` is non-empty and not `identity`. |

Routes and route/base paths must already be canonical. Policy always sees the route-relative path. The upstream
may itself have a base path: with upstream `https://api.openai.com/v1`, public
prefix `/openai`, and request `/openai/responses`, Forcefield sends
`https://api.openai.com/v1/responses` and policy matches `/responses`.

The exact data-plane path `/.well-known/forcefield/capabilities` is reserved
for authenticated capability discovery. A service path prefix cannot equal or
be an ancestor of that path.

SPKI pins are the standard-base64 SHA-256 digest of certificate
SubjectPublicKeyInfo, not hex and not a certificate fingerprint. Plan for pin
overlap during rotation.

An `ssh-session` service requires `server.advertised_base_url` because `ff ssh`
resolves the alias through authenticated capability discovery before opening
the stream. SSH uses the same path/host route and an `Authorization` header
with the exact `Bearer ` prefix on the outer HTTPS data plane. HTTP-only forwarding, static
header, SPKI, insecure-upstream, and response fields are invalid on this
adapter.

Static and forwarded header names may not overlap. Static headers also cannot
be the client-token or injected-credential carrier, `Host`, `Accept-Encoding`,
a framing/representation header (`Content-Length`, `Content-Encoding`, or
`Content-Type`), or a hop-by-hop/forwarding header. Values are single strings,
limited to 8 KiB, may not have leading/trailing whitespace, and may not contain
CR, LF, or NUL. They are non-secret configuration only: never put an API key or other
credential in `static_headers`; the configuration file is not a secret backend,
and the response guard scans for the injected credential, not arbitrary static
values. In particular, pin `Anthropic-Version` and `X-GitHub-Api-Version` here;
do not forward an SDK-selected version header across the trust boundary.

### Git smart-HTTP services

A Git service is an explicit adapter over the same pinned transport and secret
boundary:

```yaml
services:
  git:
    adapter: git-smart-http
    git:
      repository_case: ascii-insensitive
    upstream: https://git.example.com
    path_prefix: /git
    client_auth:
      header: Authorization
      prefix: "Bearer "
    forward_headers: [User-Agent]
    response:
      require_identity: true
```

For `git-smart-http`, `client_auth` must be exactly `Authorization` with prefix
`Bearer ` and identity responses cannot be disabled. Git itself can still use
HTTP Basic challenge/response: the bundled credential helper supplies the
`ff_` bearer as its password, and Forcefield extracts it without forwarding
that Basic value. The adapter, route, transport, response controls, and
credential transformation are included in the binding revision.

`git.repository_case` is required because repository URL spelling is a policy
identity:

- `sensitive` preserves the canonical URL repository path byte-for-byte. Use it
  only for an upstream that treats case-distinct URL paths as distinct
  repositories.
- `ascii-insensitive` lowercases ASCII `A`--`Z` before repository-policy
  matching and applies the same normalization to configured repository
  patterns. It rejects non-ASCII repository paths and patterns rather than
  guessing at Unicode normalization or case folding. Use it when the upstream
  maps ASCII case variants to the same repository.

This setting does not change ref-name matching, which remains case-sensitive.
It is hashed into binding and policy revisions, so changing it requires new
grants. Neither mode discovers general aliases: if an old path, rename alias,
vanity URL, redirect, or Unicode-normalized name maps to the same physical
repository, it must not be governed by different repository rules. Remove the
alias or give all URL names for that repository identical Forcefield authority.
The configured mode must exactly match every upstream repository-name mapping;
otherwise a differently spelled URL can bypass a repository-specific deny.

Only these service-relative smart-HTTP routes are accepted:

- `GET /REPOSITORY.git/info/refs?service=git-upload-pack`
- `POST /REPOSITORY.git/git-upload-pack` with Content-Type
  `application/x-git-upload-pack-request`
- `GET /REPOSITORY.git/info/refs?service=git-receive-pack`
- `POST /REPOSITORY.git/git-receive-pack` with Content-Type
  `application/x-git-receive-pack-request`

`REPOSITORY.git` may contain multiple canonical path segments. The `.git`
suffix, method, query, and RPC media type are mandatory and exact. The service
prefix is removed first, so a public clone URL for the example is
`https://forcefield.example/git/owner/repository.git`. Dumb Git HTTP endpoints,
Git LFS endpoints, and hosting-provider REST APIs do not share this adapter.

### SSH session services

An SSH service is a terminating broker, not a TCP forwarder. The guest opens an
inner SSH connection over the service's authenticated HTTPS stream. Forcefield
then uses a host-side private key to authenticate independently to one fixed
upstream:

```yaml
services:
  infra-box:
    adapter: ssh-session
    upstream: ssh://10.200.4.20:22
    path_prefix: /ssh/infra-box
    allowed_cidrs: [10.200.4.0/24]
    client_auth: {header: Authorization, prefix: "Bearer "}
    ssh:
      user: ops
      host_key_sha256:
        - SHA256:REPLACE_WITH_VERIFIED_UNPADDED_BASE64
      connect_timeout: 5s
```

The target address, port, username, host-key pins, and private-key reference
are operator configuration and never appear in the capability manifest or
come from the guest. Verify host-key fingerprints through an independent
trusted channel before configuring them. Multiple pins support deliberate key
rotation; normal SSH `known_hosts` discovery and trust-on-first-use are not
used.

The adapter accepts one `session` channel. It unconditionally rejects direct
and remote port forwarding, agent and X11 forwarding, environment requests,
subsystems (including SFTP), tunnel channels, and additional session channels.
Shell, exec, and PTY are separately enabled by policy. The HTTPS workload
identity remains the existing source-IP or verified mTLS identity; the inner
SSH username is a fixed protocol value and conveys no authority.

Those denials constrain SSH protocol features, not commands run inside an
allowed shell or exec session. The configured Unix account can still read or
write whatever its filesystem permissions allow and make whatever network
connections the target permits. Enforce finer boundaries with the target
account, sshd and `authorized_keys`, sudoers, filesystem/namespaces, and egress
policy.

The guest-side SSH handshake must complete within 10 seconds, or sooner if the
token/policy deadline arrives first. A reverse proxy in front of this route must
support unbuffered, simultaneous request and response streaming. The wire form
is HTTP/1.1 chunked or HTTP/2; prefer HTTP/2 over TLS when proxying. A proxy that
buffers the request body cannot carry the session, and terminating mTLS or
changing the direct peer also changes the workload identity Forcefield can
authenticate.

## `credentials`

```yaml
credentials:
  github-reader:
    service: github
    secret_ref: GITHUB_READ_TOKEN
    inject:
      header: Authorization
      prefix: "Bearer "
```

Each credential belongs to exactly one service. `secret_ref` is passed verbatim
as the final helper argument (or appended to `env_prefix` for the env backend).
References are at most 512 bytes; the env backend accepts only letters, digits,
and underscore, while exec also accepts non-leading `.`, `-`, `:`, and `/`.
For HTTP and Git credentials, `inject.header` is required and limited to 256
bytes, and `inject.prefix` is prepended to the secret.

For `ssh-session`, omit both `inject` and `basic_username`; the secret must be
an unencrypted PEM or OpenSSH private key accepted by Go's SSH parser:

```yaml
credentials:
  infra-box-key:
    service: infra-box
    secret_ref: INFRA_BOX_SSH_PRIVATE_KEY
```

The key bytes are fetched only after grant authorization and the fail-closed
audit boundary, parsed on the trusted host, and never sent to the guest or
upstream. Public-key authentication necessarily sends the login public key and
proof-of-key signatures to the target; private-key bytes remain on the
Forcefield host. Login keys and target host keys use Go's supported
non-insecure SSH algorithms. RSA login or host keys must be at least 2048 bits,
and RSA login authentication permits only RSA-SHA2-256/512, not legacy
`ssh-rsa`/SHA-1. Encrypted private keys and passphrase references are not
supported in v1. Prefer a unique login key for each Forcefield service/target
instead of reusing a key across accounts or machines.

For HTTP and Git, inbound client auth and outbound injection are independent.
For Anthropic, for example, both can be `x-api-key` with an empty prefix; for an
API whose SDK expects a bearer token while the upstream expects a different
header, configure those separately.

For an upstream that treats a token as an HTTP Basic password, configure an
otherwise empty-prefix `Authorization` injection plus `basic_username`:

```yaml
credentials:
  git-user:
    service: git
    secret_ref: GIT_SMART_HTTP_TOKEN
    inject:
      header: Authorization
    basic_username: broker
```

Forcefield sends `Authorization: Basic base64("broker:" + secret)`. The
username is non-secret visible ASCII, at most 256 bytes, and cannot contain
`:`; the secret remains in the host backend. `basic_username` requires the
injection header to be `Authorization` and `inject.prefix` to be empty. Omit it
when the upstream instead expects a bearer/token prefix. This upstream setting
is independent of the guest-side `forcefield` username emitted by
`ff git-credential`.

At mint time the grant also captures a SHA-256 **binding revision** over the
security-relevant service and route, upstream confinement, client-token
carrier, forwarded and static headers, response controls, credential reference
and injection, secret-backend command/arguments/mapping, and the global
`server.max_request_bytes` and `server.read_timeout`. After restart, changing
any of those inputs makes old tokens fail closed instead of silently receiving
different authority. Rotating the value behind an unchanged `secret_ref` does
not change the binding revision.

## `policies`

Policy syntax is selected by the service adapter. An `http` service uses the
existing `rules`, body, GraphQL, and CEL fields. A `git-smart-http` service uses
only nested `git.rules`; `ssh-session` uses only nested `ssh` permissions.
Mixing adapter policy languages is rejected.

```yaml
policies:
  github-read:
    service: github
    capability_summary: Read approved repository metadata, contents, issues, and named GraphQL queries.
    body_limit: 1048576
    cel_cost_limit: 10000
    cel_timeout: 10ms
    rules: []
```

| Field | Required/default | Meaning |
|---|---|---|
| `service` | required | The one service whose relative requests this policy can authorize. |
| `capability_summary` | empty | Optional one-line, agent-facing description of the policy's useful scope; at most 512 UTF-8 bytes. It is advisory, not executable policy. |
| `body_limit` | 1 MiB | HTTP adapter only: maximum body supplied to JSON, GraphQL, or CEL policy inspection. |
| `cel_cost_limit` | 10000 | HTTP adapter only: per-expression CEL runtime cost ceiling. |
| `cel_timeout` | `10ms` | HTTP adapter only: per-expression CEL evaluation deadline. |
| `rules` | HTTP adapter only; may be empty | Compiled HTTP rules. Empty means deny every request. |
| `git.rules` | Git adapter only; 1--256 | Compiled repository/ref rules. |
| `ssh.allow_shell` | SSH adapter only | Permit an interactive/default shell on the pinned account. |
| `ssh.allow_exec` | SSH adapter only | Permit arbitrary SSH exec command strings on the pinned account. |
| `ssh.allow_pty` | SSH adapter only | Permit PTY allocation; shell or exec must also be allowed. |
| `ssh.max_session_duration` | required for SSH | Hard session ceiling from 1 second through 24 hours, further bounded by token expiry. |

For the HTTP adapter, `body_limit` may not exceed
`server.max_request_bytes`. Every body is buffered under the smallest
applicable server, policy-inspection, and concrete grant ceiling before policy
evaluation. Non-empty `Content-Encoding` other than `identity`, an
invalid/duplicate `Content-Type`, and trailers present before or after body
reading fail closed. Git RPC streaming has separate bounded behavior below.

`capability_summary` is included in the policy revision, so changing it makes
tokens carrying the previous revision fail closed unless that revision remains
available. Keep it concise and faithful to the actual rules. It appears in
agent context and must never contain a bearer, provider credential, secret
reference, private upstream, other sensitive value, control character, or
bidirectional/formatting control. Configuration compilation also proves that
the largest possible 64-service projection from all current services and
policies fits the 128 KiB manifest bound, including worst-case delegated
numeric ceilings.

Rule order has no meaning. Each rule is a conjunction: every configured matcher
group in that rule must match. Within `methods` and `paths`, any listed member
may match. Across query and JSON entries, all entries must match.

HTTP rule evaluation is:

1. Any matcher error: deny.
2. Otherwise, any matching `deny`: deny.
3. Otherwise, any matching `allow`: allow.
4. Otherwise: deny.

An empty matcher set matches every canonical request, so an empty `deny` rule is
a useful explicit kill switch and an empty `allow` rule is dangerously broad.

### Method and path

```yaml
- id: allow-repo-reads
  effect: allow
  methods: [GET, HEAD]
  paths: [/repos/*/*, /repos/*/*/**]
```

Methods are exact and case-sensitive. Paths are absolute service-relative
patterns. A literal segment matches exactly, `*` matches one non-empty segment,
and `**` matches zero or more non-empty segments. Wildcards are whole decoded
segments, not substring globs.

Paths and queries are canonicalized before evaluation and the same spelling is
forwarded. Forcefield rejects dot segments, repeated interior slashes, encoded
slash/backslash, double-encoded octets, controls, invalid UTF-8, malformed
escapes, semicolons in path segments, raw `+` or semicolons in a query, queries
over 16 KiB, more than 256 pairs, or an empty query key. Encode a literal query
plus as `%2B` and a space as `%20`.

### Query matchers

```yaml
query:
  - key: state
    op: in
    values: [open, closed]
  - key: cursor
    op: absent
```

| `op` | Configuration | Match semantics |
|---|---|---|
| `present` | key only | Key exists, including an empty value. |
| `absent` | key only | Key does not exist. |
| `eq` | `value` | Exactly one occurrence exists and equals `value`. |
| `in` | non-empty `values` | At least one occurrence exists and every occurrence is in the allowlist. |

The duplicate-safe `eq`/`in` semantics prevent adding one allowed and one
attacker-controlled value to satisfy a rule.

### JSON matchers

```yaml
json:
  - pointer: /model
    op: in
    values: [approved-model-a, approved-model-b]
  - pointer: /store
    op: eq
    value: false
```

Pointers use RFC 6901 (`~0` for `~`, `~1` for `/`); the empty pointer addresses
the whole document. `eq` takes exactly one YAML value and `in` a non-empty list.
Values are restricted to the JSON data model. Numeric comparison is exact
mathematical equality, so `1` equals `1.0`. Object key order is irrelevant;
array order is not.

The body must contain exactly one valid UTF-8 JSON value with no duplicate
object keys at any depth, unpaired UTF-16 surrogate escape, excessive depth,
or excessive number/exponent. Its media type must be `application/json` or
`application/*+json`; the only accepted parameter is an optional
`charset=utf-8` (case-insensitive). A missing pointer is a non-match; malformed
input is an evaluation error and denies the whole request.

### GraphQL matchers

```yaml
graphql:
  operation_type: query
  operation_name: AgentRead
  root_fields: [viewer, repository, rateLimit]
```

At least one constraint is required. `operation_type` is `query`, `mutation`,
or `subscription`. `operation_name` is exact. `root_fields` is an allowlist:
every expanded root field that may execute must be listed, rather than merely
one field matching. Aliases do not hide the underlying field, and fragments
are expanded with depth and cycle checks.

GraphQL GET requires no body, exactly one `query` parameter, and at most one
`operationName`. Body mode requires POST and rejects URL `query` or
`operationName` carriers; it accepts `application/graphql`, or an
`application/json`/`+json` envelope with a non-empty `query` and optional string
or null `operationName`. A multi-operation document requires selection by
`operationName`. Parsing is capped at 10,000 tokens, syntax nesting at 128, and
fragment/selection expansion at 128; cycles and undefined fragments fail
closed.

This is not schema validation and does not constrain nested selections,
arguments, variables, directives, or complexity. Add JSON/CEL checks or use a
semantic adapter where those affect authority.

### CEL matchers

```yaml
cel:
  expression: >-
    method == "POST" &&
    query["mode"] == ["safe"] &&
    body.max_output_tokens <= 2048
```

The expression must compile to boolean and is limited to 4096 bytes, bounded
parser recursion, configured cost, and configured time. Only these variables
exist:

| Variable | Type/value |
|---|---|
| `method` | Canonical request method string. |
| `path` | Canonical escaped service-relative path string. |
| `query` | `map<string, list<string>>` after duplicate-preserving canonical parsing. |
| `body` | Decoded JSON value, or null for an empty body. |

A non-empty CEL-inspected body must be `application/json` or `+json`. CEL has no
secret, clock, filesystem, network, or extension callback. Missing dynamic
fields, type mismatch, timeout, or cost exhaustion is an evaluation error and
denies the entire request.

JSON integers that fit CEL's integer types remain exact. Decimals are adapted
lazily: a decimal in an unrelated field does not break an expression, but a
decimal the expression actually inspects must be exactly representable as a
binary CEL `double`. A lossy value such as `0.1` therefore fails that CEL
evaluation closed rather than being silently rounded. JSON pointer matchers
continue to compare numbers by exact mathematical value.

## SSH session policies

```yaml
policies:
  infra-box-shell:
    service: infra-box
    capability_summary: Full shell and arbitrary command execution as the configured account; SSH protocol forwarding/subsystems are disabled, but account filesystem/network authority remains.
    ssh:
      allow_shell: true
      allow_exec: true
      allow_pty: true
      max_session_duration: 30m
```

An SSH policy must have a non-empty `capability_summary`, must allow shell or
exec, and must set a finite duration. `allow_exec` is arbitrary command
execution, not a command allowlist: on ordinary SSH servers it is effectively
shell-level authority. Forcefield deliberately does not parse quoting, shell
syntax, sudo, or target-side command effects. Use a dedicated Unix account,
restricted sudoers rules, filesystem permissions, namespaces, and egress
policy for finer authority.

The hard deadline is the earlier of token expiry and
`max_session_duration`. Forcefield revalidates the concrete token/grant once
per second and closes both SSH legs after revocation or revision invalidation.
This bounds continued access but cannot undo completed actions or guarantee
that a process deliberately detached on the target exits with the connection.

## Git smart-HTTP policies

Git policy is provider- and branch-name-neutral. This example permits fetches
from repositories under `engineering/`, permits branch creates/updates/deletes,
and protects the arbitrary ref `refs/heads/stable`:

```yaml
policies:
  git-engineering:
    service: git
    capability_summary: Fetch engineering repositories and push branches except the protected stable ref.
    git:
      rules:
        - id: allow-fetch
          effect: allow
          operation: fetch
          repositories: [engineering/**]

        - id: allow-branch-push
          effect: allow
          operation: push
          repositories: [engineering/**]
          refs: [refs/heads/**]
          update_kinds: [create, update, delete]

        - id: deny-protected-stable
          effect: deny
          operation: push
          repositories: [engineering/infrastructure.git]
          refs: [refs/heads/stable]
```

There is no built-in `main`, infrastructure-repository, or hosting-provider
rule. Another deployment can allow `refs/heads/main`, protect a tag namespace,
or name its protected branch differently by changing only policy.

Each Git rule has these fields:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique lowercase identifier used in policy revisions and bounded audit metadata. |
| `effect` | yes | `allow` or `deny`; rule order has no meaning. |
| `operation` | yes | `fetch` or `push`. |
| `repositories` | yes | One or more exact or recursive repository path patterns, including the `.git` suffix for exact paths. |
| `refs` | push allow: yes; otherwise optional | Exact full refs or recursive ref-prefix patterns. |
| `update_kinds` | push allow: yes; otherwise optional | Any of `create`, `update`, and `delete`. |

Repository requests and repository patterns are first normalized using the
service's required `git.repository_case`, then compared byte-for-byte. Ref
matching is always case-sensitive and byte-for-byte after ref validation. A
pattern is either exact or ends in `/**`, which matches every value below that
slash-terminated prefix. A lone `**` is an explicit match-all and must be the
only entry in its list. There are no substring globs: `release-*` and
`owner/*/repo.git` are invalid. Exact repository values end in `.git`; ref
values are full valid names beginning with `refs/`.

Fetch is repository-wide. A fetch rule cannot contain `refs` or
`update_kinds`, because upload-pack is not a sound branch-level confidentiality
boundary. Once fetch is allowed, the client may request any object the upstream
repository makes available. Use separate repositories or upstream object
visibility controls when different refs require different read audiences.

For a receive-pack push, Forcefield validates the pkt-line command prefix and
derives the kind of every ref update: a zero old object ID is `create`, a zero
new object ID is `delete`, and two nonzero IDs are `update`. Every update must
match an allow rule, and any update matching a deny rejects the entire
multi-ref request before credential lookup or an upstream call. A push deny
with no `refs` or `update_kinds` denies that repository operation as a whole.
Push discovery is allowed when some scoped push allow could apply; the concrete
POST remains subject to per-update authorization. No match denies.

Policy authorizes only the repository path and ref commands actually present on
the smart-HTTP wire. Upstream `proc-receive` or other receive hooks must not
rewrite an allowed command into an update, deployment, or privileged side
effect on an unauthorized ref or repository. Forcefield cannot authorize an
effect the upstream invents after request evaluation; hook code and
configuration are part of the trusted upstream.

Git's update command does not reveal whether an `update` is a fast-forward.
Force and non-force updates have the same old-ID/new-ID/ref shape, and
Forcefield does not load the repository object graph to prove ancestry. There
is therefore no `force` update kind. Enforce non-fast-forward and merge rules
with upstream branch protection or receive-pack configuration, while using
Forcefield to restrict the observable repository/ref/update tuple.

Git upload-pack requests and receive-pack pack data stream under the smaller of
`server.max_request_bytes` and the concrete grant's `max_request_bytes` instead
of being buffered wholesale. Receive-pack first buffers a bounded command
prefix (up to 1 MiB and 1024 updates), authorizes all updates, then replays that
prefix exactly while streaming the remaining pack. `byte_budget` is charged on
decoded bytes as the upstream transport consumes them.

RPC bodies may use identity, `gzip`, or `x-gzip`. Forcefield streams gzip
decoding before policy and forwarding, removes the content encoding, bounds
both compressed and decoded input by the request ceiling, applies a 100:1
ratio guard with 1 MiB slack, and rejects concatenated/trailing gzip members.
Request trailers and limit overruns abort the request. Size ceilings must be
large enough for the intended pack files, and `server.read_timeout` must be
long enough for the slowest permitted push.

Fetch supports Git protocol v0, v1, and v2. Receive-pack supports v0/v1; a v2
header on discovery is stripped to permit client fallback, and a protocol-v2
push RPC is denied. Push certificates and push options are not supported and
fail closed. Git LFS and dumb HTTP are separate protocols/endpoints and are not
matched by this adapter.

## `roles` and grant limits

```yaml
roles:
  repo-reader:
    grants:
      - service: github
        credential: github-reader
        policy: github-read
        limits:
          requests_per_second: 5
          burst: 10
          request_budget: 10000
          byte_budget: 104857600
          max_request_bytes: 1048576
```

Every role must contain 1--64 grants and no more than one grant for a given
service. Credential and policy must both belong to that service. A grant's
`max_request_bytes` may not exceed the server ceiling. `burst` requires a
nonzero rate, and configured rate/burst values may not exceed 1,000,000.

For rate and aggregate budgets, `0` means unlimited:

- `requests_per_second`: token-bucket refill rate.
- `burst`: bucket capacity; defaults to 1 when a rate is set and burst is zero.
- `request_budget`: aggregate request attempts for the root token/grant.
- `byte_budget`: aggregate client-to-upstream counted input bytes. For HTTP it
  is request-body bytes; for a gzip-encoded Git RPC, it is decoded bytes
  forwarded upstream. For SSH, it is decoded session-channel input plus the raw
  payload bytes of allowed session requests actually forwarded upstream (such
  as exec, PTY, window-change, signal, and break). It excludes HTTP/SSH framing
  and encryption overhead, rejected request payloads, and replies.
- `max_request_bytes`: per-request body ceiling; `0` in a role inherits the
  finite `server.max_request_bytes` rather than becoming unlimited. For SSH it
  is the per-session ceiling over those same counted input and forwarded
  request-payload bytes.

Every request is charged atomically against the corresponding concrete grant at
each token in its root-to-leaf delegation chain. An ancestor therefore bounds
all descendants, while a narrower child does not throttle its parent or
siblings. State is kept in memory and reset on server restart. A request can
consume request budget before a later body or policy denial. Responses are not
charged against `byte_budget` in v1.

An SSH tunnel admission counts as one request/rate-budget use. In addition to
configured grant limits, the process admits at most 128 concurrent SSH
sessions, 16 per workload, and 8 per token. These hard bounds are availability
controls, not additional authority. Each session also has a hard SSH protocol
request guard: 64 requests per second with burst 128 and 4096 total. Channel
opens and global/session request attempts count toward that guard even when
rejected; rejected payload bytes do not count toward `byte_budget` or
`max_request_bytes`.

## Production example

[examples/forcefield.yaml](../examples/forcefield.yaml) combines TLS/mTLS,
`agent-secret`, REST/query rules, JSON and CEL bounds, GraphQL allowlisting, a
generic Git smart-HTTP policy, deny-wins overlap, separate credentials, and
roles, plus a deliberately non-working pinned SSH-session target. Replace all
marked paths, origins, certificate files, identity assumptions, repository
namespaces, SSH target/account/key/pin values, approved model placeholders, and
review the pinned upstream API versions before use. Then run `ff check` and
adversarial tests.
