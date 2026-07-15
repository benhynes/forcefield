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
| `admin_socket` | required, absolute | Private Unix control-socket path. Its parent must be a non-symlink private directory. |
| `tls_cert` | optional pair | PEM server certificate chain. Requires `tls_key`. |
| `tls_key` | optional pair | PEM server private key. Requires `tls_cert`. |
| `client_ca` | optional | PEM CA pool for required verified client certificates; requires server TLS. |
| `allow_insecure_ingress` | `false` | Allows plaintext on a non-loopback listener. Development/isolated networks only. |
| `read_header_timeout` | `5s` | Inbound HTTP header timeout. |
| `read_timeout` | `30s` | Inbound request-read deadline. |
| `idle_timeout` | `60s` | Inbound idle connection timeout. |
| `max_token_ttl` | `24h` | Maximum TTL accepted by mint and delegate; must be from 1 second through 168 hours. |
| `max_request_bytes` | 16 MiB | Enforced global request-body ceiling and upper bound for policy/grant ceilings; from 1 byte through 1 GiB. |

TLS minimum version is 1.2. When `client_ca` is set, clients must present a
certificate chaining to that pool. When it is absent, the workload identity is
the direct peer IP even if ordinary server TLS is enabled.

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
| `upstream` | required | Fixed absolute HTTP(S) base. No userinfo, query, or fragment. HTTPS is required by default. |
| `path_prefix` | exactly one route | Public path route such as `/github`; not `/`, trailing `/`, or repeated slash. Longest matching prefix wins. |
| `host` | exactly one route | Exact lowercase DNS hostname route instead of a path prefix. IP literals and trailing dots are invalid. |
| `allow_insecure_upstream` | `false` | Allows a configured `http` upstream. Never use for production credentials. |
| `allowed_cidrs` | empty | Explicit private/special address exceptions for this configured upstream's DNS results. |
| `pinned_spki_sha256` | empty | Standard-base64 SHA-256 SPKI pins, additive to normal TLS verification. |
| `client_auth.header` | required | Header from which exactly one `ff_` bearer is extracted. |
| `client_auth.prefix` | empty | Exact prefix removed before validating the `ff_` token. |
| `forward_headers` | empty | Agent-controlled inbound headers rebuilt upstream. Known credential/key/token/session/signature names and unsafe/hop-by-hop names are rejected. |
| `static_headers` | empty | Non-secret operator-controlled values installed after forwarding and before credential injection. The same credential-bearing names are rejected; use this map to pin semantic/version headers. |
| `response.strip_headers` | empty | Extra upstream response headers to remove in addition to built-in risky names. |
| `response.require_identity` | `true` | Reject a response whose `Content-Encoding` is non-empty and not `identity`. |

Routes and route/base paths must already be canonical. Policy always sees the route-relative path. The upstream
may itself have a base path: with upstream `https://api.openai.com/v1`, public
prefix `/openai`, and request `/openai/responses`, Forcefield sends
`https://api.openai.com/v1/responses` and policy matches `/responses`.

SPKI pins are the standard-base64 SHA-256 digest of certificate
SubjectPublicKeyInfo, not hex and not a certificate fingerprint. Plan for pin
overlap during rotation.

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
`inject.header` is required and `inject.prefix` is prepended to the secret.

Inbound client auth and outbound injection are independent. For Anthropic, for
example, both can be `x-api-key` with an empty prefix; for an API whose SDK
expects a bearer token while the upstream expects a different header, configure
those separately.

At mint time the grant also captures a SHA-256 **binding revision** over the
security-relevant service and route, upstream confinement, client-token
carrier, forwarded and static headers, response controls, credential reference
and injection, secret-backend command/arguments/mapping, and the global
`server.max_request_bytes` and `server.read_timeout`. After restart, changing
any of those inputs makes old tokens fail closed instead of silently receiving
different authority. Rotating the value behind an unchanged `secret_ref` does
not change the binding revision.

## `policies`

```yaml
policies:
  github-read:
    service: github
    body_limit: 1048576
    cel_cost_limit: 10000
    cel_timeout: 10ms
    rules: []
```

| Field | Required/default | Meaning |
|---|---|---|
| `service` | required | The one service whose relative requests this policy can authorize. |
| `body_limit` | 1 MiB | Maximum body supplied to JSON, GraphQL, or CEL policy inspection. |
| `cel_cost_limit` | 10000 | Per-expression CEL runtime cost ceiling. |
| `cel_timeout` | `10ms` | Per-expression CEL evaluation deadline. |
| `rules` | required (may be empty) | Compiled rules. Empty means deny every request. |

`body_limit` may not exceed `server.max_request_bytes`. Every request body is
buffered under the smallest applicable server, policy-inspection, and concrete
grant ceiling before policy evaluation. Streaming request uploads are therefore
not supported in v1. Non-empty `Content-Encoding` other than `identity`, an
invalid/duplicate `Content-Type`, and trailers present before or after body
reading fail closed.

Rule order has no meaning. Each rule is a conjunction: every configured matcher
group in that rule must match. Within `methods` and `paths`, any listed member
may match. Across query and JSON entries, all entries must match.

Evaluation is:

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

Every role must contain at least one grant and no more than one grant for a
given service. Credential and policy must both belong to that service. A grant's
`max_request_bytes` may not exceed the server ceiling. `burst` requires a
nonzero rate, and configured rate/burst values may not exceed 1,000,000.

For rate and aggregate budgets, `0` means unlimited:

- `requests_per_second`: token-bucket refill rate.
- `burst`: bucket capacity; defaults to 1 when a rate is set and burst is zero.
- `request_budget`: aggregate request attempts for the root token/grant.
- `byte_budget`: aggregate client-to-upstream request body bytes only.
- `max_request_bytes`: per-request body ceiling; `0` in a role inherits the
  finite `server.max_request_bytes` rather than becoming unlimited.

Every request is charged atomically against the corresponding concrete grant at
each token in its root-to-leaf delegation chain. An ancestor therefore bounds
all descendants, while a narrower child does not throttle its parent or
siblings. State is kept in memory and reset on server restart. A request can
consume request budget before a later body or policy denial. Responses are not
charged against `byte_budget` in v1.

## Production example

[examples/forcefield.yaml](../examples/forcefield.yaml) combines TLS/mTLS,
`agent-secret`, REST/query rules, JSON and CEL bounds, GraphQL allowlisting,
deny-wins overlap, separate credentials, and roles. Replace all marked paths,
certificate files, identity assumptions, approved model placeholders, and
review the pinned upstream API versions before use. Then run `ff check` and
adversarial tests.
