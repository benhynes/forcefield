# Client recipes

The easiest client integration is a path-routed service and an SDK base-URL
override. The agent supplies its `ff_` capability where the SDK normally expects
the provider API key. Forcefield removes it and injects the real host-side value
using the service's configured credential adapter.

These examples match [examples/forcefield.yaml](../examples/forcefield.yaml).
Replace the example's non-working model placeholders with an explicit approved
model allowlist before calling an LLM. The recipes use environment variables so
model names are an operator choice rather than a stale documentation default.

```sh
export FORCEFIELD_URL=https://forcefield.internal:7902
export FORCEFIELD_TOKEN=ff_REDACTED
export OPENAI_MODEL=your-approved-openai-model
export ANTHROPIC_MODEL=your-approved-anthropic-model
```

The `ff_` token is scoped but still bearer material. It is acceptable for the
assigned agent to see; do not send it to any endpoint except Forcefield.

For an autonomous guest, provision the bearer as a regular 0600 file and let
`ff capabilities` or the Forcefield MCP server read it. Those commands expose a
fresh, secret-free description of revision-current configured grants without
printing the bearer:

```sh
ff capabilities \
  --url "$FORCEFIELD_URL" \
  --token-file /run/forcefield/token \
  --ca-cert /run/forcefield/ca.crt \
  --client-cert /run/forcefield/client.crt \
  --client-key /run/forcefield/client.key
```

Managed agent runtimes can inject that output at startup and offer an MCP
refresh tool; see [Automatic agent capability awareness](agent-awareness.md).
This discovery text is advisory. A generic 404 from a real request can mean
either nonexistent or outside the current grant, and the gateway remains
authoritative. Remaining quota is not reported, so a listed grant can already
be exhausted.

## curl: REST

GitHub repository metadata:

```sh
curl --fail-with-body --silent --show-error \
  --cert /run/forcefield/client.crt \
  --key /run/forcefield/client.key \
  -H "Authorization: Bearer $FORCEFIELD_TOKEN" \
  -H 'Accept: application/vnd.github+json' \
  "$FORCEFIELD_URL/github/repos/OWNER/REPO"
```

The filtered-issues policy requires all three query parameters. Query order does not
matter because Forcefield canonicalizes it:

```sh
curl --fail-with-body --silent --show-error \
  --cert /run/forcefield/client.crt \
  --key /run/forcefield/client.key \
  -H "Authorization: Bearer $FORCEFIELD_TOKEN" \
  "$FORCEFIELD_URL/github/repos/OWNER/REPO/issues?page=1&per_page=25&state=open"
```

Forcefield strips upstream `Link` response headers as a credential-leak and
redirect defense. Paginate by changing the explicit, policy-bounded `page`
parameter; the production template permits pages 1 through 3. The service also
sets its pinned `X-GitHub-Api-Version` static header, so a client-supplied
version is neither required nor forwarded. Review and test that pin before its
support window ends; GitHub lists supported values in its
[API version reference](https://docs.github.com/en/rest/about-the-rest-api/api-versions).

On a source-IP-bound isolated network, omit `--cert` and `--key`. Do not omit
them for a token minted to an `mtls-spki:` workload.

Many systems expose command arguments to other privileged processes. To avoid a
literal bearer in curl's argv, create a 0600 curl config inside the guest or feed
one on a protected file descriptor. That protects the Forcefield capability,
not a provider key—the client never has the latter.

## curl: GraphQL

The example policy permits only the named `AgentRead` query and only the listed
expanded root fields. A mutation is explicitly denied:

```sh
curl --fail-with-body --silent --show-error \
  --cert /run/forcefield/client.crt \
  --key /run/forcefield/client.key \
  -H "Authorization: Bearer $FORCEFIELD_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "operationName": "AgentRead",
    "query": "query AgentRead($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { nameWithOwner } rateLimit { remaining } }",
    "variables": {"owner": "OWNER", "name": "REPO"}
  }' \
  "$FORCEFIELD_URL/github/graphql"
```

GraphQL root-field policy does not constrain variables, arguments, nested
fields, or query complexity. Add CEL/JSON constraints or a semantic adapter if
those carry authority in your use case.

## OpenAI Python SDK

The example OpenAI service has:

```yaml
upstream: https://api.openai.com/v1
path_prefix: /openai
client_auth: {header: Authorization, prefix: "Bearer "}
```

The Python SDK can therefore use the Forcefield capability as its `api_key` and
the public path as its `base_url`:

```python
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["FORCEFIELD_TOKEN"],
    base_url=os.environ["FORCEFIELD_URL"].rstrip("/") + "/openai",
)

response = client.responses.create(
    model=os.environ["OPENAI_MODEL"],
    input="Summarize the supplied text in three bullets.",
    store=False,
    max_output_tokens=512,
)

print(response.output_text)
```

The current official OpenAI Python client documents the Responses API,
constructor `base_url`, and `OPENAI_BASE_URL`; pin a tested SDK release in the
guest rather than assuming all historical versions behave identically. See the
[official OpenAI Python library](https://github.com/openai/openai-python).

The SDK sends `Authorization: Bearer ff_...` to Forcefield. Forcefield evaluates
the relative `/responses` request, requires an approved model, `store: false`,
and bounded `max_output_tokens`, then sends `Authorization: Bearer <real key>`
to `api.openai.com`.

Do not set `OPENAI_API_KEY` to the real provider value inside the VM. If an
existing application insists on that conventional variable, assign the scoped
Forcefield token to it and separately override the base URL:

```sh
export OPENAI_API_KEY=$FORCEFIELD_TOKEN
export OPENAI_BASE_URL=$FORCEFIELD_URL/openai
```

Environment-variable support is application/SDK-version dependent; explicit
constructor parameters are easier to audit. Verify with a mock credential and
Forcefield audit log before provisioning a live key.

## Anthropic Python SDK

The Anthropic SDK sends its API key in `x-api-key`, so the service's inbound
carrier and outbound injection both use that header. They contain different
values because Forcefield replaces the client header:

```python
import os
from anthropic import Anthropic

client = Anthropic(
    api_key=os.environ["FORCEFIELD_TOKEN"],
    base_url=os.environ["FORCEFIELD_URL"].rstrip("/") + "/anthropic",
)

message = client.messages.create(
    model=os.environ["ANTHROPIC_MODEL"],
    max_tokens=512,
    messages=[
        {"role": "user", "content": "Summarize the supplied text in three bullets."}
    ],
)

for block in message.content:
    if getattr(block, "type", None) == "text":
        print(block.text)
```

The current official client supports constructor `base_url`,
`ANTHROPIC_BASE_URL`, and the `x-api-key` authentication path. See the
[official Anthropic Python library](https://github.com/anthropics/anthropic-sdk-python).

The SDK calls `/v1/messages`; the public request is therefore
`$FORCEFIELD_URL/anthropic/v1/messages`. The SDK may send an
`Anthropic-Version` header, but Forcefield does not trust or forward it. The
service installs the operator-pinned static value `2023-06-01`, then replaces
`x-api-key: ff_...` with the host-side Anthropic key. Static headers are for
non-secret protocol metadata only; API keys still belong in the secret backend.

For an existing application that supports standard SDK environment variables:

```sh
export ANTHROPIC_API_KEY=$FORCEFIELD_TOKEN
export ANTHROPIC_BASE_URL=$FORCEFIELD_URL/anthropic
```

Again, prefer an explicit constructor when possible and verify the particular
SDK version. Never leave a fallback provider key in the same environment; a
base-URL mistake could otherwise send it directly.

## Git smart HTTP

For a service configured with `adapter: git-smart-http`, use its advertised
Forcefield service URL as the Git remote. The bundled credential helper reads a
0600 token file only when Git asks for credentials under that exact
scheme/host/path prefix. It returns the fixed username `forcefield` and the
`ff_` bearer as the HTTP Basic password; the upstream Git credential remains on
the trusted host.

Provision this scoped configuration in the guest's `~/.gitconfig` (substitute
the actual service URL and paths):

```gitconfig
[credential "https://forcefield.internal:7902/git"]
    useHttpPath = true
    helper = !ff git-credential --url https://forcefield.internal:7902/git --token-file /run/forcefield/token

[http "https://forcefield.internal:7902/git"]
    sslCAInfo = /run/forcefield/ca.crt
    sslCert = /run/forcefield/client.crt
    sslKey = /run/forcefield/client.key
```

`credential.useHttpPath` is important: without it Git omits the URL path from
credential lookup, and the helper intentionally refuses to widen `/git` into a
host-wide credential. The helper implements `get` but deliberately ignores
`store` and `erase`; it never copies the bearer out of its separately delivered
token file. Avoid configuring another caching helper for the same URL, because
that other helper could persist the returned Forcefield bearer.

Clone and push normally:

```sh
export FORCEFIELD_GIT_URL=https://forcefield.internal:7902/git

git clone "$FORCEFIELD_GIT_URL/engineering/application.git"
cd application
git switch -c agent/topic
git push origin HEAD:refs/heads/agent/topic
```

On a valid smart-HTTP route, the initial unauthenticated request receives a
Basic challenge and Git invokes the helper. Invalid routes and authorization
denials remain opaque. The helper is URL-scoped, and Forcefield rechecks the
token's workload, expiry, concrete grant, policy revision, and budgets on every
discovery and RPC request.

Repository URL spelling follows the service's required
`git.repository_case`. In `ascii-insensitive` mode, ASCII case variants share a
lowercase policy identity and non-ASCII repository paths are denied;
`sensitive` preserves case for an upstream that really treats those paths as
different repositories. This is not alias discovery. Operators must not expose
old names, rename aliases, vanity paths, or redirects that map differently
authorized URL names to the same physical repository.

A fetch grant authorizes the repository as a whole, not selected branches.
Push policy is finer-grained: every receive-pack update is classified as
`create`, `update`, or `delete`, every update must match an allow, and one
matching deny rejects the whole multi-ref push. For example, a deployment may
allow `refs/heads/**` while denying `refs/heads/stable`; neither that name nor
`main` is built into Forcefield.

Git does not label an ordinary update as fast-forward or force. Enforce
non-fast-forward restrictions with the upstream's branch protection or
receive-pack configuration. Forcefield enforces the repository/ref/update
policy it can prove from the wire request.

Pack bodies stream under `server.max_request_bytes`, the grant's
`max_request_bytes`, `byte_budget`, and the request read deadline. Git's gzip
request form is decoded, bounded, and forwarded as identity. Set these limits
for the largest intended push. Git LFS, dumb HTTP, push certificates, push
options, and protocol-v2 push are not supported; use ordinary protocol fallback
and do not route those other endpoints through this adapter.

## SSH sessions

For a grant whose service uses `adapter: ssh-session`, use the service alias
from capability discovery. `ff ssh` fetches the live manifest, resolves only
that named SSH service, then opens the exact advertised route:

```sh
ff ssh \
  --url https://forcefield.internal:7902 \
  --token-file /run/forcefield/token \
  --ca-cert /run/forcefield/ca.crt \
  infra-box
```

When `FORCEFIELD_URL`, `FORCEFIELD_TOKEN_FILE`, and any TLS variables are
provisioned, the short form is simply:

```sh
ff ssh infra-box
ff ssh infra-box -- uname -a
```

An interactive shell automatically requests a PTY when stdin is a terminal and
the discovered grant permits PTYs. A shell-only grant without PTY permission
automatically stays non-PTY. Use `-t`/`--pty` to force a permitted PTY or
`-T`/`--no-pty` to suppress it. The client rejects unavailable shell, exec, or
PTY modes locally before opening a broker session. Command arguments are
joined with spaces like the ordinary SSH CLI; quote a compound remote command
as one local shell argument when exact grouping matters.

The capability entry reports `allow_shell`, `allow_exec`, `allow_pty`, and the
configured maximum session duration. Agent-facing recipes are mode-aware: an
exec-only grant shows only the `-- COMMAND ...` form, while a shell without PTY
permission includes `--no-pty`.

The `ff_` token authenticates only the outer HTTPS request and remains bound to
the existing source-IP or mTLS workload. Inside that stream, Forcefield
terminates a native SSH connection and authenticates independently to the
pinned upstream with the host-side key. The guest receives neither the key nor
an SSH agent; the target receives the corresponding public key and
proof-of-key signatures, never private-key bytes. Port/agent/X11 forwarding,
environment requests, subsystems, and additional channels are unavailable as
SSH protocol features. They do not prevent a permitted shell or command from
using the configured account's filesystem or opening outbound connections
allowed by target policy. A generic connection failure can mean an
expired/revoked grant, exhausted limits, a stale policy/binding revision, host
key mismatch, a 10-second guest-handshake timeout, or an upstream failure.

The HTTPS exchange is full duplex. Connect directly when possible. If the
Forcefield endpoint is behind a reverse proxy, it must stream request and
response bodies simultaneously without buffering for HTTP/1.1 chunked or
HTTP/2; prefer HTTP/2 over TLS. It must also preserve the intended
workload-authentication boundary.

An accepted remote command's non-zero exit status becomes the `ff` process exit
status without an extra diagnostic line. Connection and pre-start failures use
the generic Forcefield connection error and exit status 255; a rejected exec
request never prints the command text.

## mTLS from SDKs

SDKs commonly use an HTTP client such as `httpx` underneath. Configure that
client with the workload certificate, private key, and Forcefield server CA,
then pass it through the SDK's supported custom-client option. The exact option
is SDK-version-specific, so pin and test it rather than disabling TLS
verification.

An alternative is a minimal guest-local shim listening only on a Unix socket or
loopback. The shim owns the mTLS key, connects to Forcefield with mTLS, and gives
the SDK a simple local HTTP base URL. It must not become an arbitrary forward
proxy and must preserve the original Forcefield path. Source-IP binding is not a
safe workaround on a shared network.

## Unsupported clients

Do not point these at the generic header adapter and assume equivalence:

- AWS SDKs sign the request with SigV4. They need an exact-request signer or a
  native temporary-credential vending adapter.
- `gh` has host-specific configuration and authentication behavior beyond a
  generic REST base URL. A raw GitHub REST curl or Git smart-HTTP clone does not
  prove `gh` is supported.
- Git LFS, dumb HTTP, signed pushes, push options, and protocol-v2 push need
  explicit adapter support beyond the current Git smart-HTTP surface.
- Docker/OCI clients follow registry challenge and token-exchange flows across
  multiple authorities.
- SSH certificates, arbitrary SSH destinations, SFTP, and raw SSH/TCP
  forwarding remain outside the terminating `ssh-session` adapter.
- Clients requiring CONNECT, WebSockets, arbitrary absolute URLs, request-body
  signing, or upstream mTLS need dedicated adapters.

Until those adapters exist, use a purpose-built narrow host operation or a
short-lived native credential with provider-side scope. Do not broaden
`forward_headers`, upstream CIDRs, or policy paths to force compatibility.
