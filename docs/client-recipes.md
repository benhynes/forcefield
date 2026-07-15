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
- `gh` and Git may use host-specific configuration, credential helpers, smart
  HTTP discovery, and redirects. A raw GitHub REST curl working does not prove
  `gh` or `git clone` is supported.
- Docker/OCI clients follow registry challenge and token-exchange flows across
  multiple authorities.
- SSH needs a separate adapter that issues a short-lived SSH certificate or a
  tightly constrained `ProxyCommand` for a pinned host. It must not use the HTTP
  gateway as a raw TCP tunnel.
- Clients requiring CONNECT, WebSockets, arbitrary absolute URLs, request-body
  signing, or upstream mTLS need dedicated adapters.

Until those adapters exist, use a purpose-built narrow host operation or a
short-lived native credential with provider-side scope. Do not broaden
`forward_headers`, upstream CIDRs, or policy paths to force compatibility.
