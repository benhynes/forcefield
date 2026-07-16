# Forcefield

Forcefield (`ff`) is a default-deny credential capability gateway for
untrusted agents. An agent receives a short-lived `ff_...` token and calls an
HTTP API or Git smart-HTTP endpoint. Forcefield binds that token to a workload,
evaluates the canonical request against an immutable grant, fetches the real
credential on the host, replaces the broker token with that credential, and
calls one pinned upstream.

The agent can exercise only the authority in its grant; the upstream API key or
Git password does not enter the VM. Forcefield supports header-authenticated
APIs and an explicit Git smart-HTTP adapter. It is not a general forward proxy,
TLS MITM, or universal replacement for provider-specific authentication.

```text
agent / VM                  trusted host                    upstream
-----------                 ------------                    --------
ff_ token + request  --->   route -> identity -> token
                            -> limits -> deny-wins policy
                            -> audit -> fetch credential
                            -> replace auth header       ---> pinned API
                      <---  guard response              <--- response

operator CLI  ----------->  same-user Unix admin socket
                            mint / delegate / revoke
```

## Status

Forcefield is an early implementation. Its security boundaries are deliberate,
but it has not had an independent security audit. Start with mock upstreams and
provider credentials that are already narrowly scoped. Read the
[threat model](docs/threat-model.md) before putting a live credential behind it.

The repository also contains an experimental Linux `ff run` agent sandbox
wrapper. It keeps Forcefield and optional Hive credentials in a host-side
broker while applying bubblewrap, systemd resource limits, and seccomp around
one agent. It is not yet a VM-grade or multi-tenant boundary; read the
[agent sandbox runner guide](docs/runner.md) before trying it.

## Quickstart with the local mock

Requirements: Go 1.26 or newer, Python 3, and curl.

```sh
git clone https://github.com/benhynes/forcefield.git
cd forcefield
go build -o ff ./cmd/ff

# Render canonical private state paths. This avoids /tmp, which is a symlink on
# macOS and is intentionally rejected for token state.
config=$(python3 examples/render_dev_config.py "$(pwd -P)/.forcefield-dev")

./ff check --config "$config"
python3 examples/mock_upstream.py
```

In another terminal, start Forcefield with the development-only environment
secret backend:

```sh
cd forcefield
export FF_SECRET_DEMO=upstream-demo-key
config="$(pwd -P)/.forcefield-dev/forcefield.yaml"
./ff serve --config "$config"
```

In a third terminal, derive the workload identity, mint a 15-minute token, and
make allowed and denied requests:

```sh
cd forcefield
config="$(pwd -P)/.forcefield-dev/forcefield.yaml"
workload=$(./ff identity --ip 127.0.0.1)
token=$(./ff mint --config "$config" \
  --role demo-agent --workload "$workload" --ttl 15m)

curl -sS -H "Authorization: Bearer $token" \
  'http://127.0.0.1:7902/demo/v1/resources?scope=public'

curl -i -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"admin","size":1}' \
  http://127.0.0.1:7902/demo/v1/resources
```

The first request succeeds. The second returns the generic deny response even
though an allow rule also matches: any matching deny wins. The real value of
`FF_SECRET_DEMO` is sent only to the mock upstream. The `ff_` token is intended
to be visible to its agent and must still be treated as a scoped bearer secret.

The mock uses explicitly allowed loopback HTTP and the `env` backend. Neither is
a production pattern. Start from [examples/forcefield.yaml](examples/forcefield.yaml)
for a TLS-only `agent-secret` configuration.

## How authority is structured

- A **service** defines an adapter, one pinned upstream, one public route, the
  inbound token header, forwarded-header allowlist, operator-pinned static
  protocol headers, transport restrictions, and response guard.
- A **credential** attaches a host-side secret reference and outbound injection
  header to exactly one service.
- A **policy** attaches either deny-wins HTTP/query/JSON/GraphQL/CEL rules or
  Git repository/ref rules to exactly one service. No matching allow means
  deny.
- A **grant** is the concrete tuple of service, credential, policy revision,
  security-binding revision, and resource ceilings.
- A **role** is an operator template used only when minting. Tokens contain
  immutable concrete grants, not a live role reference.

Changing a role does not change existing tokens. Changing/removing a policy
revision, or changing security-relevant service/credential binding inputs, makes
old tokens fail closed after restart unless the old revision remains available.

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration and policy reference](docs/configuration.md)
- [Operating: start, mint, use, delegate, revoke, and roll out policy](docs/operations.md)
- [Client recipes: curl, OpenAI, Anthropic, and Git](docs/client-recipes.md)
- [Automatic agent capability awareness: live manifest, Claude/Codex hooks, and MCP](docs/agent-awareness.md)
- [Experimental Linux agent sandbox runner](docs/runner.md)
- [Threat model and residual risks](docs/threat-model.md)

## Supported now

- Header-authenticated REST and JSON APIs
- GraphQL operation type/name/root-field constraints
- Bounded CEL predicates over canonical request data
- Git smart-HTTP clone/fetch/push with repository and per-ref policy
- Explicit case-sensitive or ASCII-insensitive Git repository identity
- A path-scoped Git credential helper that reads a delivered `ff_` token file
- Path-prefix or host-based reverse-proxy routes
- Source-IP or verified-client-certificate workload binding
- `agent-secret` and other no-shell exec credential helpers
- Development-only environment credential lookup
- Expiring, revocable, monotonically delegated capability tokens
- Authenticated live capability discovery, a guest CLI, and Claude Code/Codex
  CLI hook and MCP integrations
- Experimental Linux amd64/arm64 `ff run` wrapping with an operator-owned
  profile, read-only rootfs, read-only-by-default per-agent workspace,
  disjoint operator-approved host directory roots, hard systemd runtime and
  resource ceilings, bubblewrap namespaces, seccomp, a bounded streaming
  credential-hiding Forcefield broker, and an optional recipient/kind-limited
  Hive MSG proxy

## Not supported yet

- AWS SigV4 or any request-signing protocol
- Git LFS, dumb HTTP, signed pushes, push options, or protocol-v2 push
- `gh`-specific integration
- OCI/Docker registry token exchanges and challenge flows
- Generic CONNECT/forward proxying, arbitrary destinations, WebSockets, or HTTP
  upgrades
- Client-certificate credentials to upstreams
- SSH credentials or raw SSH tunneling (a future adapter should issue
  short-lived SSH certificates or a constrained `ProxyCommand`)
- Runtime config reload, runtime shadow-policy evaluation, or an observe mode
- Request-body rewriting or provider-semantic approval workflows
- Non-Linux agent sandboxing, VM-grade hostile-tenant isolation, unique
  per-sandbox host UIDs/peer credentials, rootfs provisioning, or automatic
  runner crash reconciliation
- Rootfs, tool, mount, or operator-config content attestation; the runner
  profile digest records configuration fields, not file contents
- Runner-managed writable-workspace disk quotas; swap is disabled, but
  execution profiles still need host filesystem/project quotas or disposable
  bounded volumes
- Debian/tmux end-to-end validation of the mediated controlling PTY, job
  control, and real Claude/Codex interactive CLIs remains outstanding
- Atomic task claims, fencing generations, Linear board integration, or an
  agent review/workflow engine; these belong in a deterministic coordinator

Provider and protocol additions require explicit adapters; see the
[adapter roadmap](docs/architecture.md#adapter-boundary-and-roadmap).

## Security invariants

Forcefield evaluates the exact canonical path and query it forwards. Unknown,
expired, revoked, misbound, and under-scoped tokens all fail with a generic
response. Policies are order-independent: matcher errors deny, any matching deny
wins, otherwise any matching allow permits, and no match denies. Secrets are
looked up only after authorization and a fail-closed audit write.

For Git, repository authorization is over the configured URL identity and each
wire-visible ref update. Operators must choose repository case semantics that
match the upstream and must not let aliases or server-side hooks translate an
allowed URL/ref into effects on differently authorized repositories or refs.

The response guard is defense in depth, not a proof that a hostile upstream can
never disclose a credential. It catches the exact credential in headers or a
streamed identity-encoded body, strips risky headers, and rejects cross-origin
redirects. An upstream can encode or transform a secret so exact matching does
not find it. Use trusted upstreams and narrowly scoped provider credentials.

## License

MIT. See [LICENSE](LICENSE).
