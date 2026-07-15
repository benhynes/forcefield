# Forcefield

Forcefield (`ff`) is a default-deny credential capability gateway for
untrusted agents. An agent receives a short-lived `ff_...` token and calls an
HTTP API, Git smart-HTTP endpoint, or pinned SSH-session route. Forcefield
binds that token to a workload, evaluates the canonical request against an
immutable grant, fetches the real credential on the host, and either injects
HTTP/Git authentication or authenticates independently to one pinned SSH
upstream.

The agent can exercise only the authority in its grant; the upstream API key,
Git password, or SSH private key does not enter the VM. Forcefield supports
header-authenticated APIs plus explicit Git smart-HTTP and terminating SSH
session adapters. It is not a general forward proxy, TLS MITM, or universal
replacement for provider-specific authentication.

```text
agent / VM                  trusted host                    upstream
-----------                 ------------                    --------
ff_ token + request  --->   route -> identity -> token
                            -> limits -> deny-wins policy
                            -> audit -> fetch credential
                            -> inject HTTP/Git auth      ---> pinned API
                            -> or terminate SSH          ---> pinned SSH host
                      <---  guard/relay response         <--- response

operator CLI  ----------->  same-user Unix admin socket
                            mint / delegate / revoke
```

## Status

Forcefield is an early implementation. Its security boundaries are deliberate,
but it has not had an independent security audit. Start with mock upstreams and
provider credentials that are already narrowly scoped. Read the
[threat model](docs/threat-model.md) before putting a live credential behind it.

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
  inbound token carrier, transport restrictions, and adapter-specific protocol
  settings.
- A **credential** attaches a host-side secret reference and adapter-specific
  upstream authentication mechanism to exactly one service.
- A **policy** attaches deny-wins HTTP/query/JSON/GraphQL/CEL rules, Git
  repository/ref rules, or SSH shell/exec/PTY permissions to exactly one
  service. No matching HTTP/Git allow means deny.
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
- [Client recipes: curl, OpenAI, Anthropic, Git, and SSH](docs/client-recipes.md)
- [Automatic agent capability awareness: live manifest, Claude/Codex hooks, and MCP](docs/agent-awareness.md)
- [Threat model and residual risks](docs/threat-model.md)

## Supported now

- Header-authenticated REST and JSON APIs
- GraphQL operation type/name/root-field constraints
- Bounded CEL predicates over canonical request data
- Git smart-HTTP clone/fetch/push with repository and per-ref policy
- Explicit case-sensitive or ASCII-insensitive Git repository identity
- A path-scoped Git credential helper that reads a delivered `ff_` token file
- Terminating SSH sessions to a pinned host, port, user, and host key via
  `ff ssh`, with the upstream private key retained on the trusted host
- SSH session expiry/revocation checks, decoded input and allowed protocol
  request-payload accounting, and unconditional rejection of SSH forwarding,
  agent/X11, environment, and subsystems
- Path-prefix or host-based reverse-proxy routes
- Source-IP or verified-client-certificate workload binding
- `agent-secret` and other no-shell exec credential helpers
- Development-only environment credential lookup
- Expiring, revocable, monotonically delegated capability tokens
- Authenticated live capability discovery, a guest CLI, and Claude Code/Codex
  CLI hook and MCP integrations

## Not supported yet

- AWS SigV4 or any request-signing protocol
- Git LFS, dumb HTTP, signed pushes, push options, or protocol-v2 push
- `gh`-specific integration
- OCI/Docker registry token exchanges and challenge flows
- Generic CONNECT/forward proxying, arbitrary destinations, WebSockets, or HTTP
  upgrades
- Client-certificate credentials to upstreams
- SSH certificates, SFTP/subsystems, agent/X11/port forwarding, arbitrary SSH
  destinations, and raw TCP tunneling
- Runtime config reload, runtime shadow-policy evaluation, or an observe mode
- Request-body rewriting or provider-semantic approval workflows

These require explicit adapters; see the [adapter roadmap](docs/architecture.md#adapter-boundary-and-roadmap).

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

For SSH, Forcefield terminates an SSH connection inside the already
authenticated HTTPS route, then authenticates separately to exactly one pinned
upstream. The target receives the configured login public key and proof-of-key
signatures, never the private key. Rejected port forwarding, agent, X11,
environment, and subsystem requests are SSH protocol restrictions; an allowed
shell or arbitrary exec still has the configured Unix account's filesystem and
network authority. Forcefield does not interpret shell commands. Target-side
account, sshd/`authorized_keys`, sudo, filesystem, and egress policy remain
essential boundaries.

The response guard is defense in depth, not a proof that a hostile upstream can
never disclose a credential. It catches the exact credential in headers or a
streamed identity-encoded body, strips risky headers, and rejects cross-origin
redirects. An upstream can encode or transform a secret so exact matching does
not find it. Use trusted upstreams and narrowly scoped provider credentials.

## License

MIT. See [LICENSE](LICENSE).
